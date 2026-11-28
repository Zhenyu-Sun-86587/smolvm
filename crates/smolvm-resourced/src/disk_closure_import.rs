//! Enroll an already transferred immutable disk closure in a running Worker.

use crate::backup_closure::{self, Manifest};
use crate::blocks::{self, BlockSpec};
use crate::catalog::Catalog;
use crate::ipc::{Fault, Request, Result, valid_digest, valid_id};
use rusqlite::{TransactionBehavior, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(crate) const KIND: &str = "disk_closure_import";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    import_id: String,
    closure_digest: String,
    worker_manifest_digest: String,
    state_reader_id: String,
    generation_ids: Vec<String>,
    bundle_manifest: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    import_id: String,
    closure_digest: String,
    worker_manifest_digest: String,
}

fn invalid(message: impl ToString) -> Fault {
    Fault::new("E_BACKUP_CLOSURE_INVALID", message.to_string())
}

fn conflict(message: &str) -> Fault {
    Fault::new("E_IDEMPOTENCY_CONFLICT", message)
}

fn attempt_digest(closure: &str, native: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(format!("{closure}:{native}")))
}

fn bundle<'a>(catalog: &Catalog, request: &'a Request) -> Result<(&'a str, String)> {
    let id = request
        .bundle_digest
        .as_deref()
        .filter(|id| valid_digest(id) && request.route_id.as_deref() == Some("deep"))
        .ok_or_else(|| Fault::invalid("disk closure requires the registered deep RuntimeBundle"))?;
    Ok((id, catalog.bundle(id)?))
}

fn ordered_blocks<'a>(
    manifest: &'a Manifest,
    generations: &[String],
    migration: bool,
) -> Result<Vec<&'a BlockSpec>> {
    let mut ordered = Vec::new();
    let mut visited = std::collections::BTreeMap::new();
    if manifest.generations != generations
        || (if migration {manifest.captures.len() != 1} else {!manifest.captures.is_empty()})
        || manifest.blocks.len() > backup_closure::MAX_CLOSURE
        || (!migration && manifest.members.len() != manifest.blocks.len())
        || manifest.block_digests.len() != manifest.blocks.len()
    {
        return Err(invalid("expected an exact disk-only closure"));
    }
    for root in generations {
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = Some(root.as_str());
        let mut depth = 0;
        while let Some(id) = current {
            if let Some(known) = visited.get(id) {
                depth = *known;
                break;
            }
            if !valid_id(id) || !seen.insert(id) || seen.len() > 64 {
                return Err(invalid("invalid immutable disk ancestry"));
            }
            let spec = manifest
                .blocks
                .get(id)
                .ok_or_else(|| invalid("missing disk ancestor"))?;
            if spec.resource_id != id
                || spec.mutable()
                || spec.capacity_bytes == 0
                || spec.capacity_bytes > i64::MAX as u64
                || spec.capacity_bytes % 512 != 0
                || spec.volume_id.as_deref().is_some_and(|id| !valid_id(id))
                || !manifest
                    .block_digests
                    .get(id)
                    .is_some_and(|value| valid_digest(value))
            {
                return Err(invalid("invalid immutable block descriptor"));
            }
            let bytes = manifest
                .members
                .get(&format!("blocks/{id}/data"))
                .ok_or_else(|| invalid("missing immutable disk member"))?;
            if *bytes == 0
                || *bytes > i64::MAX as u64
                || (spec.backing_id.is_none() && *bytes != spec.capacity_bytes)
                || spec
                    .content_sha256
                    .as_ref()
                    .is_some_and(|value| value != &manifest.block_digests[id])
            {
                return Err(invalid("invalid immutable disk member length or digest"));
            }
            if let Some(parent) = &spec.backing_id {
                if manifest
                    .blocks
                    .get(parent)
                    .is_none_or(|backing| backing.capacity_bytes != spec.capacity_bytes)
                {
                    return Err(invalid("disk and backing capacities differ"));
                }
            }
            chain.push(spec);
            current = spec.backing_id.as_deref();
        }
        if chain.len() + depth > 64 {
            return Err(invalid(
                "immutable disk ancestry exceeds its supported depth",
            ));
        }
        for spec in chain.into_iter().rev() {
            depth += 1;
            visited.insert(spec.resource_id.as_str(), depth);
            ordered.push(spec);
        }
    }
    if ordered.len() != manifest.blocks.len() {
        return Err(invalid("closure contains unrelated disk members"));
    }
    Ok(ordered)
}

fn verify_bytes(
    mut source: File,
    mut output: Option<&File>,
    bytes: u64,
    digest: &str,
) -> Result<()> {
    if source.metadata().map_err(invalid)?.len() != bytes {
        return Err(invalid("disk member length changed"));
    }
    let mut remaining = bytes;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    while remaining > 0 {
        let size = remaining.min(buffer.len() as u64) as usize;
        let chunk = &mut buffer[..size];
        source.read_exact(chunk).map_err(invalid)?;
        hasher.update(&*chunk);
        if let Some(output) = &mut output {
            if chunk.iter().all(|byte| *byte == 0) {
                output
                    .seek(io::SeekFrom::Current(size as i64))
                    .map_err(invalid)?;
            } else {
                output.write_all(chunk).map_err(invalid)?;
            }
        }
        remaining -= size as u64;
    }
    if source.read(&mut [0]).map_err(invalid)? != 0
        || format!("sha256:{:x}", hasher.finalize()) != digest
    {
        return Err(invalid("disk member digest changed"));
    }
    if let Some(output) = output {
        output.set_len(bytes).map_err(invalid)?;
        output
            .set_permissions(Permissions::from_mode(0o400))
            .map_err(invalid)?;
        output.sync_all().map_err(invalid)?;
    }
    Ok(())
}

pub(crate) fn import(
    catalog: &mut Catalog,
    objects: &File,
    request: &Request,
    descriptors: Vec<OwnedFd>,
) -> Result<Value> {
    import_closure(catalog, objects, request, descriptors, None)
}

pub(crate) struct MigrationCapture<'a> {
    pub points: &'a Path,
    pub capture_id: &'a str,
    pub operation_id: &'a str,
    pub manifest_digest: &'a str,
    pub source: &'a crate::ipc::Expected,
}

pub(crate) fn import_migration(
    catalog: &mut Catalog,
    objects: &File,
    request: &Request,
    descriptors: Vec<OwnedFd>,
    capture: MigrationCapture<'_>,
) -> Result<Value> {
    import_closure(catalog, objects, request, descriptors, Some(capture))
}

fn import_closure(
    catalog: &mut Catalog,
    objects: &File,
    request: &Request,
    descriptors: Vec<OwnedFd>,
    migration: Option<MigrationCapture<'_>>,
) -> Result<Value> {
    let (bundle, executable) = bundle(catalog, request)?;
    let input: Import = request.payload()?;
    let generation_set: BTreeSet<_> = input.generation_ids.iter().collect();
    if !valid_id(&input.import_id)
        || !valid_digest(&input.closure_digest)
        || !valid_digest(&input.worker_manifest_digest)
        || generation_set.is_empty()
        || generation_set.len() != input.generation_ids.len()
        || generation_set.len() > backup_closure::MAX_CLOSURE
        || request.fd_table.len() != 1
        || descriptors.len() != 1
        || request.fd_table[0].resource_id != input.import_id
        || request.fd_table[0].role != "closure_directory"
    {
        return Err(Fault::invalid(
            "invalid disk closure import scope or descriptor",
        ));
    }
    let executable = executable
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("invalid registered Worker hash"))?;
    let handshake =
        smolvm_runtime_protocol::handshake(input.bundle_manifest.clone(), executable).map_err(invalid)?;
    if handshake.bundle_digest != bundle || handshake.state_reader_id != input.state_reader_id {
        return Err(Fault::new(
            "E_BUNDLE_UNAVAILABLE",
            "import requires the original Bundle and reader",
        ));
    }
    let op = crate::managed::key(&input.import_id, KIND, 0);
    // Bind both digests to this attempt; the sender verifies the outer
    // manifest, while this Worker independently verifies the native manifest.
    let request_digest = attempt_digest(&input.closure_digest, &input.worker_manifest_digest);
    let result = json!({"import_id":input.import_id,"closure_digest":input.closure_digest,
        "generation_ids":input.generation_ids,"phase":"imported"});
    let directory = File::from(descriptors.into_iter().next().unwrap());
    let flags = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || flags & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY
        || !directory.metadata().map_err(invalid)?.is_dir()
    {
        return Err(Fault::invalid(
            "disk closure requires a readable directory descriptor",
        ));
    }
    let (manifest, _) = backup_closure::load(
        &directory,
        &input.worker_manifest_digest,
        bundle,
        &input.state_reader_id,
    )
    .map_err(invalid)?;
    let layers = ordered_blocks(&manifest, &input.generation_ids, migration.is_some())?;
    if let Some(capture) = &migration {
        let archived = &manifest.captures[0];
        if archived.commit_id != capture.operation_id || archived.manifest_digest != capture.manifest_digest
            || archived.point.capture_id != capture.capture_id
            || Some(&archived.point.incarnation_id) != capture.source.incarnation_id.as_ref()
            || archived.point.execution_epoch != capture.source.execution_epoch
            || archived.point.disk_generations != input.generation_ids {
            return Err(invalid("archive does not carry the ticket's final held StatePoint"));
        }
    }
    match catalog.operation(&op) {
        Ok(previous)
            if previous.kind != KIND
                || previous.bundle_digest != bundle
                || previous.request_digest != request_digest
                || previous.phase == "ABORTED" =>
        {
            return Err(conflict(
                "disk closure import was released or its scope changed",
            ));
        }
        Ok(previous) if previous.phase == "COMPLETED" => {
            let count: i64 = catalog.db.query_row(
                "SELECT COUNT(*) FROM root_refs WHERE owner_kind=? AND owner_id=? AND state='active'",
                params![KIND, input.import_id], |row| row.get(0))?;
            let expected_count = input.generation_ids.len() + usize::from(migration.is_some());
            if count != expected_count as i64 {
                return Err(conflict("disk closure import was released"));
            }
            return Ok(result);
        }
        Ok(_) => {}
        Err(error) if error.code == "E_NOT_FOUND" => {}
        Err(error) => return Err(error),
    }
    catalog.ready()?;

    let mut existing = BTreeSet::new();
    for spec in &layers {
        let id = &spec.resource_id;
        if let Some((owner, prior, identity)) = catalog.block_intent(id)? {
            if prior != **spec || (identity.is_none() && owner != op) {
                return Err(conflict(
                    "disk generation is already registered with different content",
                ));
            }
            if identity.is_some() {
                let closure = catalog.block_closure(id)?;
                let file = blocks::open_object(objects, &closure[0], false)?;
                verify_bytes(
                    file,
                    None,
                    manifest.members[&format!("blocks/{id}/data")],
                    &manifest.block_digests[id],
                )?;
                existing.insert(id.as_str());
            }
        } else {
            match catalog.resource(id) {
                Ok(_) => {
                    return Err(conflict(
                        "disk generation conflicts with an existing resource",
                    ));
                }
                Err(error) if error.code == "E_NOT_FOUND" => {}
                Err(error) => return Err(error),
            }
        }
    }
    let tx = catalog
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT OR IGNORE INTO operations VALUES(?, ?, ?, 'deep', ?, ?, 0, NULL, 'NEW', 'NONE', 1)",
        params![op, KIND, request_digest, input.import_id, bundle],
    )?;
    for spec in layers
        .iter()
        .filter(|spec| !existing.contains(spec.resource_id.as_str()))
    {
        tx.execute(
            "INSERT OR IGNORE INTO managed_blocks VALUES(?,?,?,NULL)",
            params![
                spec.resource_id,
                op,
                serde_json::to_string(spec).map_err(invalid)?
            ],
        )?;
    }
    tx.commit()?;

    let mut prepared = Vec::new();
    for spec in layers
        .into_iter()
        .filter(|spec| !existing.contains(spec.resource_id.as_str()))
    {
        let name = format!("blocks/{}/data", spec.resource_id);
        let bytes = manifest.members[&name];
        let digest = &manifest.block_digests[&spec.resource_id];
        let object = if let Some(published) = blocks::read_published(objects, spec)? {
            verify_bytes(
                blocks::open_object(objects, &published, false)?,
                None,
                bytes,
                digest,
            )?;
            published
        } else {
            let file = backup_closure::open_member(&directory, &name).map_err(invalid)?;
            blocks::materialize_with(objects, &op, spec.clone(), |_, data| {
                verify_bytes(file, Some(data), bytes, digest)
            })?
        };
        prepared.push(object);
    }
    if let Some(capture) = &migration {
        publish_capture(&directory, &input, &manifest, capture.points, bundle)?;
    }
    let tx = catalog.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for object in &prepared {
        blocks::publish_block_record(&tx, &op, object)?;
    }
    for id in &input.generation_ids {
        tx.execute(
            "INSERT INTO root_refs VALUES(?,?,?,'active',1,?)",
            params![KIND, input.import_id, id, op],
        )?;
    }
    if migration.is_some() {
        let item = &manifest.captures[0];
        crate::backup_import::capture(&tx, &manifest, item)?;
        // The captured frame is a migration staging root, owned by this attempt.
        tx.execute("DELETE FROM root_refs WHERE owner_kind='backup_import' AND owner_id=? AND resource_id=?",
            params![manifest.backup_id,item.point.representation_id])?;
        tx.execute("INSERT INTO root_refs VALUES(?,?,?,'active',1,?)",
            params![KIND,input.import_id,item.point.representation_id,op])?;
    }
    tx.execute(
        "UPDATE operations SET phase='COMPLETED',revision=revision+1 WHERE operation_id=?",
        [&op],
    )?;
    tx.commit()?;
    Ok(result)
}

fn publish_capture(
    directory: &File, input: &Import, manifest: &Manifest, points: &Path, bundle: &str,
) -> Result<()> {
    let item = &manifest.captures[0];
    let representation = &item.point.representation_id;
    let prefix = format!("statepoints/{representation}/");
    let stage = tempfile::Builder::new().prefix(".migrate-point-").tempdir_in(points).map_err(invalid)?;
    let destination = points.join(representation);
    if !destination.exists() {
        for (member, bytes) in manifest.members.iter().filter(|(name, _)| !name.starts_with("blocks/")) {
            let path = member.strip_prefix(&prefix).ok_or_else(|| invalid("unexpected migration StatePoint member"))?;
            if path.is_empty() || path.split('/').any(|part| !valid_id(part)) {
                return Err(invalid("invalid migration StatePoint member path"));
            }
            let target = stage.path().join(representation).join(path);
            fs::create_dir_all(target.parent().ok_or_else(|| invalid("missing StatePoint member directory"))?).map_err(invalid)?;
            let output = OpenOptions::new().write(true).create_new(true).mode(0o400).open(target).map_err(invalid)?;
            let source = backup_closure::open_member(directory, member).map_err(invalid)?;
            if source.metadata().map_err(invalid)?.len() != *bytes {
                return Err(invalid("StatePoint member length changed"));
            }
            // The StatePoint reader verifies the manifest, exact chunk digests,
            // checkpoint, RAM, and immutable disk hashes before catalog publication.
            let mut source = source.take(bytes.saturating_add(1));
            if io::copy(&mut source, &mut &output).map_err(invalid)? != *bytes {
                return Err(invalid("StatePoint member changed during transfer"));
            }
            output.sync_all().map_err(invalid)?;
        }
    }
    let existing = destination.exists();
    let root = if existing {points} else {stage.path()};
    let stored = crate::statepoint_store::read(root, &item.point, bundle, &item.commit_id).map_err(invalid)?;
    if stored.digest().map_err(invalid)? != item.manifest_digest {
        return Err(invalid("imported capture does not match the final StatePoint digest"));
    }
    let disks = backup_closure::disk_set(directory, &manifest.blocks, &input.generation_ids).map_err(invalid)?;
    crate::statepoint_store::materialize_in(root, &stored, disks, stage.path()).map_err(invalid)?;
    if !existing {
        let from = stage.path().join(representation);
        backup_closure::sync_directories(&from).map_err(invalid)?;
        fs::rename(from, &destination).map_err(invalid)?;
        File::open(points).and_then(|file| file.sync_all()).map_err(invalid)?;
    }
    Ok(())
}

pub(crate) fn release(catalog: &mut Catalog, objects: &File, request: &Request) -> Result<Value> {
    let (bundle, _) = bundle(catalog, request)?;
    let input: Release = request.payload()?;
    if !valid_id(&input.import_id)
        || !valid_digest(&input.closure_digest)
        || !valid_digest(&input.worker_manifest_digest)
    {
        return Err(Fault::invalid("invalid disk closure release scope"));
    }
    let op = crate::managed::key(&input.import_id, KIND, 0);
    let record = catalog.operation(&op)?;
    if record.kind != KIND
        || record.bundle_digest != bundle
        || record.request_digest
            != attempt_digest(&input.closure_digest, &input.worker_manifest_digest)
    {
        return Err(conflict("disk closure differs from the original import"));
    }
    if record.phase == "NEW" {
        let staged = {
            let mut query = catalog.db.prepare(
                "SELECT spec_json FROM managed_blocks WHERE operation_id=? AND backing_identity IS NULL")?;
            let rows = query.query_map([&op], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for raw in staged {
            let spec = serde_json::from_str(&raw).map_err(invalid)?;
            blocks::discard_staged(objects, &op, &spec)?;
        }
    }
    let tx = catalog
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if record.phase == "NEW" {
        tx.execute(
            "DELETE FROM managed_blocks WHERE operation_id=? AND backing_identity IS NULL",
            [&op],
        )?;
        tx.execute("UPDATE operations SET phase='ABORTED',decision='ABORT',revision=revision+1 WHERE operation_id=?", [&op])?;
    }
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind=? AND owner_id=? AND state='active'",
        params![KIND, input.import_id])?;
    tx.commit()?;
    Ok(
        json!({"import_id":input.import_id,"closure_digest":input.closure_digest,"phase":"released"}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{FdEntry, PROTOCOL};
    use std::fs;

    fn digest(data: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(data))
    }

    fn request(method: &str, bundle: &str, payload: Value) -> Request {
        Request {
            protocol: PROTOCOL.into(),
            method: method.into(),
            request_id: "fixture".into(),
            operation_id: None,
            request_digest: None,
            route_id: Some("deep".into()),
            bundle_digest: Some(bundle.into()),
            expected: None,
            fd_table: Vec::new(),
            payload,
        }
    }

    #[test]
    fn corrupt_member_keeps_catalog_unpublished_and_retry_survives_restart() {
        let scratch = tempfile::tempdir().unwrap();
        let catalog_path = scratch.path().join("catalog.sqlite");
        let stage = scratch.path().join("closure");
        let objects = scratch.path().join("objects");
        fs::create_dir(&objects).unwrap();
        let objects = File::open(objects).unwrap();
        let mut catalog = Catalog::open(&catalog_path, "host", "session").unwrap();
        let executable = "1".repeat(64);
        let mut bundle_manifest = json!({
            "schema":"RuntimeBundle/1","platform":"linux-x86_64",
            "artifacts":[{"path":"smolvm-bin","sha256":executable}],
            "contracts":{"state_reader_id":"reader:fixture","worker_resource":1,
                "capture_control":1,"statepoint":1,"guest_identity":1,
                "block_attachment":1,"network_attachment":1}
        });
        bundle_manifest.sort_all_objects();
        let bundle = digest(&serde_json::to_vec(&bundle_manifest).unwrap());
        bundle_manifest["bundle_digest"] = json!(&bundle);
        catalog
            .register_bundle(&bundle, &format!("sha256:{executable}"))
            .unwrap();

        let first = vec![11; 512];
        let second = vec![22; 512];
        fs::create_dir_all(stage.join("blocks/root")).unwrap();
        fs::create_dir_all(stage.join("blocks/attached")).unwrap();
        fs::write(stage.join("blocks/root/data"), &first).unwrap();
        fs::write(stage.join("blocks/attached/data"), &first).unwrap();
        let spec = |id: &str| {
            json!({
                "resource_id":id,"capacity_bytes":512,"volume_id":format!("volume-{id}"),
                "backing_id":null,"content_sha256":null,"sealed":true
            })
        };
        let manifest = serde_json::to_vec(&json!({
            "schema":"NativeBackupClosure/1","backup_id":"source",
            "bundle_digest":bundle,"state_reader_id":"reader:fixture","captures":[],
            "generations":["root","attached"],
            "blocks":{"root":spec("root"),"attached":spec("attached")},
            "block_digests":{"root":digest(&first),"attached":digest(&second)},
            "members":{"blocks/root/data":512,"blocks/attached/data":512}
        }))
        .unwrap();
        fs::write(stage.join("closure.json"), &manifest).unwrap();
        let outer = digest(b"externally verified outer manifest");
        let native = digest(&manifest);
        let mut envelope = request(
            "ImportImmutableClosure",
            &bundle,
            json!({
                "import_id":"destination","closure_digest":outer,"worker_manifest_digest":native,
                "state_reader_id":"reader:fixture","generation_ids":["root","attached"],"bundle_manifest":bundle_manifest
            }),
        );
        envelope.fd_table.push(FdEntry {
            index: 0,
            resource_id: "destination".into(),
            role: "closure_directory".into(),
        });
        let open_stage = || vec![File::open(&stage).unwrap().into()];

        let error = import(&mut catalog, &objects, &envelope, open_stage()).unwrap_err();
        assert_eq!(error.code, "E_BACKUP_CLOSURE_INVALID");
        assert!(catalog.resource("root").is_err());
        assert!(catalog.resource("attached").is_err());

        drop(catalog);
        let mut catalog = Catalog::open(&catalog_path, "host", "after-restart").unwrap();
        catalog.complete_recovery("after-restart").unwrap();
        fs::write(stage.join("blocks/attached/data"), &second).unwrap();
        let receipt = import(&mut catalog, &objects, &envelope, open_stage()).unwrap();
        assert_eq!(receipt["generation_ids"], json!(["root", "attached"]));
        assert_eq!(
            receipt,
            import(&mut catalog, &objects, &envelope, open_stage()).unwrap()
        );
        let mutable: bool = catalog
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM volume_heads UNION SELECT 1 FROM executions)",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!mutable);
        for (id, bytes) in [("root", first), ("attached", second)] {
            let chain = catalog.block_closure(id).unwrap();
            let mut data = blocks::open_object(&objects, &chain[0], false).unwrap();
            let mut actual = Vec::new();
            data.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, bytes);
        }

        let release_request = request(
            "ReleaseImmutableClosure",
            &bundle,
            json!({
                "import_id":"destination","closure_digest":outer,"worker_manifest_digest":native
            }),
        );
        assert_eq!(
            release(&mut catalog, &objects, &release_request).unwrap()["phase"],
            "released"
        );
        let error = import(&mut catalog, &objects, &envelope, open_stage()).unwrap_err();
        assert_eq!(error.code, "E_IDEMPOTENCY_CONFLICT");
    }
}
