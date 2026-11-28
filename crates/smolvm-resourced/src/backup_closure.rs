//! Pin and transfer immutable backup members through the Worker administrator socket.

use crate::blocks::{self, BlockSpec};
use crate::catalog::Catalog;
use crate::ipc::{Fault, Request, Result, valid_digest, valid_id};
use crate::statepoint_store::{self, Point};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

const MAX_MANIFEST: usize = 16 << 20;
const MAX_CLOSURE: usize = 1024;
const SCHEMA: &str = "NativeBackupClosure/1";
const TRANSFER_SCHEMA: &str = "NativeBackupTransfer/1";

fn disabled(value: &bool) -> bool {
    !value
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    backup_id: String,
    state_reader_id: String,
    capture_ids: Vec<String>,
    generation_ids: Vec<String>,
    bundle_manifest: Value,
    #[serde(default, skip_serializing_if = "disabled")]
    require_member_digests: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Locate {
    backup_id: String,
    #[serde(default)]
    member: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capture {
    pub point: Point,
    pub commit_id: String,
    pub manifest_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<crate::backup_import::Origin>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    schema: String,
    pub backup_id: String,
    pub bundle_digest: String,
    pub state_reader_id: String,
    pub captures: Vec<Capture>,
    pub generations: Vec<String>,
    pub blocks: BTreeMap<String, BlockSpec>,
    #[serde(default)]
    block_digests: BTreeMap<String, String>,
    members: BTreeMap<String, u64>,
}

// The original closure is an opaque string so it keeps the exact digest and
// encoding expected by every already-installed NativeBackupClosure/1 reader.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferManifest {
    schema: String,
    closure: String,
    member_digests: BTreeMap<String, String>,
}

fn invalid(message: &str) -> Fault {
    Fault::new("E_BACKUP_CLOSURE_INVALID", message)
}

fn corrupt(error: impl ToString) -> Fault {
    Fault::new("E_BACKUP_CLOSURE_INVALID", error.to_string())
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn bundle<'a>(catalog: &Catalog, request: &'a Request) -> Result<&'a str> {
    let id = request
        .bundle_digest
        .as_deref()
        .filter(|id| valid_digest(id))
        .ok_or_else(|| invalid("backup requires a registered runtime bundle"))?;
    if request.route_id.as_deref() != Some("deep") {
        return Err(invalid("backup requires the deep runtime route"));
    }
    catalog.bundle(id)?;
    Ok(id)
}

fn open_member(root: &File, path: &str) -> io::Result<File> {
    let parts: Vec<_> = Path::new(path).components().collect();
    if parts.is_empty()
        || parts.len() > 8
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(io::Error::other("unsafe backup member"));
    }
    let mut directory = root.try_clone()?;
    for part in &parts[..parts.len() - 1] {
        let name = part
            .as_os_str()
            .to_str()
            .ok_or_else(|| io::Error::other("invalid backup member"))?;
        directory = crate::worker::openat(&directory, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    }
    let name = parts
        .last()
        .and_then(|part| part.as_os_str().to_str())
        .ok_or_else(|| io::Error::other("invalid backup member"))?;
    let file = crate::worker::openat(&directory, name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("backup member is not a regular file"));
    }
    Ok(file)
}

fn enumerate(
    base: &Path,
    root: &File,
    sub: &Path,
    depth: usize,
    members: &mut BTreeMap<String, u64>,
    digests: &mut Option<BTreeMap<String, String>>,
) -> io::Result<()> {
    if depth > 6 {
        return Err(io::Error::other(
            "StatePoint representation is too deeply nested",
        ));
    }
    for entry in fs::read_dir(base.join(sub))? {
        let entry = entry?;
        let name = sub.join(entry.file_name());
        let mode = entry.file_type()?;
        if mode.is_dir() {
            enumerate(base, root, &name, depth + 1, members, digests)?;
        } else if mode.is_file() {
            let name = name
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 StatePoint member"))?;
            let member = format!("statepoints/{name}");
            let bytes = if let Some(digests) = digests {
                let mut file = open_member(root, name)?;
                let bytes = file.metadata()?.len();
                let hash = hash_file(&mut file)?;
                if file.stream_position()? != bytes {
                    return Err(io::Error::other("StatePoint member changed while pinning"));
                }
                digests.insert(member.clone(), hash);
                bytes
            } else {
                entry.metadata()?.len()
            };
            members.insert(member, bytes);
        } else {
            return Err(io::Error::other(
                "unexpected type in StatePoint representation",
            ));
        }
    }
    Ok(())
}

fn pinned_manifest(catalog: &Catalog, backup: &str, bundle: &str) -> Result<String> {
    if !valid_id(backup) {
        return Err(invalid("invalid backup ID"));
    }
    catalog.db.query_row("SELECT manifest_json FROM native_backup_exports WHERE backup_id=? AND bundle_digest=? AND phase='pinned'",
        params![backup,bundle], |row| row.get(0)).optional()?.ok_or_else(|| Fault::new("E_NOT_FOUND", "native backup is not pinned"))
}

fn manifest_file(raw: &str) -> Result<File> {
    let mut temp = tempfile::NamedTempFile::new().map_err(corrupt)?;
    temp.write_all(raw.as_bytes()).map_err(corrupt)?;
    File::open(temp.path()).map_err(corrupt)
}

pub(crate) fn prepare(
    catalog: &mut Catalog,
    points: &Path,
    objects: &File,
    request: &Request,
) -> Result<(Value, File)> {
    let bundle = bundle(catalog, request)?;
    let selection: Selection = request.payload()?;
    let enrolled = catalog.bundle(bundle)?;
    let executable = enrolled
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("invalid registered executable digest"))?;
    let handshake =
        smolvm_runtime_protocol::handshake(selection.bundle_manifest.clone(), executable)
            .map_err(corrupt)?;
    if handshake.bundle_digest != bundle || handshake.state_reader_id != selection.state_reader_id {
        return Err(invalid(
            "backup requires the reader from the registered RuntimeBundle",
        ));
    }
    let requested = selection.capture_ids.len() + selection.generation_ids.len();
    if !valid_id(&selection.backup_id)
        || requested > MAX_CLOSURE
        || requested == 0
        || selection
            .capture_ids
            .iter()
            .chain(&selection.generation_ids)
            .any(|id| !valid_id(id))
    {
        return Err(invalid("invalid native backup selection"));
    }
    let input = serde_json::to_string(&selection).map_err(corrupt)?;
    if let Some((old_bundle, old_input, raw, phase)) = catalog.db.query_row(
        "SELECT bundle_digest,selection_json,manifest_json,phase FROM native_backup_exports WHERE backup_id=?",
        [&selection.backup_id], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?)))
        .optional()? {
        if old_bundle != bundle || old_input != input || phase != "pinned" {
            return Err(Fault::new("E_IDEMPOTENCY_CONFLICT", "backup scope changed or its roots were released"));
        }
        return Ok((json!({"backup_id":selection.backup_id,"manifest_digest":digest(raw.as_bytes())}), manifest_file(&raw)?));
    }
    // A committed backup has a durable root set and no execution-dependent
    // provider. Recovery only gates the creation of a new closure.
    catalog.ready()?;

    let mut manifest = Manifest {
        schema: SCHEMA.into(),
        backup_id: selection.backup_id.clone(),
        bundle_digest: bundle.into(),
        state_reader_id: selection.state_reader_id,
        captures: Vec::new(),
        generations: selection.generation_ids.clone(),
        blocks: BTreeMap::new(),
        block_digests: BTreeMap::new(),
        members: BTreeMap::new(),
    };
    let mut roots: BTreeSet<String> = selection.generation_ids.into_iter().collect();
    let mut pins = BTreeSet::new();
    let mut hashes = BTreeMap::new();
    let mut member_digests = selection.require_member_digests.then(BTreeMap::new);
    for id in selection.capture_ids {
        let (record, operation) =
            crate::managed_state_restore::source(catalog, "deep", bundle, &id)?;
        let state = statepoint_store::read(points, &record.point, bundle, &record.operation_id)
            .map_err(corrupt)?;
        let actual = state.digest().map_err(corrupt)?;
        if record.manifest_digest.as_deref() != Some(actual.as_str()) {
            return Err(invalid("StatePoint digest differs from the catalog"));
        }
        for (disk, digest, bytes) in state.disk_hashes() {
            if hashes
                .insert(disk.to_owned(), (digest.to_owned(), bytes))
                .is_some_and(|prior| prior != (digest.to_owned(), bytes))
            {
                return Err(invalid("durable captures disagree on a disk digest"));
            }
        }
        pins.insert(record.point.representation_id.clone());
        roots.extend(record.point.disk_generations.iter().cloned());
        enumerate(
            points,
            &File::open(points).map_err(corrupt)?,
            Path::new(&record.point.representation_id),
            0,
            &mut manifest.members,
            &mut member_digests,
        )
        .map_err(corrupt)?;
        let origin = crate::backup_import::describe(catalog, &record, &operation)?;
        manifest.captures.push(Capture {
            point: record.point,
            commit_id: operation.operation_id,
            manifest_digest: actual,
            origin: Some(origin),
        });
    }
    for root in roots {
        for layer in catalog.block_closure(&root)? {
            let id = &layer.spec.resource_id;
            if manifest.blocks.contains_key(id) {
                continue;
            }
            let resource = catalog.resource(id)?;
            if layer.spec.mutable()
                || resource["immutable"] != true
                || resource["durability"] != "durable"
                || resource["state"] != "available"
            {
                return Err(invalid(
                    "backup closure contains a live or unavailable block object",
                ));
            }
            let mut file = blocks::open_object(objects, &layer, false)?;
            let bytes = file.metadata().map_err(corrupt)?.len();
            let hash = if let Some((digest, length)) = hashes.get(id) {
                if *length != bytes {
                    return Err(invalid(
                        "backup ancestor length differs from the original capture",
                    ));
                }
                digest.clone()
            } else if let Some(digest) = &layer.spec.content_sha256 {
                digest.clone()
            } else {
                hash_file(&mut file).map_err(corrupt)?
            };
            let member = format!("blocks/{id}/data");
            if let Some(digests) = &mut member_digests {
                digests.insert(member.clone(), hash.clone());
            }
            manifest.members.insert(member, bytes);
            manifest.block_digests.insert(id.clone(), hash);
            pins.insert(id.clone());
            manifest.blocks.insert(id.clone(), layer.spec);
        }
    }
    let closure = serde_json::to_string(&manifest).map_err(corrupt)?;
    let raw = match member_digests {
        Some(member_digests) => serde_json::to_string(&TransferManifest {
            schema: TRANSFER_SCHEMA.into(),
            closure,
            member_digests,
        })
        .map_err(corrupt)?,
        None => closure,
    };
    if raw.len() > MAX_MANIFEST {
        return Err(Fault::new(
            "E_RESOURCE_LIMIT",
            "backup closure manifest exceeds its supported size",
        ));
    }
    let file = manifest_file(&raw)?;
    let tx = catalog
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    for id in pins {
        if tx.execute("INSERT INTO root_refs SELECT 'backup',?,resource_id,'active',1,created_by_operation FROM resources
            WHERE resource_id=? AND state='available' AND durability='durable' AND immutable=1",params![selection.backup_id,id])? != 1 {
            return Err(invalid("backup closure lost a resource before pin publication"));
        }
    }
    tx.execute(
        "INSERT INTO native_backup_exports VALUES(?,?,?,?,'pinned')",
        params![selection.backup_id, bundle, input, raw],
    )?;
    tx.commit()?;
    Ok((
        json!({"backup_id":selection.backup_id,"manifest_digest":digest(raw.as_bytes())}),
        file,
    ))
}

pub(crate) fn read(
    catalog: &Catalog,
    points: &Path,
    objects: &File,
    request: &Request,
) -> Result<(Value, File)> {
    let bundle = bundle(catalog, request)?;
    let selection: Locate = request.payload()?;
    let raw = pinned_manifest(catalog, &selection.backup_id, bundle)?;
    let manifest = decode_pinned(&raw).map_err(corrupt)?;
    let member = selection
        .member
        .ok_or_else(|| invalid("backup member is missing"))?;
    let bytes = manifest
        .members
        .get(&member)
        .ok_or_else(|| invalid("member is outside the pinned backup closure"))?;
    let file = if let Some(path) = member.strip_prefix("statepoints/") {
        open_member(&File::open(points).map_err(corrupt)?, path).map_err(corrupt)?
    } else {
        let id = member
            .strip_prefix("blocks/")
            .and_then(|v| v.strip_suffix("/data"))
            .ok_or_else(|| invalid("unknown backup member"))?;
        let layer = catalog
            .block_closure(id)?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("backup block object disappeared"))?;
        if layer.spec.mutable() || manifest.blocks.get(id) != Some(&layer.spec) {
            return Err(invalid("pinned block resource changed"));
        }
        blocks::open_object(objects, &layer, false)?
    };
    if file.metadata().map_err(corrupt)?.len() != *bytes {
        return Err(invalid("pinned backup member length changed"));
    }
    Ok((
        json!({"backup_id":selection.backup_id,"member":member,"bytes":bytes}),
        file,
    ))
}

fn decode_pinned(raw: &str) -> io::Result<Manifest> {
    #[derive(Deserialize)]
    struct PinnedTransfer {
        schema: String,
        closure: String,
    }

    if let Ok(manifest) = serde_json::from_str(raw) {
        return Ok(manifest);
    }
    let transfer: PinnedTransfer = serde_json::from_str(raw)?;
    if transfer.schema != TRANSFER_SCHEMA {
        return Err(io::Error::other("unknown backup transfer schema"));
    }
    Ok(serde_json::from_str(&transfer.closure)?)
}

pub(crate) fn release(catalog: &mut Catalog, request: &Request) -> Result<Value> {
    let bundle = bundle(catalog, request)?;
    let selection: Locate = request.payload()?;
    if !valid_id(&selection.backup_id) || selection.member.is_some() {
        return Err(invalid("invalid native backup release"));
    }
    let tx = catalog
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let owned: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM native_backup_exports WHERE backup_id=? AND bundle_digest=?)",
        params![selection.backup_id, bundle],
        |row| row.get(0),
    )?;
    if !owned {
        return Err(Fault::new(
            "E_NOT_FOUND",
            "native backup does not belong to this bundle",
        ));
    }
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='backup' AND owner_id=? AND state='active'",[&selection.backup_id])?;
    tx.execute(
        "UPDATE native_backup_exports SET phase='released' WHERE backup_id=?",
        [&selection.backup_id],
    )?;
    tx.commit()?;
    Ok(json!({"backup_id":selection.backup_id,"phase":"released"}))
}

fn load(
    archive: &File,
    expected: &str,
    bundle: &str,
    reader: &str,
) -> io::Result<(Manifest, Vec<u8>)> {
    let mut raw = Vec::new();
    open_member(archive, "closure.json")?
        .take(MAX_MANIFEST as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_MANIFEST || digest(&raw) != expected {
        return Err(io::Error::other("backup closure digest mismatch"));
    }
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    if manifest.schema != SCHEMA
        || manifest.bundle_digest != bundle
        || manifest.state_reader_id != reader
        || !valid_digest(bundle)
        || !valid_id(&manifest.backup_id)
        // Reader contracts are opaque manifest values. Released readers use
        // colons between the family and source revisions.
        || reader.trim().is_empty()
    {
        return Err(io::Error::other(
            "backup closure requires the original reader and bundle",
        ));
    }
    for capture in &manifest.captures {
        if !valid_id(&capture.point.capture_id)
            || !valid_id(&capture.point.representation_id)
            || !valid_id(&capture.point.incarnation_id)
            || !valid_id(&capture.commit_id)
            || !valid_digest(&capture.manifest_digest)
        {
            return Err(io::Error::other("invalid archived StatePoint identity"));
        }
    }
    Ok((manifest, raw))
}

fn disk_set(
    root: &File,
    blocks: &BTreeMap<String, BlockSpec>,
    generations: &[String],
) -> io::Result<BTreeMap<String, File>> {
    let mut result = BTreeMap::new();
    for id in generations {
        let mut seen = BTreeSet::new();
        let mut next = Some(id);
        while let Some(id) = next {
            if !valid_id(id) || !seen.insert(id) || seen.len() > 64 {
                return Err(io::Error::other("invalid backup block graph"));
            }
            let spec = blocks
                .get(id)
                .ok_or_else(|| io::Error::other("backup closure omits a block ancestor"))?;
            if &spec.resource_id != id || spec.mutable() {
                return Err(io::Error::other(
                    "backup closure substitutes a different block",
                ));
            }
            if !result.contains_key(id) {
                result.insert(id.clone(), open_member(root, &format!("blocks/{id}/data"))?);
            }
            next = spec.backing_id.as_ref();
        }
    }
    Ok(result)
}

fn hash_file(file: &mut File) -> io::Result<String> {
    let mut sha = Sha256::new();
    file.rewind()?;
    io::copy(file, &mut sha)?;
    Ok(format!("sha256:{:x}", sha.finalize()))
}

/// Revalidate all captured RAM, checkpoint, and disk digests with the same
/// reader used by a normal StatePoint restore. Optionally publish an isolated
/// immutable recovery directory using an atomic non-replacing rename.
pub(crate) fn restore(
    archive: &Path,
    expected: &str,
    bundle: &str,
    reader: &str,
    output: Option<&Path>,
    registered_bundle: Option<(&Path, &str)>,
) -> io::Result<Value> {
    let original = File::open(archive)?;
    let (manifest, raw) = load(&original, expected, bundle, reader)?;
    if registered_bundle.is_some() && output.is_none() {
        return Err(io::Error::other(
            "Worker catalog import requires an independent output directory",
        ));
    }
    let stage = output
        .map(|path| {
            let parent = path
                .parent()
                .filter(|value| !value.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let directory = tempfile::Builder::new()
                .prefix(".native-recovery-")
                .tempdir_in(parent)?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            Ok::<_, io::Error>(directory)
        })
        .transpose()?;
    for (name, bytes) in &manifest.members {
        let mut file = open_member(&original, name)?;
        if file.metadata()?.len() != *bytes {
            return Err(io::Error::other("backup member length changed"));
        }
        if let Some(stage) = &stage {
            let target = stage.path().join(name);
            fs::create_dir_all(
                target
                    .parent()
                    .ok_or_else(|| io::Error::other("invalid member path"))?,
            )?;
            let mut copy = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(target)?;
            if io::copy(&mut file, &mut copy)? != *bytes {
                return Err(io::Error::other("backup member changed during import"));
            }
            copy.sync_all()?;
        }
    }
    let path = stage.as_ref().map(|dir| dir.path()).unwrap_or(archive);
    let root = File::open(path)?;
    let mut all = disk_set(&root, &manifest.blocks, &manifest.generations)?;
    for capture in &manifest.captures {
        let disks = disk_set(&root, &manifest.blocks, &capture.point.disk_generations)?;
        all.extend(
            disks
                .iter()
                .map(|(id, file)| Ok((id.clone(), file.try_clone()?)))
                .collect::<io::Result<BTreeMap<_, _>>>()?,
        );
        let points = path.join("statepoints");
        let point = statepoint_store::read(&points, &capture.point, bundle, &capture.commit_id)?;
        if point.digest()? != capture.manifest_digest {
            return Err(io::Error::other(
                "backup no longer has the original StatePoint manifest digest",
            ));
        }
        let _ = statepoint_store::materialize_in(&points, &point, disks, &std::env::temp_dir())?;
    }
    if all.len() != manifest.blocks.len() {
        return Err(io::Error::other(
            "backup block catalog has members outside the selected closure",
        ));
    }
    for (id, mut file) in all {
        let expected = manifest
            .block_digests
            .get(&id)
            .or(manifest.blocks[&id].content_sha256.as_ref());
        if expected.is_some_and(|value| !valid_digest(value))
            || (expected.is_none() && manifest.captures.is_empty())
        {
            return Err(io::Error::other(
                "backup lacks an immutable generation digest",
            ));
        }
        if let Some(expected) = expected {
            if hash_file(&mut file)? != *expected {
                return Err(io::Error::other("immutable block digest changed"));
            }
        }
    }
    if let (Some(stage), Some(output)) = (stage, output) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(stage.path().join("closure.json"))?;
        file.write_all(&raw)?;
        file.sync_all()?;
        if let Some((bundle_manifest, executable_hash)) = registered_bundle {
            crate::backup_import::catalog(
                stage.path(),
                &manifest,
                bundle_manifest,
                executable_hash,
            )
            .map_err(io::Error::other)?;
        }
        sync_directories(stage.path())?;
        let from = CString::new(stage.path().as_os_str().as_encoded_bytes())?;
        let to = CString::new(output.as_os_str().as_encoded_bytes())?;
        let status = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        let parent = output
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    Ok(
        json!({"schema":SCHEMA,"backup_id":manifest.backup_id,"manifest_digest":expected,
        "captures":manifest.captures.len(),"block_generations":manifest.blocks.len(),"bundle_digest":bundle,"state_reader_id":reader}),
    )
}

fn sync_directories(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_digests_keep_the_original_closure_reader_compatible() {
        let root = tempfile::tempdir().unwrap();
        let points = root.path().join("statepoints");
        fs::create_dir_all(points.join("p1/pack")).unwrap();
        fs::write(points.join("p1/pack/ram"), b"ram").unwrap();
        fs::write(points.join("p1/statepoint.json"), b"point").unwrap();
        let bundle = digest(b"bundle");
        let mut manifest = Manifest {
            schema: SCHEMA.into(),
            backup_id: "backup".into(),
            bundle_digest: bundle.clone(),
            state_reader_id: "reader:v1".into(),
            captures: Vec::new(),
            generations: Vec::new(),
            blocks: BTreeMap::new(),
            block_digests: BTreeMap::new(),
            members: BTreeMap::new(),
        };
        let mut member_digests = Some(BTreeMap::new());
        enumerate(
            &points,
            &File::open(&points).unwrap(),
            Path::new("p1"),
            0,
            &mut manifest.members,
            &mut member_digests,
        )
        .unwrap();
        let closure = serde_json::to_string(&manifest).unwrap();
        let digest_map = member_digests.unwrap();
        let member = "statepoints/p1/pack/ram";
        assert_eq!(manifest.members[member], 3);
        assert_eq!(digest_map[member], digest(b"ram"));
        assert_eq!(
            digest_map["statepoints/p1/statepoint.json"],
            digest(b"point")
        );

        let transfer = serde_json::to_string(&TransferManifest {
            schema: TRANSFER_SCHEMA.into(),
            closure: closure.clone(),
            member_digests: digest_map,
        })
        .unwrap();
        assert_eq!(decode_pinned(&transfer).unwrap().members, manifest.members);
        assert_eq!(decode_pinned(&closure).unwrap().members, manifest.members);
        fs::write(root.path().join("closure.json"), &closure).unwrap();
        let (archived, original) = load(
            &File::open(root.path()).unwrap(),
            &digest(closure.as_bytes()),
            &bundle,
            "reader:v1",
        )
        .unwrap();
        assert_eq!(original, closure.as_bytes());
        assert_eq!(archived.members, manifest.members);
    }
}
