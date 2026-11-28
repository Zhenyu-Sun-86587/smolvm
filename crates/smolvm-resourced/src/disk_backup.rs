//! Immutable disk-only recovery points and stopped-writer replacement.

use crate::blocks::{self, BlockObject, BlockSpec};
use crate::catalog::{self, Catalog, VolumeHead};
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::{managed, product_volumes};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, Permissions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;

const KIND: &str = "disk_backup";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    action: String,
    attempt_id: String,
    backup_id: String,
    owner_epoch: i64,
    binding_generation: i64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
struct Product {
    owner_id: String,
    attachment_revision: i64,
    #[serde(default)]
    generation_id: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
struct Slot {
    device_id: String,
    role: String,
    attachment_id: String,
    volume_id: String,
    read_only: bool,
    capacity_bytes: u64,
    product: Option<Product>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
struct Selection {
    slot: Slot,
    product_revision: Option<i64>,
    top: String,
    backing_identity: String,
}

#[derive(Deserialize, Serialize)]
struct Layer {
    resource_id: String,
    digest: String,
}

#[derive(Deserialize, Serialize)]
struct SavedDisk {
    slot: Slot,
    layers: Vec<Layer>,
}

impl SavedDisk {
    fn generation(&self) -> Result<&str> {
        self.layers
            .first()
            .map(|layer| layer.resource_id.as_str())
            .ok_or_else(|| bad_catalog("disk backup has an empty immutable closure"))
    }

    fn receipt(&self) -> Result<Value> {
        Ok(
            json!({"device_id": self.slot.device_id, "role": self.slot.role,
            "volume_id": self.slot.volume_id, "read_only": self.slot.read_only,
            "capacity_bytes": self.slot.capacity_bytes, "generation_id": self.generation()?}),
        )
    }
}

struct Backup {
    disks: Vec<SavedDisk>,
    deleted: bool,
}

struct Attempt<'a> {
    input: Input,
    scope: &'a Request,
    digest: String,
    native: Request,
}

fn bad_catalog(message: &str) -> Fault {
    Fault::new("E_CATALOG", message)
}

fn fenced(message: &str) -> Fault {
    Fault::new("DISK_BACKUP_WRITER_CHANGED", message)
}

fn unsupported(message: &str) -> Fault {
    Fault::new("DISK_BACKUP_RUNTIME_UNAVAILABLE", message)
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn decode<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T> {
    serde_json::from_str(raw).map_err(|_| bad_catalog("invalid stored disk backup record"))
}

impl<'a> Attempt<'a> {
    fn new(scope: &'a Request) -> Result<Self> {
        let input: Input = scope.payload()?;
        let (route, bundle, expected) = scope.scope()?;
        if route != "deep"
            || !scope.fd_table.is_empty()
            || scope.operation_id.as_deref() != Some(&input.attempt_id)
            || !valid_id(&input.attempt_id)
            || !valid_id(&input.backup_id)
            || input.owner_epoch < 1
            || input.binding_generation < 1
            || expected.execution_epoch < 1
            || expected.incarnation_id.is_some()
            || !matches!(input.action.as_str(), "capture" | "restore" | "delete")
            || (input.action == "capture"
                && input.backup_id != format!("backup_{}", input.attempt_id))
        {
            return Err(Fault::invalid("invalid stopped disk backup scope"));
        }
        let digest = sha(json!([route, bundle, expected, input])
            .to_string()
            .as_bytes());
        // The public operation ID remains available for the ordinary System launch.
        let mut native = scope.derived("DiskBackup", Value::Null);
        native.operation_id = Some(managed::key(&input.attempt_id, "disk-backup", 0));
        native.request_digest = Some(digest.clone());
        Ok(Self {
            input,
            scope,
            digest,
            native,
        })
    }

    fn receipt(&self, phase: &str) -> Value {
        json!({"phase": phase, "attempt_id": self.input.attempt_id, "backup_id": self.input.backup_id})
    }

    fn failure(&self, error: Fault) -> Value {
        let mut result = self.receipt("failed");
        result["error_code"] = json!(error.code);
        result["error"] = json!(error.message);
        result
    }

    fn load_backup(&self, catalog: &Catalog) -> Result<Backup> {
        let (bundle, instance, epoch, owner, generation, raw, deleted) = catalog.db.query_row(
            "SELECT bundle_digest,instance_id,execution_epoch,owner_epoch,binding_generation,disks_json,deleted
             FROM disk_backups WHERE backup_id=?",
            [&self.input.backup_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?, r.get::<_, String>(5)?, r.get::<_, bool>(6)?)),
        ).optional()?.ok_or_else(|| Fault::new("DISK_BACKUP_NOT_FOUND", "disk backup is unavailable"))?;
        let (_, wanted_bundle, expected) = self.scope.scope()?;
        if bundle != wanted_bundle
            || instance != expected.instance_id
            || owner != self.input.owner_epoch
            || generation != self.input.binding_generation
            || expected.execution_epoch < epoch
            || (self.input.action == "delete" && expected.execution_epoch != epoch)
        {
            return Err(fenced(
                "disk backup is bound to a different original machine owner",
            ));
        }
        Ok(Backup {
            disks: decode(&raw)?,
            deleted,
        })
    }
}

pub(crate) fn apply(catalog: &mut Catalog, objects: &File, request: &Request) -> Result<Value> {
    let attempt = Attempt::new(request)?;
    let prior = catalog.db.query_row(
        "SELECT intent_digest,selection_json,receipt_json FROM disk_backup_attempts WHERE attempt_id=?",
        [&attempt.input.attempt_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?)),
    ).optional()?;
    if let Some((digest, selection, receipt)) = &prior {
        if digest != &attempt.digest {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "disk backup attempt scope changed",
            ));
        }
        if let Some(receipt) = receipt {
            let receipt: Value = decode(receipt)?;
            if receipt["phase"] == "restored" {
                let selection: Vec<Selection> = decode(selection.as_deref().unwrap_or("null"))?;
                retire_previous_heads(catalog, objects, &attempt, &selection);
            }
            return Ok(receipt);
        }
    }
    if attempt.input.action == "delete" {
        return delete(catalog, &attempt);
    }

    let selection = stopped_selection(catalog, &attempt);
    if let Some((_, stored, _)) = &prior {
        // Before retrying any staged file, reestablish the same full stopped scope.
        let result = selection.and_then(|selection| {
            if stored.as_deref() != Some(json!(selection).to_string().as_str()) {
                return Err(fenced(
                    "stopped disk set changed while the backup attempt was pending",
                ));
            }
            run(catalog, objects, &attempt, &selection)
        });
        return finish_pending(catalog, objects, &attempt, result);
    }
    let selection = match selection {
        Ok(selection) => selection,
        Err(error) => return reject_unstarted(catalog, &attempt, error),
    };
    let existing: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM disk_backups WHERE backup_id=?)",
        [&attempt.input.backup_id],
        |r| r.get(0),
    )?;
    if attempt.input.action == "capture" && existing {
        return reject_unstarted(
            catalog,
            &attempt,
            Fault::new("E_IDEMPOTENCY_CONFLICT", "disk backup ID already exists"),
        );
    }
    let native_id = attempt.native.operation()?.0;
    let begun = catalog.begin_with(&attempt.native, KIND, |tx| {
        tx.execute(
            "INSERT INTO disk_backup_attempts VALUES(?,?,?,?,NULL)",
            params![
                attempt.input.attempt_id,
                attempt.digest,
                native_id,
                json!(selection).to_string()
            ],
        )?;
        Ok(())
    });
    if let Err(error) = begun {
        return reject_unstarted(catalog, &attempt, error);
    }
    let result = run(catalog, objects, &attempt, &selection);
    finish_pending(catalog, objects, &attempt, result)
}

fn reject_unstarted(catalog: &Catalog, attempt: &Attempt<'_>, error: Fault) -> Result<Value> {
    if matches!(
        error.code,
        "E_CATALOG" | "E_RECOVERING" | "E_BUNDLE_UNAVAILABLE" | "E_OPERATION_IN_PROGRESS"
    ) {
        return Err(error);
    }
    let receipt = attempt.failure(error);
    catalog.db.execute(
        "INSERT INTO disk_backup_attempts VALUES(?,?,NULL,NULL,?)",
        params![
            attempt.input.attempt_id,
            attempt.digest,
            receipt.to_string()
        ],
    )?;
    Ok(receipt)
}

fn delete(catalog: &mut Catalog, attempt: &Attempt<'_>) -> Result<Value> {
    let backup = match attempt.load_backup(catalog) {
        Ok(backup) => backup,
        Err(error) => return reject_unstarted(catalog, attempt, error),
    };
    let receipt = attempt.receipt("deleted");
    let tx = catalog.db.transaction()?;
    if !backup.deleted {
        tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='disk_backup'
            AND owner_id=? AND state='active'", [&attempt.input.backup_id])?;
        tx.execute(
            "UPDATE disk_backups SET deleted=1 WHERE backup_id=?",
            [&attempt.input.backup_id],
        )?;
    }
    tx.execute(
        "INSERT INTO disk_backup_attempts VALUES(?,?,NULL,NULL,?)",
        params![
            attempt.input.attempt_id,
            attempt.digest,
            receipt.to_string()
        ],
    )?;
    tx.commit()?;
    Ok(receipt)
}

fn stopped_selection(catalog: &Catalog, attempt: &Attempt<'_>) -> Result<Vec<Selection>> {
    let (route, bundle, expected) = attempt.scope.scope()?;
    let (epoch, incarnation, active) = catalog::binding(&catalog.db, route, &expected.instance_id)?;
    if epoch != expected.execution_epoch || incarnation.is_some() {
        return Err(fenced(
            "the exact stopped Worker disk writer is no longer current",
        ));
    }
    if active
        .as_deref()
        .is_some_and(|id| Some(id) != attempt.native.operation_id.as_deref())
    {
        return Err(Fault::new(
            "E_OPERATION_IN_PROGRESS",
            "another Worker operation owns the disk writer",
        ));
    }
    let last: Option<String> = catalog.db.query_row(
        "SELECT last_operation_id FROM executions WHERE route_id=? AND instance_id=? AND bundle_digest=?
            AND execution_epoch=? AND phase='exited'",
        params![route, expected.instance_id, bundle, epoch], |r| r.get(0),
    ).optional()?;
    let op = catalog.operation(&last.ok_or_else(|| {
        fenced("no confirmed exited execution exists at the selected disk epoch")
    })?)?;
    let plan = managed::plan(catalog, &op)?
        .filter(|plan| op.phase == "COMPLETED" && plan.machine.boot_profile == "system-debian-v1")
        .ok_or_else(|| unsupported("disk backup requires a completed managed System disk plan"))?;
    let mut selection = Vec::with_capacity(plan.devices.len());
    let mut product_count = 0;
    let mut volumes = BTreeSet::new();
    for device in plan.devices {
        let disk = device.disk;
        let is_root = disk.role == "root" && disk.device_id == "root" && !disk.read_only;
        let product: Option<(Product, i64)> = catalog.db.query_row(
            "SELECT v.owner_id,a.revision,a.generation_id,v.revision FROM product_volume_attachments a JOIN product_volumes v USING(volume_id)
             WHERE a.volume_id=? AND a.attachment_id=? AND a.instance_id=? AND a.device_key=?
               AND a.state='reserved' AND a.mode=? AND a.capture_policy='include'
               AND v.state='available' AND v.route_id=? AND v.bundle_digest=?
               AND NOT EXISTS(SELECT 1 FROM product_volume_operations p WHERE p.volume_id=v.volume_id AND p.result_json IS NULL)",
            params![device.volume_id, disk.attachment_id, expected.instance_id, disk.device_id,
                if disk.read_only { "ro" } else { "rw" }, route, bundle],
            |r| Ok((Product { owner_id: r.get(0)?, attachment_revision: r.get(1)?, generation_id: r.get(2)? }, r.get(3)?)),
        ).optional()?;
        let (product, product_revision) = match product {
            Some((product, revision)) => (Some(product), Some(revision)),
            None => (None, None),
        };
        if !is_root && (disk.role != "data" || product.is_none()) {
            return Err(fenced(
                "a disk is not the original reserved, included product volume",
            ));
        }
        if product.is_some() {
            product_count += 1;
        }
        if !volumes.insert(device.volume_id.clone()) {
            return Err(fenced(
                "a disk appears more than once in the stopped writer set",
            ));
        }
        let top = if disk.read_only {
            product
                .as_ref()
                .and_then(|p| p.generation_id.clone())
                .unwrap_or(disk.generation_id)
        } else {
            catalog
                .db
                .query_row(
                    "SELECT head_resource_id FROM volume_heads WHERE volume_id=?",
                    [&device.volume_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
                .ok_or_else(|| fenced("the stopped writer volume has no current head"))?
        };
        let closure = catalog.block_closure(&top)?;
        let current = &closure[0];
        if current.spec.mutable() == disk.read_only || current.spec.capacity_bytes == 0 {
            return Err(fenced("current disk mode does not match the stopped slot"));
        }
        if !disk.read_only {
            catalog.require_unsealed_head(&top)?;
            let head = VolumeHead {
                volume_id: device.volume_id.clone(),
                head_resource_id: top.clone(),
            };
            if current.spec.volume_id.as_deref() != Some(&device.volume_id)
                || catalog.volume_identity(&head)? != current.backing_identity
                || catalog.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM writer_reservations WHERE volume_id=?)",
                    [&device.volume_id],
                    |r| r.get::<_, bool>(0),
                )?
            {
                return Err(fenced(
                    "the disk still has a writer or its current generation changed",
                ));
            }
        }
        selection.push(Selection {
            slot: Slot {
                device_id: disk.device_id,
                role: disk.role,
                attachment_id: disk.attachment_id,
                volume_id: device.volume_id,
                read_only: disk.read_only,
                capacity_bytes: current.spec.capacity_bytes,
                product,
            },
            product_revision,
            top,
            backing_identity: current.backing_identity.clone(),
        });
    }
    if selection
        .first()
        .is_none_or(|first| first.slot.role != "root")
    {
        return Err(fenced("the stopped writer has no System root disk"));
    }
    product_volumes::require_launch_set(catalog, route, &expected.instance_id, product_count)?;
    Ok(selection)
}

fn run(
    catalog: &mut Catalog,
    objects: &File,
    attempt: &Attempt<'_>,
    selection: &[Selection],
) -> Result<Value> {
    let mut locked = Vec::with_capacity(selection.len());
    for selected in selection {
        let closure = catalog.block_closure(&selected.top)?;
        let top = &closure[0];
        if top.backing_identity != selected.backing_identity {
            return Err(fenced("the stopped head backing identity changed"));
        }
        let handle = if selected.slot.read_only {
            None
        } else {
            let (_, handle) = blocks::fence_head_for_seal(objects, top, false)?;
            handle
                .sync_all()
                .map_err(crate::statepoint_capture::host_io)?;
            Some(handle)
        };
        locked.push((closure, handle));
    }
    // Keep the full set of exclusive old writer FDs open until the committed
    // SQLite transaction can no longer reassign any of these old heads.
    let publish = if attempt.input.action == "capture" {
        prepare_capture(catalog, objects, attempt, selection, &locked)?
    } else {
        prepare_restore(catalog, objects, attempt, selection)?
    };
    let result = publish.apply(catalog, attempt, selection);
    drop(locked);
    if result.is_ok() && attempt.input.action == "restore" {
        retire_previous_heads(catalog, objects, attempt, selection);
    }
    result
}

// A failed restore cannot make any original head read-only. Superseded heads
// are reclaimed only after the writer CAS and receipt have committed. This
// cleanup can safely resume after a lost reply or an interrupted inode seal.
fn retire_previous_heads(
    catalog: &mut Catalog,
    objects: &File,
    attempt: &Attempt<'_>,
    selection: &[Selection],
) {
    for old in selection.iter().filter(|disk| !disk.slot.read_only) {
        if let Err(error) = retire_previous_head(catalog, objects, attempt, old) {
            eprintln!(
                "disk backup {} could not mark superseded head {} for collection: {}",
                attempt.input.attempt_id, old.top, error.code
            );
        }
    }
}

fn retire_previous_head(
    catalog: &mut Catalog,
    objects: &File,
    attempt: &Attempt<'_>,
    old: &Selection,
) -> Result<()> {
    let Some((_, spec, _)) = catalog.block_intent(&old.top)? else {
        return Ok(());
    };
    if !spec.mutable() {
        return Ok(());
    }
    let fenced: bool = catalog.db.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM volume_heads WHERE head_resource_id=?1)
        AND NOT EXISTS(SELECT 1 FROM writer_reservations WHERE head_resource_id=?1)",
        [&old.top],
        |r| r.get(0),
    )?;
    if !fenced {
        return Err(Fault::new(
            "E_FENCE_UNPROVEN",
            "superseded disk still has writer authority",
        ));
    }
    let mut object = catalog.block_closure(&old.top)?.remove(0);
    if object.backing_identity != old.backing_identity {
        return Err(Fault::new(
            "E_BLOCK_BACKING_CHANGED",
            "superseded disk backing identity changed",
        ));
    }
    let (directory, handle) = blocks::fence_head_for_seal(objects, &object, true)?;
    blocks::seal_fenced_head(&directory, &handle, &mut object)?;
    let op = attempt.native.operation()?.0;
    let tx = catalog.db.transaction()?;
    blocks::publish_seal_record(&tx, op, &object)?;
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='operation' AND owner_id=?
        AND resource_id=? AND state='active'", params![op, old.top])?;
    tx.commit()?;
    Ok(())
}

struct Publish {
    disks: Vec<SavedDisk>,
    staged: Vec<BlockObject>,
    observations: Vec<Value>,
}

fn stage(catalog: &Catalog, attempt: &Attempt<'_>, spec: &BlockSpec) -> Result<()> {
    let op = attempt.native.operation()?.0;
    match catalog.block_intent(&spec.resource_id)? {
        Some((owner, recorded, None)) if owner == op && recorded == *spec => Ok(()),
        Some(_) => Err(fenced("staged block specification changed")),
        None => {
            catalog.db.execute(
                "INSERT INTO managed_blocks VALUES(?,?,?,NULL)",
                params![spec.resource_id, op, json!(spec).to_string()],
            )?;
            Ok(())
        }
    }
}

fn prepare_capture(
    catalog: &Catalog,
    objects: &File,
    attempt: &Attempt<'_>,
    selection: &[Selection],
    locked: &[(Vec<BlockObject>, Option<File>)],
) -> Result<Publish> {
    let op = attempt.native.operation()?.0;
    let mut disks = Vec::with_capacity(selection.len());
    let mut staged = Vec::new();
    for (index, (selected, (closure, handle))) in selection.iter().zip(locked).enumerate() {
        let mut layers = Vec::with_capacity(closure.len());
        if let Some(source) = handle {
            let mut spec = closure[0].spec.clone();
            spec.resource_id = managed::key(op, "disk-cut", index);
            spec.sealed = true;
            stage(catalog, attempt, &spec)?;
            let clone =
                blocks::materialize_with(objects, op, spec, |_, target| copy_cut(source, target))?;
            layers.push(layer_digest(objects, &clone)?);
            staged.push(clone);
        }
        let skip = usize::from(handle.is_some());
        for layer in &closure[skip..] {
            layers.push(layer_digest(objects, layer)?);
        }
        disks.push(SavedDisk {
            slot: selected.slot.clone(),
            layers,
        });
    }
    Ok(Publish {
        disks,
        staged,
        observations: Vec::new(),
    })
}

fn layer_digest(objects: &File, object: &BlockObject) -> Result<Layer> {
    let mut source = blocks::open_object(objects, object, false)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut source, &mut hasher).map_err(crate::statepoint_capture::host_io)?;
    Ok(Layer {
        resource_id: object.spec.resource_id.clone(),
        digest: format!("sha256:{:x}", hasher.finalize()),
    })
}

fn copy_cut(source: &File, mut target: &File) -> Result<()> {
    let host_io = crate::statepoint_capture::host_io;
    let mut source = source.try_clone().map_err(host_io)?;
    let size = source.metadata().map_err(host_io)?.len();
    source.rewind().map_err(host_io)?;
    let mut buffer = vec![0; 1 << 20];
    let mut remaining = size;
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        let bytes = &mut buffer[..count];
        source.read_exact(bytes).map_err(host_io)?;
        if bytes.iter().any(|byte| *byte != 0) {
            target.write_all(bytes).map_err(host_io)?;
        } else {
            target
                .seek(SeekFrom::Current(count as i64))
                .map_err(host_io)?;
        }
        remaining -= count as u64;
    }
    target.set_len(size).map_err(host_io)?;
    target
        .set_permissions(Permissions::from_mode(0o400))
        .map_err(host_io)?;
    target.sync_all().map_err(host_io)
}

fn prepare_restore(
    catalog: &Catalog,
    objects: &File,
    attempt: &Attempt<'_>,
    selection: &[Selection],
) -> Result<Publish> {
    let backup = attempt.load_backup(catalog)?;
    if backup.deleted || backup.disks.len() != selection.len() {
        return Err(fenced(
            "disk backup is deleted or has a different disk layout",
        ));
    }
    let mut layers = 0;
    let mut closures = Vec::with_capacity(selection.len());
    // Verify every immutable member before staging any replacement writer.
    for (saved, current) in backup.disks.iter().zip(selection) {
        if saved.slot != current.slot
            || (saved.slot.read_only && saved.generation()? != current.top)
        {
            return Err(fenced(
                "disk backup attachment identity, capacity or generation changed",
            ));
        }
        let closure = catalog.block_closure(saved.generation()?)?;
        if closure.len() != saved.layers.len() {
            return Err(Fault::new(
                "DISK_BACKUP_CONTENT_MISMATCH",
                "immutable disk closure membership changed",
            ));
        }
        for (layer, original) in closure.iter().zip(&saved.layers) {
            let actual = layer_digest(objects, layer)?;
            if actual.resource_id != original.resource_id || actual.digest != original.digest {
                return Err(Fault::new(
                    "DISK_BACKUP_CONTENT_MISMATCH",
                    "immutable backup member differs from the captured bytes",
                ));
            }
        }
        layers += closure.len() + usize::from(!current.slot.read_only);
        closures.push(closure);
    }
    if layers > crate::ipc::MAX_FDS {
        return Err(unsupported(
            "restoring the disk chains would exceed the System launch descriptor limit",
        ));
    }
    let op = attempt.native.operation()?.0;
    let mut staged = Vec::new();
    let mut observations = Vec::new();
    for (index, (current, closure)) in selection.iter().zip(&closures).enumerate() {
        if current.slot.read_only {
            continue;
        }
        let parent = &closure[0];
        let spec = BlockSpec {
            resource_id: managed::key(op, "restored-head", index),
            capacity_bytes: current.slot.capacity_bytes,
            volume_id: Some(current.slot.volume_id.clone()),
            backing_id: Some(parent.spec.resource_id.clone()),
            content_sha256: None,
            sealed: false,
        };
        stage(catalog, attempt, &spec)?;
        let replacement = blocks::materialize(objects, op, spec, None, Some(parent))?;
        if let Some(product) = &current.slot.product {
            let query = attempt.scope.derived(
                "QueryVolume",
                json!({"volume_id": current.slot.volume_id, "owner_id": product.owner_id}),
            );
            let mut observed = product_volumes::query(catalog, &query)?;
            let revision = current
                .product_revision
                .filter(|value| Some(*value) == observed["revision"].as_i64())
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| fenced("product volume revision changed during disk restore"))?;
            if observed["state"] != "available" || observed["head_resource_id"] != current.top {
                return Err(fenced(
                    "product volume no longer describes the stopped writer",
                ));
            }
            observed["head_resource_id"] = json!(replacement.spec.resource_id);
            observed["generation_id"] = json!(parent.spec.resource_id);
            observed["revision"] = json!(revision);
            observations.push(observed);
        }
        staged.push(replacement);
    }
    Ok(Publish {
        disks: backup.disks,
        staged,
        observations,
    })
}

impl Publish {
    fn apply(
        self,
        catalog: &mut Catalog,
        attempt: &Attempt<'_>,
        selection: &[Selection],
    ) -> Result<Value> {
        let (route, bundle, expected) = attempt.scope.scope()?;
        let native_id = attempt.native.operation()?.0;
        let mut receipt = attempt.receipt(if attempt.input.action == "capture" {
            "ready"
        } else {
            "restored"
        });
        receipt["disks"] = json!(self
            .disks
            .iter()
            .map(SavedDisk::receipt)
            .collect::<Result<Vec<_>>>()?);
        if !self.observations.is_empty() {
            receipt["volume_observations"] = json!(self.observations);
        }
        let tx = catalog.db.transaction()?;
        let (epoch, incarnation, active) = catalog::binding(&tx, route, &expected.instance_id)?;
        if epoch != expected.execution_epoch
            || incarnation.is_some()
            || active.as_deref() != Some(native_id)
        {
            return Err(fenced(
                "stopped slot no longer grants the disk backup attempt writer authority",
            ));
        }
        for selected in selection {
            verify_product_scope(&tx, route, bundle, &expected.instance_id, selected)?;
        }
        for replacement in &self.staged {
            blocks::publish_block_record(&tx, native_id, replacement)?;
        }
        if attempt.input.action == "capture" {
            tx.execute(
                "INSERT INTO disk_backups VALUES(?,?,?,?,?,?,?,0)",
                params![
                    attempt.input.backup_id,
                    bundle,
                    expected.instance_id,
                    epoch,
                    attempt.input.owner_epoch,
                    attempt.input.binding_generation,
                    json!(self.disks).to_string()
                ],
            )?;
            for disk in &self.disks {
                tx.execute(
                    "INSERT OR IGNORE INTO root_refs VALUES('disk_backup',?,?,'active',1,?)",
                    params![attempt.input.backup_id, disk.generation()?, native_id],
                )?;
            }
        } else {
            for (old, replacement) in selection
                .iter()
                .filter(|old| !old.slot.read_only)
                .zip(&self.staged)
            {
                let changed = tx.execute(
                    "UPDATE volume_heads SET head_resource_id=?,backing_identity=?
                    WHERE volume_id=? AND head_resource_id=? AND backing_identity=?
                      AND NOT EXISTS(SELECT 1 FROM writer_reservations WHERE volume_id=?)",
                    params![
                        replacement.spec.resource_id,
                        replacement.backing_identity,
                        old.slot.volume_id,
                        old.top,
                        old.backing_identity,
                        old.slot.volume_id
                    ],
                )?;
                if changed != 1 {
                    return Err(fenced(
                        "one of the original disk writers changed before the whole-set replacement",
                    ));
                }
                if let Some(revision) = old.product_revision {
                    let next: i64 = tx.query_row(
                        "SELECT revision FROM product_volumes WHERE volume_id=?",
                        [&old.slot.volume_id],
                        |r| r.get(0),
                    )?;
                    if revision.checked_add(1) != Some(next) {
                        return Err(bad_catalog(
                            "changing a product writer did not advance the volume revision",
                        ));
                    }
                }
            }
        }
        settle(&tx, attempt, &receipt, false)?;
        tx.commit()?;
        Ok(receipt)
    }
}

fn verify_product_scope(
    tx: &Transaction<'_>,
    route: &str,
    bundle: &str,
    instance: &str,
    selected: &Selection,
) -> Result<()> {
    let slot = &selected.slot;
    if let (Some(product), Some(revision)) = (&slot.product, selected.product_revision) {
        let matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM product_volume_attachments a JOIN product_volumes v USING(volume_id)
            WHERE a.volume_id=? AND a.attachment_id=? AND a.instance_id=? AND a.device_key=? AND a.revision=?
              AND a.mode=? AND a.generation_id IS ? AND a.state='reserved' AND a.capture_policy='include'
              AND v.owner_id=? AND v.revision=? AND v.route_id=? AND v.bundle_digest=? AND v.state='available'
              AND NOT EXISTS(SELECT 1 FROM product_volume_operations p WHERE p.volume_id=v.volume_id AND p.result_json IS NULL))",
            params![slot.volume_id, slot.attachment_id, instance, slot.device_id, product.attachment_revision,
                if slot.read_only { "ro" } else { "rw" }, product.generation_id, product.owner_id, revision, route, bundle],
            |r| r.get(0))?;
        if !matches {
            return Err(fenced(
                "product volume ownership or attachment changed during disk backup",
            ));
        }
    }
    Ok(())
}

fn settle(
    tx: &Transaction<'_>,
    attempt: &Attempt<'_>,
    receipt: &Value,
    failed: bool,
) -> Result<()> {
    let op = attempt.native.operation()?.0;
    let updated = tx.execute("UPDATE operations SET phase=?,decision=?,revision=revision+1 WHERE operation_id=? AND phase='NEW'",
        params![if failed { "ABORTED" } else { "COMPLETED" }, if failed { "ABORT" } else { "NONE" }, op])?;
    if updated != 1 {
        return Err(bad_catalog("disk backup catalog decision already settled"));
    }
    tx.execute(
        "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
        [op],
    )?;
    tx.execute("UPDATE disk_backup_attempts SET receipt_json=? WHERE attempt_id=? AND receipt_json IS NULL",
        params![receipt.to_string(), attempt.input.attempt_id])?;
    Ok(())
}

fn finish_pending(
    catalog: &mut Catalog,
    objects: &File,
    attempt: &Attempt<'_>,
    result: Result<Value>,
) -> Result<Value> {
    let error = match result {
        Ok(value) => return Ok(value),
        Err(error) if error.code == "E_CATALOG" => return Err(error),
        Err(error) => error,
    };
    let op = attempt.native.operation()?.0;
    let staged: Vec<String> = {
        let mut query = catalog.db.prepare("SELECT spec_json FROM managed_blocks WHERE operation_id=? AND backing_identity IS NULL")?;
        let rows = query.query_map([op], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for raw in staged {
        blocks::discard_staged(objects, op, &decode(&raw)?)?;
    }
    let receipt = attempt.failure(error);
    let tx = catalog.db.transaction()?;
    tx.execute(
        "DELETE FROM managed_blocks WHERE operation_id=? AND backing_identity IS NULL",
        [op],
    )?;
    settle(&tx, attempt, &receipt, true)?;
    tx.commit()?;
    Ok(receipt)
}
