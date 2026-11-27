//! Restore immutable backup resources into a fresh, isolated Worker catalog.

use crate::activation_catalog::{self, BoundTap};
use crate::backup_closure::{Capture, Manifest};
use crate::blocks::{self, BlockObject};
use crate::catalog::{Catalog, Operation};
use crate::ipc::{Fault, Result, valid_digest, valid_id};
use crate::managed::{self, Device, Machine, NetworkMode};
use crate::statepoint_capture::{Export, Purpose};
use crate::statepoint_catalog::Record;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, Permissions};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Origin {
    purpose: Purpose,
    instance_id: String,
    capture_request_digest: String,
    launch_id: String,
    launch_request_digest: String,
    hold_token_digest: String,
    machine: Machine,
    devices: Vec<Device>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    captured_tap: Option<BoundTap>,
}

fn invalid(error: impl ToString) -> Fault {
    Fault::new("E_BACKUP_CLOSURE_INVALID", error.to_string())
}

pub(crate) fn describe(
    catalog: &Catalog,
    record: &Record,
    operation: &Operation,
) -> Result<Origin> {
    let execution = catalog.execution(&record.point.incarnation_id)?;
    let start = catalog.operation(&execution.last_operation_id)?;
    let plan = managed::plan(catalog, &start)?
        .ok_or_else(|| invalid("captured StatePoint has no measured launch provenance"))?;
    if execution.incarnation_id != record.point.incarnation_id
        || execution.execution_epoch != record.point.execution_epoch
        || start.phase != "COMPLETED"
        || execution.instance_id != operation.instance_id
        || start.instance_id != operation.instance_id
        || execution.bundle_digest != operation.bundle_digest
        || start.bundle_digest != operation.bundle_digest
        || plan.launch.execution.incarnation_id.as_deref()
            != Some(execution.incarnation_id.as_str())
        || plan.launch.execution.execution_epoch != execution.execution_epoch
    {
        return Err(invalid(
            "StatePoint execution differs from its measured launch provenance",
        ));
    }
    let captured_tap =
        activation_catalog::archive_bound_tap(catalog, record, plan.machine.network.is_some())?;
    check_network(&record.point, &plan.machine, captured_tap.as_ref())?;
    Ok(Origin {
        purpose: record.export.purpose,
        instance_id: execution.instance_id,
        capture_request_digest: operation.request_digest.clone(),
        launch_id: start.operation_id,
        launch_request_digest: start.request_digest,
        hold_token_digest: format!(
            "sha256:{:x}",
            Sha256::digest(record.export.hold_token.as_bytes())
        ),
        machine: plan.machine,
        devices: plan.devices,
        captured_tap,
    })
}

fn check_network(
    point: &crate::statepoint_store::Point,
    machine: &Machine,
    tap: Option<&BoundTap>,
) -> Result<()> {
    let device_count = point
        .devices
        .iter()
        .filter(|device| device.is_network())
        .count();
    match (device_count, &machine.network, tap) {
        (0, None, None) => Ok(()),
        (1, Some(network), Some(tap)) => {
            let a = &tap.attachment;
            let expected = match network.mode {
                NetworkMode::Native => {
                    a.mode == "native" && a.guest_ipv4 == a.private_ipv4 && a.guest_prefix == 32
                }
                NetworkMode::FixedInternal => {
                    a.mode == "fixed_internal"
                        && network.fixed_route()
                            == Some((a.guest_ipv4, a.gateway_ipv4, a.guest_prefix))
                }
            };
            if !expected
                || a.schema != "NetworkAttachment/1"
                || a.route_domain_id != network.route_domain_id
                || !valid_id(&a.attachment_id)
                || !valid_id(&tap.lease_id)
                || !valid_id(&a.device_id)
                || tap.lease_revision < 1
                || !valid_digest(&format!("sha256:{}", tap.attachment_digest))
                || !crate::network_catalog::archived_address_is_valid(
                    &network.cidr,
                    a.private_ipv4,
                )?
            {
                return Err(crate::network_catalog::network_recovery_fault(
                    "archived TAP differs from its measured launch profile",
                ));
            }
            Ok(())
        }
        _ => Err(crate::network_catalog::network_recovery_fault(
            "backup lacks its original network capture attestation",
        )),
    }
}

fn serial(value: impl Serialize) -> Result<String> {
    serde_json::to_string(&value).map_err(invalid)
}

fn descriptor(
    tx: &Transaction<'_>,
    id: &str,
    op: &str,
    state: &str,
    durability: &str,
    value: Value,
) -> Result<()> {
    let raw = serial(value)?;
    let digest = format!("sha256:{:x}", Sha256::digest(raw.as_bytes()));
    tx.execute(
        "INSERT INTO resources VALUES(?,'descriptor',?,?,1,?,?,?,1)",
        params![id, state, durability, raw, digest, op],
    )?;
    Ok(())
}

/// Archival origin rows are historical and cannot authorize any live VMM.
/// Only a separately created new target may claim the imported StatePoint.
fn capture(tx: &Transaction<'_>, manifest: &Manifest, item: &Capture) -> Result<()> {
    let point = &item.point;
    let origin = item
        .origin
        .as_ref()
        .ok_or_else(|| invalid("backup lacks original managed launch provenance"))?;
    check_network(point, &origin.machine, origin.captured_tap.as_ref())?;
    let serve = managed::serve_id(&origin.instance_id, &origin.machine.name)?;
    if point.execution_epoch < 1
        || !valid_id(&point.incarnation_id)
        || !valid_id(&item.commit_id)
        || !valid_id(&origin.launch_id)
        || item.commit_id == origin.launch_id
        || !valid_digest(&origin.capture_request_digest)
        || !valid_digest(&origin.launch_request_digest)
        || !valid_digest(&origin.hold_token_digest)
        || origin.machine.cpus == 0
        || origin.machine.memory_mib < 64
        || origin.machine.disks.len() != origin.devices.len()
    {
        return Err(invalid("invalid archived launch provenance"));
    }
    let kind = match origin.purpose {
        Purpose::Checkpoint => "vm_snapshot",
        Purpose::Hibernate => "hibernate",
        Purpose::RollbackRescue => "vm_rollback",
    };
    tx.execute(
        "INSERT INTO operations VALUES(?,? ,?,'deep',?,?,?,?, 'COMPLETED','NONE',1)",
        params![
            item.commit_id,
            kind,
            origin.capture_request_digest,
            origin.instance_id,
            manifest.bundle_digest,
            point.execution_epoch,
            point.incarnation_id
        ],
    )?;
    tx.execute("INSERT INTO operations VALUES(?,'launch',?,'deep',?,?,?,NULL,'COMPLETED','NONE',1) ON CONFLICT(operation_id) DO NOTHING",
        params![origin.launch_id,origin.launch_request_digest,origin.instance_id,manifest.bundle_digest,point.execution_epoch-1])?;
    let spec = serial(&origin.machine)?;
    let devices = serial(&origin.devices)?;
    tx.execute("INSERT INTO managed_launches(operation_id,incarnation_id,serve_instance,machine_name,spec_json,devices_json,vcpus,memory_mib)
        VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(operation_id) DO NOTHING", params![origin.launch_id,point.incarnation_id,serve,origin.machine.name,
        spec,devices,origin.machine.cpus,origin.machine.memory_mib])?;
    let launch_matches: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_launches m JOIN operations o USING(operation_id)
        WHERE m.operation_id=? AND m.incarnation_id=? AND m.spec_json=? AND m.devices_json=? AND o.kind='launch' AND o.route_id='deep'
        AND o.bundle_digest=? AND o.instance_id=? AND o.request_digest=? AND o.expected_execution_epoch=?)",params![origin.launch_id,point.incarnation_id,
        spec,devices,manifest.bundle_digest,origin.instance_id,origin.launch_request_digest,point.execution_epoch-1],|row|row.get(0))?;
    if !launch_matches {
        return Err(invalid("archived StatePoints disagree on source launch"));
    }
    tx.execute("INSERT INTO executions(incarnation_id,route_id,instance_id,execution_epoch,bundle_digest,host_boot_id,pid,pid_start_time,uid,phase,last_operation_id)
        VALUES(?,'deep',?,?,?,?,1,1,0,'exited',?) ON CONFLICT(incarnation_id) DO NOTHING",
        params![point.incarnation_id,origin.instance_id,point.execution_epoch,manifest.bundle_digest,format!("archived:{}",manifest.backup_id),origin.launch_id])?;
    let volatile = managed::key(&item.commit_id, "archived-volatile", 0);
    descriptor(
        tx,
        &volatile,
        &item.commit_id,
        "lost",
        "volatile",
        json!({"schema":"ImportedStatePointOrigin/1","capture_id":point.capture_id}),
    )?;
    descriptor(
        tx,
        &point.representation_id,
        &item.commit_id,
        "available",
        "durable",
        json!({"schema":"CaptureManifest/1","capture_id":point.capture_id,
        "required_bundle":manifest.bundle_digest,"manifest_digest":item.manifest_digest,"commit_id":item.commit_id}),
    )?;
    let export = Export {
        capture_id: point.capture_id.clone(),
        representation_id: point.representation_id.clone(),
        purpose: origin.purpose,
        session: 1,
        hold_token: String::new(),
    };
    let phase = if origin.purpose == Purpose::Checkpoint {
        "durable"
    } else {
        "hibernated"
    };
    tx.execute(
        "INSERT INTO statepoints VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,1)",
        params![
            point.capture_id,
            point.representation_id,
            volatile,
            item.commit_id,
            point.incarnation_id,
            serial(export)?,
            serial(point)?,
            phase,
            item.manifest_digest
        ],
    )?;
    for id in &point.disk_generations {
        tx.execute(
            "INSERT INTO resource_edges VALUES(?,?,'block_generation')",
            params![point.representation_id, id],
        )?;
    }
    tx.execute(
        "INSERT INTO root_refs VALUES('backup_import',?,?,'active',1,?)",
        params![manifest.backup_id, point.representation_id, item.commit_id],
    )?;
    tx.execute(
        "INSERT INTO native_backup_imports VALUES(?,?,?,?)",
        params![
            point.capture_id,
            manifest.backup_id,
            manifest.state_reader_id,
            origin.hold_token_digest
        ],
    )?;
    activation_catalog::import_bound_tap(
        tx,
        &point.representation_id,
        origin.captured_tap.as_ref(),
    )?;
    Ok(())
}

pub(crate) fn imported(c: &Catalog, capture: &str) -> Result<bool> {
    Ok(c.db
        .query_row(
            "SELECT 1 FROM native_backup_imports WHERE capture_id=?",
            [capture],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some())
}

/// The output is still staging at this point. No old catalog or path is opened.
pub(crate) fn catalog(
    stage: &Path,
    manifest: &Manifest,
    bundle_manifest: &Path,
    executable: &str,
) -> Result<()> {
    let mut raw = Vec::new();
    File::open(bundle_manifest)
        .map_err(invalid)?
        .take((16 << 20) + 1)
        .read_to_end(&mut raw)
        .map_err(invalid)?;
    if raw.len() > 16 << 20 {
        return Err(invalid(
            "runtime bundle manifest exceeds its supported size",
        ));
    }
    let metadata = serde_json::from_slice(&raw).map_err(invalid)?;
    let handshake = smolvm_runtime_protocol::handshake(metadata, executable).map_err(invalid)?;
    if handshake.bundle_digest != manifest.bundle_digest
        || handshake.state_reader_id != manifest.state_reader_id
    {
        return Err(Fault::new(
            "E_BUNDLE_UNAVAILABLE",
            "import requires the exact original bundle and state reader",
        ));
    }
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(invalid)?;
    let stage_catalog = stage.join("catalog.sqlite");
    let mut catalog = Catalog::open(&stage_catalog, boot.trim(), "import")?;
    catalog.register_bundle(&manifest.bundle_digest, &format!("sha256:{executable}"))?;
    let volumes = stage.join("objects");
    fs::rename(stage.join("blocks"), &volumes).map_err(invalid)?;
    fs::set_permissions(&volumes, Permissions::from_mode(0o700)).map_err(invalid)?;
    let points = stage.join("statepoints");
    if points.exists() {
        fs::set_permissions(&points, Permissions::from_mode(0o700)).map_err(invalid)?;
    }
    let op = managed::key(&manifest.backup_id, "catalog-import", 0);
    let digest = format!("sha256:{:x}", Sha256::digest(manifest.backup_id.as_bytes()));
    let tx = catalog
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "INSERT INTO operations VALUES(?,'backup_import',?,'deep',?,?,0,NULL,'COMPLETED','NONE',1)",
        params![op, digest, manifest.backup_id, manifest.bundle_digest],
    )?;
    let mut ready = BTreeSet::new();
    while ready.len() < manifest.blocks.len() {
        let mut progress = false;
        for (id, spec) in &manifest.blocks {
            if ready.contains(id)
                || spec
                    .backing_id
                    .as_ref()
                    .is_some_and(|parent| !ready.contains(parent))
            {
                continue;
            }
            let dir = volumes.join(id);
            fs::set_permissions(&dir, Permissions::from_mode(0o700)).map_err(invalid)?;
            let file = File::open(dir.join("data")).map_err(invalid)?;
            let object = BlockObject {
                spec: spec.clone(),
                format: if spec.backing_id.is_some() {
                    "qcow2".into()
                } else {
                    "raw".into()
                },
                backing_identity: crate::backing_identity::recorded(&file).map_err(invalid)?,
                verified_identity: None,
            };
            tx.execute(
                "INSERT INTO managed_blocks VALUES(?,?,?,NULL)",
                params![id, op, serial(spec)?],
            )?;
            blocks::publish_block_record(&tx, &op, &object)?;
            ready.insert(id.clone());
            progress = true;
        }
        if !progress {
            return Err(invalid("imported block ancestry cannot be installed"));
        }
    }
    for id in &manifest.generations {
        tx.execute(
            "INSERT INTO root_refs VALUES('backup_import',?,?,'active',1,?)",
            params![manifest.backup_id, id, op],
        )?;
    }
    for item in &manifest.captures {
        capture(&tx, manifest, item)?;
    }
    tx.commit()?;
    catalog
        .db
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")?;
    drop(catalog);
    fs::set_permissions(&stage_catalog, Permissions::from_mode(0o600)).map_err(invalid)?;
    File::open(stage_catalog)
        .and_then(|file| file.sync_all())
        .map_err(invalid)?;
    Ok(())
}
