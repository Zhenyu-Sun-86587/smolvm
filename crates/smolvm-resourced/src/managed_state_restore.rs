//! Launch an isolated VMM from a committed StatePoint and its exact disk closure.

use crate::catalog::{Catalog, Operation, VolumeHead};
use crate::ipc::{valid_id, Expected, Fault, Request, Result, PROTOCOL};
use crate::managed::{self, key, Device, Disk, Restore};
use crate::statepoint_capture::Purpose;
use crate::statepoint_catalog::Record;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMode {
    Exact,
    #[default]
    CloneConflicts,
}

impl RestoreMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::CloneConflicts => "clone_conflicts",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Durable {
    pub representation_id: String,
    pub mode: RestoreMode,
    pub lease_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub name: String,
    pub capture_id: String,
    #[serde(default)]
    pub mode: RestoreMode,
}

fn invalid(error: impl ToString) -> Fault {
    Fault::invalid(error.to_string())
}

fn unavailable(message: &str) -> Fault {
    Fault::new("E_RESOURCE_UNAVAILABLE", message)
}

pub(crate) fn source(
    catalog: &Catalog,
    route: &str,
    bundle: &str,
    capture: &str,
) -> Result<(Record, Operation)> {
    let record = catalog.require_statepoint(capture)?;
    let operation = catalog.operation(&record.operation_id)?;
    if operation.route_id != route || operation.bundle_digest != bundle {
        return Err(Fault::new(
            "E_BUNDLE_UNAVAILABLE",
            "restore requires the original StatePoint reader",
        ));
    }
    if !matches!(
        (record.export.purpose, record.phase.as_str()),
        (Purpose::Checkpoint, "durable")
            | (Purpose::Hibernate | Purpose::RollbackRescue, "hibernated")
    ) {
        return Err(unavailable(
            "StatePoint has no available durable restore root",
        ));
    }
    let resource = catalog.resource(&record.point.representation_id)?;
    if record.manifest_digest.is_none()
        || resource["state"] != "available"
        || resource["durability"] != "durable"
        || resource["immutable"] != true
    {
        return Err(unavailable("StatePoint representation is unavailable"));
    }
    Ok((record, operation))
}

pub(crate) fn exact_heads(
    catalog: &Catalog,
    record: &Record,
    source: &Operation,
    target_instance: &str,
    current_operation: Option<&str>,
) -> Result<Vec<VolumeHead>> {
    if !record
        .point
        .devices
        .iter()
        .filter_map(|device| device.block())
        .any(|disk| disk.writable_head_id.is_some())
    {
        return Ok(Vec::new());
    }
    if !matches!(
        record.export.purpose,
        Purpose::Hibernate | Purpose::RollbackRescue
    ) || source.instance_id != target_instance
    {
        return Err(crate::pivots::generation_mismatch());
    }
    crate::pivots::exact_successors(catalog, &source.operation_id, current_operation)
}

pub(crate) fn submit(catalog: &mut Catalog, request: &Request, input: Input) -> Result<Operation> {
    queue(catalog, request, input, None, None)
}

pub(crate) fn queue_rollback(
    catalog: &mut Catalog,
    parent: &Operation,
    name: &str,
    restore_capture_id: &str,
    rescue_capture_id: &str,
    mode: RestoreMode,
) -> Result<Operation> {
    let rescue = catalog.require_statepoint(rescue_capture_id)?;
    if rescue.export.purpose != Purpose::RollbackRescue
        || rescue.operation_id != parent.operation_id
        || rescue.phase != "hibernated"
        || rescue.restore_capture_id.as_deref() != Some(restore_capture_id)
        || catalog.execution(&rescue.point.incarnation_id)?.phase != "exited"
    {
        return Err(Fault::new(
            "E_FENCE_UNPROVEN",
            "rollback target requires its durable stopped rescue",
        ));
    }
    let request = Request {
        protocol: PROTOCOL.into(),
        request_id: "queue-rollback".into(),
        method: "SubmitManagedStateRestore".into(),
        route_id: Some(parent.route_id.clone()),
        bundle_digest: Some(parent.bundle_digest.clone()),
        operation_id: Some(key(&parent.operation_id, "restore", 0)),
        request_digest: Some(format!(
            "sha256:{:x}",
            Sha256::digest(format!(
                "{}\0{}\0{}\0{}",
                parent.request_digest,
                restore_capture_id,
                rescue_capture_id,
                mode.as_str(),
            ))
        )),
        expected: Some(Expected {
            instance_id: parent.instance_id.clone(),
            incarnation_id: None,
            execution_epoch: rescue.point.execution_epoch,
        }),
        payload: json!({}),
        fd_table: Vec::new(),
    };
    queue(
        catalog,
        &request,
        Input {
            name: name.into(),
            capture_id: restore_capture_id.into(),
            mode,
        },
        Some(rescue_capture_id),
        Some(&parent.operation_id),
    )
}

fn queue(
    catalog: &mut Catalog,
    request: &Request,
    input: Input,
    rescue_capture_id: Option<&str>,
    predecessor: Option<&str>,
) -> Result<Operation> {
    let (id, _) = request.operation()?;
    let (route, bundle, expected) = request.scope()?;
    if route != "deep"
        || expected.incarnation_id.is_some()
        || expected.execution_epoch == i64::MAX
        || !valid_id(&input.name)
        || input.name.len() > 63
    {
        return Err(invalid(
            "restore needs a stopped target slot and its exact epoch",
        ));
    }
    let namespace = managed::serve_id(&expected.instance_id, &input.name)?;
    if let Some((capture, mode, rescue)) = catalog.db.query_row(
        "SELECT capture_id,mode,rescue_capture_id FROM managed_state_restores WHERE operation_id=?",
        [id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?)),
    ).optional()? {
        if capture != input.capture_id || mode != input.mode.as_str() || rescue.as_deref() != rescue_capture_id {
            return Err(Fault::new("E_IDEMPOTENCY_CONFLICT", "durable restore parameters changed"));
        }
        return catalog.begin(request, "restore_target");
    }
    let (point, original) = source(catalog, route, bundle, &input.capture_id)?;
    let imported = crate::backup_import::imported(catalog,&input.capture_id)?;
    if !imported && !original.instance_id.starts_with(&format!("i-{namespace}-")) {
        return Err(Fault::new(
            "E_PERMISSION_DENIED",
            "StatePoint belongs to a different Serve",
        ));
    }
    let same_machine = original.instance_id == expected.instance_id;
    let archived_target = imported && !same_machine && expected.execution_epoch==0 && rescue_capture_id.is_none() && input.mode==RestoreMode::CloneConflicts;
    if (imported && !archived_target) || (!imported && ((point.export.purpose == Purpose::Checkpoint && same_machine) != rescue_capture_id.is_some()
        || (point.export.purpose != Purpose::Checkpoint && !same_machine)
        || (!same_machine && expected.execution_epoch != 0)))
    {
        return Err(Fault::new(
            "E_FENCE_UNPROVEN",
            "capture cannot restore to this target slot",
        ));
    }
    let execution = catalog.execution(&point.point.incarnation_id)?;
    let start = catalog.operation(&execution.last_operation_id)?;
    let source_plan = managed::plan(catalog, &start)?
        .ok_or_else(|| unavailable("StatePoint has no managed launch provenance"))?;
    if start.phase != "COMPLETED" {
        return Err(unavailable("StatePoint source launch was not completed"));
    }
    let exact: BTreeMap<_, _> = if input.mode == RestoreMode::Exact {
        exact_heads(catalog, &point, &original, &expected.instance_id, None)?
            .into_iter()
            .map(|head| (head.volume_id, head.head_resource_id))
            .collect()
    } else {
        BTreeMap::new()
    };
    let mut machine = source_plan.machine;
    machine.name = input.name;
    let mut devices = Vec::with_capacity(machine.disks.len());
    let mut volume_map = BTreeMap::new();
    let mut roots = HashSet::from([point.point.representation_id.clone()]);
    let mut layers = HashSet::new();
    let mut storage_bytes = 0u64;
    let captured: Vec<_> = point
        .point
        .devices
        .iter()
        .filter_map(|device| device.block())
        .collect();
    if captured.len() != machine.disks.len() || captured.is_empty() {
        return Err(unavailable(
            "captured disks differ from the measured source topology",
        ));
    }
    for (index, (disk, captured)) in machine.disks.iter_mut().zip(captured).enumerate() {
        let read_only = captured.writable_head_id.is_none();
        if disk.attachment_id != captured.attachment_id
            || disk.device_id != captured.device_id
            || disk.role != captured.role
            || disk.read_only != read_only
        {
            return Err(unavailable(
                "capture disk identity differs from its launch provenance",
            ));
        }
        let generation = captured
            .writable_head_id
            .as_ref()
            .unwrap_or(&captured.generation_id);
        if !point.point.disk_generations.contains(generation) {
            return Err(unavailable("capture has an unpinned disk generation"));
        }
        roots.insert(generation.clone());
        let closure = catalog.block_closure(generation)?;
        if closure[0].spec.mutable() || closure[0].spec.capacity_bytes != captured.capacity_bytes {
            return Err(unavailable(
                "pinned capture generation has incompatible capacity or access",
            ));
        }
        layers.extend(closure.into_iter().map(|layer| layer.spec.resource_id));
        let (volume, head, reattach) = if read_only {
            (captured.volume_id.clone(), None, false)
        } else {
            storage_bytes = storage_bytes
                .checked_add(captured.capacity_bytes)
                .ok_or_else(|| invalid("restored disk budget overflow"))?;
            if input.mode == RestoreMode::Exact {
                let head = exact
                    .get(&captured.volume_id)
                    .ok_or_else(crate::pivots::generation_mismatch)?;
                roots.insert(head.clone());
                (captured.volume_id.clone(), Some(head.clone()), true)
            } else {
                (
                    key(id, "volume", index),
                    Some(key(id, "head", index)),
                    false,
                )
            }
        };
        if let Some(head) = &head {
            layers.insert(head.clone());
        }
        volume_map.insert(captured.volume_id.clone(), volume.clone());
        let requested_volume = disk.volume_id.take();
        let normalized = Disk {
            generation_id: generation.clone(),
            volume_id: None,
            ..disk.clone()
        };
        *disk = normalized.clone();
        if reattach || read_only && same_machine {
            disk.volume_id = requested_volume;
            if disk.volume_id.is_some() {
                disk.generation_id.clear();
            }
        }
        devices.push(Device {
            disk: normalized,
            volume_id: volume,
            head_id: head,
            capacity_bytes: captured.capacity_bytes,
            reattach,
        });
    }
    if layers.len() > crate::ipc::MAX_FDS {
        return Err(Fault::new(
            "E_RESOURCE_LIMIT",
            "restored block descriptor limit exceeded",
        ));
    }
    let capacity = crate::admission::Capacity {
        vcpus: machine.cpus.into(),
        memory_mib: machine.memory_mib.into(),
        storage_bytes,
    };
    let incarnation = key(id, "vmm", 0);
    let machine_json = serde_json::to_string(&machine).map_err(invalid)?;
    let devices_json = serde_json::to_string(&devices).map_err(invalid)?;
    let volume_map_json = serde_json::to_string(&volume_map).map_err(invalid)?;
    catalog.begin_with_handoff(request, "restore_target", predecessor, |tx| {
        crate::admission::reserve(tx, id, &expected.instance_id, capacity)?;
        tx.execute("INSERT INTO managed_launches(operation_id,incarnation_id,serve_instance,machine_name,spec_json,devices_json,vcpus,memory_mib)
            VALUES(?,?,?,?,?,?,?,?)", params![id,incarnation,namespace,machine.name,machine_json,devices_json,machine.cpus,machine.memory_mib])?;
        tx.execute("INSERT INTO managed_state_restores(operation_id,capture_id,rescue_capture_id,mode,volume_map_json)
            VALUES(?,?,?,?,?)", params![id,input.capture_id,rescue_capture_id,input.mode.as_str(),volume_map_json])?;
        for resource in &roots {
            tx.execute("INSERT OR IGNORE INTO root_refs(owner_kind,owner_id,resource_id,state,revision,created_by_operation)
                VALUES('operation',?,?,'active',1,?)", params![id,resource,id])?;
        }
        Ok(())
    })
}

pub(crate) fn plan(catalog: &Catalog, operation: &Operation) -> Result<Option<Restore>> {
    let restore: Option<(String, String)> = catalog
        .db
        .query_row(
            "SELECT capture_id,mode FROM managed_state_restores WHERE operation_id=?",
            [&operation.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((capture_id, mode)) = restore else {
        return Ok(None);
    };
    let record = catalog.require_statepoint(&capture_id)?;
    let mode = match mode.as_str() {
        "exact" => RestoreMode::Exact,
        "clone_conflicts" => RestoreMode::CloneConflicts,
        _ => return Err(invalid("stored restore policy is unknown")),
    };
    Ok(Some(Restore {
        batch_id: record.operation_id,
        capture_id,
        anchor: record.point.capture_anchor,
        helper_digest: record.point.helper_digest,
        source_pivot: record
            .point
            .devices
            .iter()
            .filter_map(|device| device.block())
            .any(|disk| disk.writable_head_id.is_some()),
        durable: Some(Durable {
            representation_id: record.point.representation_id,
            mode,
            lease_id: key(&operation.operation_id, "statepoint-lease", 0),
        }),
    }))
}

pub(crate) fn receipt(catalog: &Catalog, op: &Operation) -> Result<Option<Value>> {
    let Some((capture, rescue, volumes, code, error, representation, manifest)) = catalog.db.query_row(
        "SELECT r.capture_id,r.rescue_capture_id,r.volume_map_json,r.error_code,r.error_message,p.representation_id,p.manifest_digest
         FROM managed_state_restores r JOIN statepoints p USING(capture_id) WHERE r.operation_id=?",
        [&op.operation_id],
        |row| Ok((row.get::<_, String>(0)?,row.get::<_, Option<String>>(1)?,row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,row.get::<_, Option<String>>(4)?,row.get::<_, String>(5)?,row.get::<_, String>(6)?)),
    ).optional()? else { return Ok(None) };
    let volume_map: Value = serde_json::from_str(&volumes).map_err(invalid)?;
    let authorization: Option<(String, String)> = catalog
        .db
        .query_row(
            "SELECT phase,decision FROM target_activations WHERE operation_id=?",
            [&op.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let stage = match op.phase.as_str() {
        "ABORTED" => "aborted",
        "COMPLETED" => "released",
        _ => authorization
            .as_ref()
            .map_or("preparing", |(phase, _)| phase),
    };
    Ok(Some(
        json!({"stage":stage,"capture_id":capture,"rescue_capture_id":rescue,"representation_id":representation,
        "manifest_digest":manifest,"target_operation_id":op.operation_id,"volume_map":volume_map,"error_code":code,"error":error,
        "activation_decision":authorization.as_ref().map(|(_, decision)| decision)}),
    ))
}

pub(crate) fn activation_input(
    catalog: &Catalog,
    op: &Operation,
    restore: &Restore,
) -> Result<Value> {
    let durable = restore
        .durable
        .as_ref()
        .ok_or_else(|| invalid("missing durable restore"))?;
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(format!(
            "{}:durable:{}",
            op.bundle_digest, restore.helper_digest
        ))
    );
    let mut input = json!({"capture_resource_id":durable.representation_id,"capture_anchor":restore.anchor,
        "profile_digest":digest,"helper_digest":restore.helper_digest});
    if catalog
        .require_statepoint(&restore.capture_id)?
        .point
        .devices
        .iter()
        .any(|device| device.is_network())
    {
        if let Some(network) = crate::activation_catalog::captured_network_input(
            catalog,
            &durable.representation_id,
            op,
        )? {
            input["network"] = network;
        }
    }
    Ok(input)
}

pub(crate) fn fail(catalog: &Catalog, id: &str, fault: &Fault) -> Result<()> {
    catalog.db.execute(
        "UPDATE managed_state_restores SET error_code=?,error_message=? WHERE operation_id=? AND error_code IS NULL",
        params![fault.code, fault.message, id],
    )?;
    Ok(())
}

pub(crate) fn identity_frame(
    catalog: &Catalog,
    op: &Operation,
    record: &crate::activation_catalog::ActivationReceipt,
) -> Result<String> {
    let (name, old): (String, Option<String>) = catalog.db.query_row(
        "SELECT m.machine_name,r.frame_hex FROM managed_state_restores r JOIN managed_launches m USING(operation_id)
         WHERE r.operation_id=?",
        [&op.operation_id], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if let Some(frame) = old {
        return Ok(frame);
    }
    let frame = crate::managed_fork::build_identity_frame(op, &name, record)?;
    catalog.db.execute(
        "UPDATE managed_state_restores SET frame_hex=? WHERE operation_id=? AND frame_hex IS NULL",
        params![frame, op.operation_id],
    )?;
    Ok(frame)
}
