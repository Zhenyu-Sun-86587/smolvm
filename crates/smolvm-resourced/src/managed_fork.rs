//! One held source cut per admitted batch, independent of the HTTP connection.
use crate::admission::{self, Capacity};
use crate::catalog::{Catalog, Execution, Operation};
use crate::escrow::Escrow;
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::managed::{key, machine_id, Machine, Restore};
use crate::native_control::{Endpoint, Inventory};
use crate::statepoint_capture::{self, Export, Purpose};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use smolvm_runtime_protocol::kernel_cow::PROFILE;
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    sync::mpsc,
    thread,
    time::Instant,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    #[serde(default)]
    pub children: Vec<String>,
    pub capture_id: Option<String>,
    pub mode: Option<String>,
    pub admission: Option<String>,
    pub memory_fork_backend: Option<MemoryForkBackend>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MemoryForkBackend {
    #[default]
    Native,
    KernelCow,
    Auto,
}

impl MemoryForkBackend {
    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::KernelCow => "kernel_cow",
            Self::Auto => "auto",
        }
    }

    fn select(self, fork: bool, native: bool, kernel: bool) -> Result<&'static str> {
        match self {
            _ if !fork && kernel => Ok("kernel_cow"),
            Self::Auto | Self::KernelCow if kernel => Ok("kernel_cow"),
            Self::Auto | Self::Native if native => Ok("native"),
            Self::KernelCow => Err(unsupported("this execution cannot fork with Kernel CoW")),
            _ => Err(unsupported("this execution has no compatible RAM capture backend")),
        }
    }
}

fn unsupported(reason: &str) -> Fault {
    Fault::new("E_CAPABILITY_UNSUPPORTED", reason)
}

fn parkable(inv: &Inventory) -> bool {
    inv.measured_helper
        && inv.standby_blocker.is_none()
        && !inv.devices.iter().any(|dev| dev["virtio_type"] == 19 && dev["parked_vsock_rebind"] != true)
}

fn memory_fork_backends(inv: &Inventory, machine: Option<&Machine>, bundle: &str) -> (bool, bool, &'static str) {
    let Some(machine) = machine.filter(|machine| !machine.live_compute_growth) else {
        return (false, false, "source_managed_profile_unverified");
    };
    if !parkable(inv) {
        return (false, false, "source_capture_ineligible");
    }
    match (inv.memory_fork_profile.as_deref(), machine.kernel_cow()) {
        (None, false) => (true, false, "source_native_ram_profile"),
        (Some(PROFILE), true) =>
            if crate::managed_kernel_cow::worker_available(bundle) {
                (false, true, "")
            } else {
                (false, false, crate::managed_kernel_cow::UNAVAILABLE)
            },
        _ => (false, false, "source_memory_profile_unverified"),
    }
}

pub(crate) fn memory_fork_inventory(c: &Catalog, execution: &Execution, inv: &Inventory) -> Result<Value> {
    let launch = c.operation(&execution.last_operation_id)?;
    let plan = crate::managed::plan(c, &launch)?;
    let machine = plan.as_ref().filter(|_| launch.phase == "COMPLETED").map(|plan| &plan.machine);
    let (native, kernel, reason) = memory_fork_backends(inv, machine, &execution.bundle_digest);
    let mut observed = json!({
        "profile": inv.memory_fork_profile.as_deref().unwrap_or("native"),
        "native_supported": native,
        "kernel_cow_supported": kernel,
    });
    if !reason.is_empty() {
        observed["unavailable_reason"] = json!(reason);
    }
    if kernel {
        observed["kernel_cow_abi_digest"] = json!(crate::managed_kernel_cow::ABI_DIGEST);
    }
    Ok(observed)
}
fn conflict(reason: impl ToString) -> Fault {
    Fault::new("E_STATE_CONFLICT", reason.to_string())
}
fn invalid(e: impl ToString) -> Fault {
    Fault::invalid(e.to_string())
}
fn nonce() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|e| Fault::new("E_HOST_IO", e.to_string()))?;
    Ok(hex::encode(bytes))
}
fn standby_scope(c: &Catalog, incarnation: &str) -> Result<(u32, String, String)> {
    c.db.query_row(
        "SELECT n.session,n.token,n.anchor FROM native_standby s
         JOIN native_transitions n USING(operation_id) WHERE s.incarnation_id=? AND n.mode='managed'",
         [incarnation], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?.ok_or_else(|| conflict("source requires managed standby"))
}

fn active_credential_relay_hold(
    db: &Connection,
    source: &Execution,
) -> Result<Option<String>> {
    if source.phase != "registered" {
        return Ok(None);
    }
    Ok(db.query_row(
        "SELECT id FROM lifecycle_protections WHERE instance_id=?1 AND incarnation_id=?2 AND epoch=?3
         AND kind='hold' AND state='active' AND reason='credential_proxy'
         AND id GLOB 'access-*' ORDER BY id LIMIT 1",
        params![source.instance_id, source.incarnation_id, source.execution_epoch],
        |row| row.get(0),
    ).optional()?)
}

fn credential_relay_fork_eligible(kind: &str, inventory: &Inventory) -> bool {
    matches!(kind, "independent_fork" | "fork_batch")
        && inventory.source_disposition == "RUNNING"
        && inventory.credential_relay_fork == Some(true)
}

pub(crate) fn source_is_pivoting(
    db: &Connection,
    route: &str,
    instance: &str,
    incarnation: &str,
) -> Result<bool> {
    // A held VMM waits on this Worker during the pivot. Callers can observe
    // the hold without waiting for that VMM's native control socket.
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM instance_bindings b
           JOIN managed_fork_batches f ON f.operation_id=b.active_operation_id
           WHERE b.route_id=?1 AND b.instance_id=?2
             AND f.source_incarnation=?3 AND f.stage='pivoting')",
        params![route, instance, incarnation],
        |row| row.get(0),
    )?)
}

pub(crate) fn restore(c: &Catalog, child: &str) -> Result<Option<Restore>> {
    Ok(c.db.query_row("SELECT b.operation_id,b.capture_id,b.anchor,b.helper_digest,b.pivot_json IS NOT NULL FROM managed_fork_children ch JOIN managed_fork_batches b ON b.operation_id=ch.batch_id WHERE ch.operation_id=? AND b.source_released=1",[child],
        |r|Ok(Restore{batch_id:r.get(0)?,capture_id:r.get(1)?,anchor:r.get(2)?,helper_digest:r.get(3)?,source_pivot:r.get(4)?,durable:None})).optional()?)
}
pub(crate) fn receipt(c: &Catalog, id: &str) -> Result<Option<Value>> {
    let Some((stage,capture,original,released,error,admission,requested,selected,relay_hold))=c.db.query_row(
        "SELECT stage,capture_id,original,source_released,error,admission_mode,
                memory_fork_backend,selected_memory_fork_backend,credential_relay_hold
         FROM managed_fork_batches WHERE operation_id=?",[id],
        |r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,bool>(3)?,
               r.get::<_,Option<String>>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?,
               r.get::<_,Option<String>>(8)?))).optional()? else {return Ok(None)};
    let mut stmt = c.db.prepare(
        "SELECT ch.name,ch.instance_id,ch.operation_id,
             CASE WHEN (ch.cancelled=1 OR ch.capture_lost=1 OR ch.admission_error IS NOT NULL) AND o.operation_id IS NULL
                 THEN 'ABORTED' ELSE COALESCE(o.phase,'RESERVED') END,
             m.incarnation_id,ch.prior_epoch,ch.attempt,ch.cancelled,
             CASE WHEN ch.capture_lost=1 THEN 'E_CAPTURE_LOST' ELSE ch.admission_error END,
             CASE WHEN o.phase='COMPLETED' THEN EXISTS(
                SELECT 1 FROM product_volume_attachments a
                WHERE a.instance_id=ch.instance_id AND a.declared_epoch=ch.prior_epoch
             ) ELSE 0 END, activation.decision
         FROM managed_fork_children ch LEFT JOIN operations o ON o.operation_id=ch.operation_id
         LEFT JOIN managed_launches m ON m.operation_id=ch.operation_id
         LEFT JOIN target_activations activation ON activation.operation_id=o.operation_id
           AND activation.incarnation_id=m.incarnation_id AND activation.instance_id=ch.instance_id
           AND activation.execution_epoch=ch.prior_epoch+1 AND activation.bundle_digest=o.bundle_digest
         WHERE ch.batch_id=? ORDER BY ch.ordinal")?;
    let rows = stmt.query_map([id], |r| {
        let mut child = json!({
            "name":r.get::<_,String>(0)?, "instance_id":r.get::<_,String>(1)?, "operation_id":r.get::<_,String>(2)?,
            "phase":r.get::<_,String>(3)?, "incarnation_id":r.get::<_,Option<String>>(4)?,
            "execution_epoch":r.get::<_,i64>(5)?+1, "attempt":r.get::<_,i64>(6)?, "cancelled":r.get::<_,bool>(7)?,
            "admission_error":r.get::<_,Option<String>>(8)?,
            "has_product_volumes":r.get::<_,bool>(9)?
        });
        if let Some(decision) = r.get::<_, Option<String>>(10)? {
            child["activation_decision"] = json!(decision);
        }
        Ok(child)
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
    let successful = rows.iter().filter(|r|r["phase"] == "COMPLETED").count();
    let failed = rows.iter().filter(|r|r["phase"] == "ABORTED").count();
    let outcome = match (stage.as_str(), successful, failed) {
        ("aborted", _, _) => "cancelled",
        ("complete", _, 0) => "applied",
        ("complete", 0, _) => "failed",
        ("complete", _, _) => "partial",
        _ => "pending",
    };
    let profile = if selected == "kernel_cow" { PROFILE } else { "native" };
    let mut receipt = json!({"stage":stage, "capture_id":capture, "original_source_disposition":original, "admission":admission,
        "requested_memory_fork_backend":requested, "selected_memory_fork_backend":selected, "memory_fork_profile":profile,
        "source_released":released, "children":rows, "completed_count":successful,
        "failed_count":failed, "outcome":outcome, "error":error});
    if selected == "kernel_cow" {
        receipt["kernel_cow_abi_digest"] = json!(crate::managed_kernel_cow::ABI_DIGEST);
    }
    if relay_hold.is_some() {
        receipt["source_relay_retention_applied"] = json!(released && stage != "aborted");
    }
    Ok(Some(receipt))
}
pub(crate) fn submit(
    c: &mut Catalog,
    boot: &str,
    r: &Request,
    kind: &str,
    input: Input,
) -> Result<Operation> {
    let (id, _) = r.operation()?;
    let (route, bundle, expected) = r.scope()?;
    let unique: HashSet<_> = input.children.iter().collect();
    let fork = matches!(kind,"independent_fork"|"fork_batch");
    let rollback = kind == "vm_rollback";
    let requested = input.memory_fork_backend.unwrap_or_default();
    let admission = input.admission.as_deref().unwrap_or("all_or_reject");
    if !matches!(admission, "all_or_reject" | "best_effort") || input.admission.is_some() && kind != "fork_batch" {
        return Err(invalid("admission mode is supported only for fork batches"));
    }
    if fork {
        if input.children.is_empty() || input.children.len()>32
            || (kind=="independent_fork" && input.children.len()!=1)
            || unique.len()!=input.children.len() || input.children.iter().any(|n| !valid_id(n)|| n.len()>63)
            || input.capture_id.is_some() || input.mode.is_some() {
            return Err(invalid("invalid fork parameters or child set"));
        }
    } else if !matches!(kind,"vm_snapshot"|"hibernate"|"vm_rollback")
        || input.memory_fork_backend.is_some() || !input.children.is_empty() || input.capture_id.as_deref().is_some_and(|id|!valid_id(id))
        || rollback && input.capture_id.is_none() || !rollback && input.mode.is_some()
        || input.mode.as_deref().is_some_and(|m| !matches!(m,"exact"|"clone_conflicts")) {
        return Err(invalid("invalid StatePoint operation parameters"));
    }
    let names = serde_json::to_string(&input.children).map_err(invalid)?;
    let capture = if fork {key(id,"ram",0)} else if rollback {key(id,"rescue",0)}
        else {input.capture_id.clone().unwrap_or_else(||key(id,"point",0))};
    let target = if rollback {input.capture_id.as_deref()} else {None};
    let mode = if rollback {Some(input.mode.as_deref().unwrap_or("clone_conflicts"))} else {None};
    if let Some(prior) = c.db.query_row(
        "SELECT children,capture_id,restore_capture_id,volume_restore_policy,admission_mode,memory_fork_backend FROM managed_fork_batches WHERE operation_id=?",
        [id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?)) ).optional()? {
        if prior.0!=names || prior.1!=capture || prior.2.as_deref()!=target || prior.3.as_deref()!=mode || prior.4!=admission || prior.5!=requested.as_str() {
            return Err(Fault::new("E_IDEMPOTENCY_CONFLICT","capture parameters changed"));
        }
        return c.begin(r,kind);
    }
    if route!="deep" {return Err(invalid("managed capture requires the deep route"))}
    if !fork && (c.statepoint(&capture)?.is_some() || c.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_fork_batches WHERE capture_id=?)",[&capture],|r|r.get::<_,bool>(0))?) {
        return Err(conflict("capture ID is already allocated"));
    }
    if let Some(target)=target {
        let record=c.require_statepoint(target)?;
        let original=c.operation(&record.operation_id)?;
        if original.instance_id!=expected.instance_id || original.bundle_digest!=bundle || original.route_id!=route
            || record.phase!="durable" || record.export.purpose!=Purpose::Checkpoint {
            return Err(conflict("rollback requires a durable checkpoint of this instance and bundle"));
        }
    }
    let incarnation = expected
        .incarnation_id
        .as_deref()
        .ok_or_else(|| invalid("fork requires a live source"))?;
    let source = c.execution(incarnation)?;
    if !source.matches(route, bundle, expected)
        || source.phase != "registered"
        || source.host_boot_id != boot
    {
        return Err(Fault::new("E_STALE_EXECUTION", "fork source changed"));
    }
    crate::product_volumes::require_capture_policy(c, &source, fork)?;
    let start = c.operation(&source.last_operation_id)?;
    let template = crate::managed::plan(c, &start)?.ok_or_else(|| {
        Fault::new(
            "E_CAPABILITY_UNSUPPORTED",
            "source lacks managed block provenance",
        )
    })?;
    if template.machine.live_compute_growth {
        return Err(Fault::new(
            "E_CAPABILITY_UNSUPPORTED",
            "the managed StatePoint reader cannot preserve this live CPU and RAM topology",
        ));
    }
    if start.phase != "COMPLETED" {
        return Err(conflict("source launch is incomplete"));
    }
    let ep = Endpoint::load(&c.db, incarnation, boot)?;
    let inv = ep.inventory()?;
    if !inv.measured_helper
        || inv.standby_blocker.is_some()
        || !matches!(inv.source_disposition.as_str(), "RUNNING" | "STANDBY")
    {
        return Err(Fault::new(
            "E_CAPABILITY_UNSUPPORTED",
            "source inventory is ineligible for parked capture",
        ));
    }
    if inv.devices.iter().any(|dev|dev["virtio_type"]==19 && dev["parked_vsock_rebind"]!=true) {
        return Err(Fault::new("E_CAPABILITY_UNSUPPORTED","this source vsock has no verified parked rebind contract"));
    }
    let (native, kernel, _) = memory_fork_backends(&inv, Some(&template.machine), bundle);
    let selected = requested.select(fork, native, kernel)?;
    let (session, token, anchor) = if inv.source_disposition == "STANDBY" {
        let (standby_session, standby_token, anchor) = standby_scope(c, incarnation)?;
        if selected == "kernel_cow" {
            let last = inv.last_session.max(standby_session);
            (crate::native_operations::next_session(c, incarnation, last)?, nonce()?, anchor)
        } else {
            (standby_session, standby_token, anchor)
        }
    } else {
        (
            crate::native_operations::next_session(c, incarnation, inv.last_session)?,
            nonce()?,
            nonce()?,
        )
    };
    let namespace = c.db.query_row(
        "SELECT serve_instance FROM managed_launches WHERE operation_id=?",
        [&source.last_operation_id],
        |r| r.get::<_, String>(0),
    )?;
    let template_bytes = serde_json::to_string(&template.machine).map_err(invalid)?;
    let mut dest = BTreeMap::new();
    let mut grants = HashSet::new();
    for disk in &inv.devices {
        let item = &disk["block"]["managed_attachment"];
        if let Some(v) = item["writable_head_id"].as_str() {
            if !valid_id(v) {
                return Err(conflict("invalid observed writable head"));
            }
            let vol = item["volume_id"]
                .as_str()
                .ok_or_else(|| conflict("missing observed volume"))?
                .to_string();
            let g = item["grant_id"]
                .as_str()
                .ok_or_else(|| conflict("missing observed writer grant"))?;
            grants.insert(g);
            dest.insert(vol, key(id, "next", dest.len()));
        }
    }
    if grants.len() > 1 {
        return Err(conflict("incomplete writer set"));
    }
    let pivot=grants.iter().next().map(|grant|->Result<String>{
        let previous=c.writer_grant(grant)?.ok_or_else(||conflict("missing current writer grant"))?;
        if previous.incarnation_id!=incarnation || previous.execution_epoch!=source.execution_epoch || previous.state!="attached"{return Err(conflict("source writer epoch changed"))}
        Ok(json!({"operation_id":id,"request_digest":r.operation()?.1,"previous_grant_revision":previous.revision,
            "admitted_grant_id":previous.grant_id,"next_grant_id":key(id,"grant",0),"destinations":dest}).to_string())
    }).transpose()?;
    let network = inv.devices.iter().any(|dev| dev["virtio_type"] == 1);
    let initial = if rollback { "restore_preflight" } else if inv.source_disposition == "STANDBY" {
        "holding"
    } else {
        "arming"
    };
    let storage = template
        .devices
        .iter()
        .filter(|d| !d.disk.read_only)
        .try_fold(0u64, |sum, d| sum.checked_add(d.capacity_bytes))
        .ok_or_else(|| invalid("storage reservation overflow"))?;
    let capacity = Capacity {
        vcpus: template.machine.cpus.into(),
        memory_mib: template.machine.memory_mib.into(),
        storage_bytes: storage,
    };
    c.begin_with(r,kind,|tx|{
        if !fork && selected == "kernel_cow" {
            admission::require_kernel_capture_space(tx, capacity.memory_mib)?;
        } else if !fork {
            admission::require_capture_space(tx, capacity.memory_mib)?;
        }
        if selected == "kernel_cow" {
            admission::require_kernel_anchor_room(tx, capacity.memory_mib)?;
        }
        let relay_hold = if credential_relay_fork_eligible(kind, &inv) {
            active_credential_relay_hold(tx, &source)?
        } else {
            None
        };
        tx.execute("INSERT INTO managed_fork_batches(operation_id,source_incarnation,serve_instance,capture_id,
            template,children,session,token,anchor,network_gate,original,stage,pivot_json,restore_capture_id,
            volume_restore_policy,admission_mode,memory_fork_backend,selected_memory_fork_backend,credential_relay_hold)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![id,incarnation,namespace,capture,template_bytes,names,session,token,anchor,network,
                inv.source_disposition,initial,pivot,target,mode,admission,requested.as_str(),selected,relay_hold])?;
        let mut admitted = 0;
        let mut last_refusal = None;
        for (i,name) in input.children.iter().enumerate(){
            let instance=machine_id(&namespace,name);
            let present:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM instance_bindings WHERE route_id=? AND instance_id=?)",params![route,instance],|r|r.get(0))?;
            if present || instance==expected.instance_id{return Err(conflict("fork child name is already allocated"))}
            let refusal = match admission::reserve(tx,id,&instance,capacity) {
                Ok(()) => { admitted += 1; None }
                Err(fault) if admission == "best_effort" && fault.code == "E_RESOURCE_LIMIT" => {
                    let code = fault.code;
                    last_refusal = Some(fault);
                    Some(code)
                }
                Err(fault) => return Err(fault),
            };
            tx.execute("INSERT INTO managed_fork_children(batch_id,ordinal,name,instance_id,operation_id,prior_epoch,admission_error) VALUES(?,?,?,?,?,0,?)",params![id,i as i64,name,instance,key(id,"fork",i),refusal])?;
        }
        if fork && admitted == 0 {
            return Err(last_refusal.unwrap_or_else(|| invalid("fork has no admissible children")));
        }
        Ok(())
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Control {
    pub(crate) expected_revision: i64,
}

fn control_scope(c: &Catalog, r: &Request) -> Result<Operation> {
    let op = c.matching_operation(r)?;
    let expected = r.scope()?.2;
    if !matches!(op.kind.as_str(), "fork_batch" | "independent_fork" | "vm_snapshot" | "hibernate" | "vm_rollback")
        || op.expected_execution_epoch != expected.execution_epoch
        || op.expected_incarnation_id != expected.incarnation_id {
        return Err(Fault::new("E_STALE_EXECUTION","request differs from the admitted fork source"));
    }
    Ok(op)
}

pub(crate) fn retry(c: &mut Catalog, r: &Request, control: Control) -> Result<Operation> {
    let op = control_scope(c,r)?;
    if !matches!(op.kind.as_str(),"fork_batch"|"independent_fork") {return Err(conflict("only failed fork children can be retried"))}
    let id = &op.operation_id;
    let replay: bool = c.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_fork_retries WHERE batch_id=? AND prior_revision=?)",
        params![id,control.expected_revision], |r|r.get(0))?;
    if replay {
        return Ok(op);
    }
    if op.revision != control.expected_revision {
        return Err(Fault::new("E_STALE_REVISION","batch retry revision changed"));
    }
    if op.phase != "COMPLETED" {
        return Err(conflict("wait for the existing target attempts to settle"));
    }
    c.ready()?;
    let (capture, selected, lost_child): (String, String, bool) = c.db.query_row(
        "SELECT capture_id,selected_memory_fork_backend,EXISTS(SELECT 1 FROM managed_fork_children ch
           WHERE ch.batch_id=b.operation_id AND ch.capture_lost=1)
         FROM managed_fork_batches b WHERE operation_id=?",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let failed = {
        let mut stmt = c.db.prepare("SELECT ch.ordinal,ch.attempt,ch.instance_id,b.execution_epoch,
            h.vcpus,h.memory_mib,h.storage_bytes
            FROM managed_fork_children ch JOIN operations o ON ch.operation_id=o.operation_id
            JOIN managed_budget_holds h ON h.operation_id=o.operation_id AND h.instance_id=ch.instance_id
            JOIN instance_bindings b ON b.route_id=o.route_id AND b.instance_id=ch.instance_id
            WHERE ch.batch_id=? AND ch.cancelled=0 AND ch.capture_lost=0 AND o.phase='ABORTED' AND h.state='released'
              AND b.incarnation_id IS NULL AND b.active_operation_id IS NULL")?;
        let rows=stmt.query_map([id],|row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,
            row.get::<_,String>(2)?,row.get::<_,i64>(3)?,Capacity { vcpus:row.get::<_,i64>(4)? as u64,memory_mib:row.get::<_,i64>(5)? as u64,storage_bytes:row.get::<_,i64>(6)? as u64 })))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    if selected == "kernel_cow" && (lost_child || !failed.is_empty()) {
        crate::kernel_mm_anchor::acquire(c, id, &capture)?;
    }
    if failed.is_empty() {
        return Err(conflict("batch has no fenced failed targets to retry"));
    }
    let tx = c.db.transaction()?;
    for (ordinal, prior_attempt, instance, epoch, capacity) in failed {
        admission::reserve(&tx,id,&instance,capacity)?;
        let attempt=prior_attempt+1;
        let child=key(&format!("{id}/{ordinal}"),"attempt",attempt as usize);
        tx.execute("UPDATE managed_fork_children SET operation_id=?,prior_epoch=?,attempt=?,frame_hex=NULL
            WHERE batch_id=? AND ordinal=? AND attempt=?",params![child,epoch,attempt,id,ordinal,prior_attempt])?;
    }
    tx.execute("INSERT INTO managed_fork_retries VALUES(?,?)",params![id,op.revision])?;
    tx.execute("UPDATE managed_fork_batches SET stage='children',error=NULL,cancel_requested=0 WHERE operation_id=? AND source_released=1",[id])?;
    tx.execute("UPDATE operations SET phase='NEW',revision=revision+1 WHERE operation_id=?",[id])?;
    tx.commit()?;
    c.operation(id)
}

pub(crate) fn cancel(c: &mut Catalog, r: &Request, control: Control) -> Result<Operation> {
    let op=control_scope(c,r)?;
    let id=&op.operation_id;
    let prior:bool=c.db.query_row("SELECT cancel_requested FROM managed_fork_batches WHERE operation_id=?",[id],|r|r.get(0))?;
    if prior {return Ok(op)}
    if control.expected_revision!=op.revision {return Err(Fault::new("E_STALE_REVISION","batch cancellation revision changed"))}
    if op.phase!="NEW" {return Err(Fault::new("E_ALREADY_COMMITTED","batch already has a terminal result"))}
    let durable=matches!(op.kind.as_str(),"vm_snapshot"|"hibernate"|"vm_rollback");
    if durable {
        let (stage,point):(String,Option<String>)=c.db.query_row("SELECT b.stage,p.phase FROM managed_fork_batches b LEFT JOIN statepoints p USING(capture_id) WHERE b.operation_id=?",[id],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if matches!(point.as_deref(),Some("stop_committed"|"hibernated")) || op.kind=="vm_snapshot" && (point.is_some() || matches!(stage.as_str(),"source_return"|"waking"|"checkpoint_export")) {
            return Err(Fault::new("E_OPERATION_HAS_EFFECTS","the durable capture has passed its cancellation boundary"));
        }
    }
    let tx=c.db.transaction()?;
    tx.execute("UPDATE managed_fork_batches SET cancel_requested=1,
        stage=CASE WHEN stage IN ('arming','parking') THEN 'cancel_gate' WHEN stage='restore_preflight' THEN 'cancel_preflight' ELSE stage END WHERE operation_id=?",[id])?;
    tx.execute("UPDATE managed_fork_children AS ch SET cancelled=1 WHERE batch_id=? AND ch.capture_lost=0 AND ch.admission_error IS NULL
         AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.operation_id=ch.operation_id AND o.phase IN ('ABORTED','COMPLETED'))
         AND NOT EXISTS(SELECT 1 FROM target_activations a WHERE a.operation_id=ch.operation_id AND a.decision='commit')", [id])?;
    tx.execute("UPDATE operations SET revision=revision+1 WHERE operation_id=?",[id])?;
    tx.commit()?;
    c.operation(id)
}

pub(crate) fn target_cancelled(c: &Catalog, id: &str) -> Result<bool> {
    Ok(c.db.query_row("SELECT EXISTS(SELECT 1 FROM managed_fork_children WHERE operation_id=? AND cancelled=1)",[id],|r|r.get(0))?)
}

struct Job {
    id: String,
    inc: String,
    resource: String,
    session: u32,
    token: String,
    anchor: String,
    stage: String,
    original: String,
    kind: String,
    network: bool,
    pivot: Option<String>,
    kernel_cow: bool,
    credential_relay_hold: Option<String>,
}
impl Job {
    fn scope(&self) -> String {
        format!("{} {}", self.session, self.token)
    }
    fn capture_timing(&self, phase: &str, started: Instant) {
        let mut ended = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ended) } == 0 {
            let monotonic_us = ended.tv_sec * 1_000_000 + ended.tv_nsec / 1000;
            let backend = if self.kernel_cow { "kernel_cow" } else { "native" };
            eprintln!(
                "resourced managed capture operation={} capture={} backend={backend} phase={phase} monotonic_us={monotonic_us} duration_us={}",
                self.id, self.resource, started.elapsed().as_micros()
            );
        }
    }
    fn advance(&self, c: &Catalog, next: &str) -> Result<()> {
        c.db.execute(
            "UPDATE managed_fork_batches SET stage=?,error=NULL WHERE operation_id=? AND stage=?",
            params![next, self.id, self.stage],
        )?;
        Ok(())
    }
    fn fail_capture(&self, c: &Catalog, reason: &str) -> Result<()> {
        c.db.execute(
            "UPDATE managed_fork_batches SET stage='failure_return',error=? WHERE operation_id=? AND stage=?",
            params![reason, self.id, self.stage],
        )?;
        Ok(())
    }
    fn gate(&self, ep: &Endpoint, verb: &str, tail: &str) -> Result<String> {
        let reply = ep.command(&format!("GUEST_GATE_{verb} {} {tail}", self.scope()))?;
        let fields: Vec<_> = reply.split_whitespace().collect();
        if fields.len() != 4
            || fields[0].parse::<u32>() != Ok(self.session)
            || fields[1] != self.token
            || (fields[3] != "0" && !matches!(fields[2],"failed_thawed"|"expired_thawed"|"aborted"))
        {
            return Err(conflict(format!("unexpected Guest gate result {reply}")));
        }
        Ok(fields[2].to_owned())
    }
    fn capture(&self, c: &Catalog, objects: &File, escrow: &mut Escrow, ep: &Endpoint) -> Result<()> {
        let started = Instant::now();
        let op = c.operation(&self.id)?;
        let source = c.execution(&self.inc)?;
        let export = Export {
            capture_id: self.resource.clone(),
            representation_id: key(&self.id, "metadata", 0),
            purpose: Purpose::Checkpoint,
            session: self.session,
            hold_token: self.token.clone(),
        };
        let (checkpoint, helper_digest, roots, disks) = if self.kernel_cow {
            let capture = statepoint_capture::acquire_kernel(ep, &export)?;
            self.check_anchor(&capture.anchor)?;
            let roots = statepoint_capture::disk_roots(c, objects, &op, &source, &export, &capture.devices)?;
            let disks = Self::capture_disks(&capture.devices);
            let import_started = Instant::now();
            crate::kernel_mm_anchor::register(
                c, &self.id, &self.resource, &source, capture.source_pidfd, &capture.regions,
            )?;
            self.capture_timing("anchor_ready", import_started);
            (capture.checkpoint, capture.helper_digest, roots, disks)
        } else {
            let mut capture = statepoint_capture::acquire(ep, &export)?;
            self.check_anchor(&capture.anchor)?;
            let roots = statepoint_capture::disk_roots(c, objects, &op, &source, &export, &capture.devices)?;
            let disks = Self::capture_disks(&capture.devices);
            escrow.import_native(c, &self.resource, &op, &source, &mut capture)?;
            (capture.checkpoint, capture.helper_digest, roots, disks)
        };
        crate::activation_catalog::pin_source_tap(c, &self.resource, &source, self.network)?;
        let tx = c.db.unchecked_transaction()?;
        for root in roots {
            tx.execute(
                "INSERT OR IGNORE INTO root_refs VALUES('fork_capture',?,?,'active',1,?)",
                params![self.id, root, self.id],
            )?;
        }
        let next = if self.kernel_cow { "kernel_confirming" } else { "source_return" };
        tx.execute("UPDATE managed_fork_batches SET stage=?,checkpoint=?,disk_json=?,helper_digest=?,error=NULL WHERE operation_id=? AND stage='exporting'",
            params![next,checkpoint,serde_json::to_string(&disks).map_err(invalid)?,helper_digest,self.id])?;
        tx.commit()?;
        self.capture_timing("exported", started);
        Ok(())
    }
    fn check_anchor(&self, anchor: &str) -> Result<()> {
        if anchor != self.anchor {
            return Err(conflict("observed capture anchor changed"));
        }
        Ok(())
    }
    fn capture_disks(devices: &[statepoint_capture::Device]) -> BTreeMap<String, (String, String)> {
        devices
            .iter()
            .filter_map(|d| d.managed_source())
            .map(|(d, (g,v))| (d.to_string(), (g.to_string(),v.to_string())))
            .collect()
    }
    fn kernel_export(&self, c: &Catalog, objects: &File, escrow: &mut Escrow, ep: &Endpoint) -> Result<()> {
        // Allow rediscovery of the same paused point after a broker restart.
        // The deadline starts after the writer transition is reconciled.
        let expired: bool = c.db.query_row(
            "UPDATE managed_fork_batches
             SET kernel_export_deadline=coalesce(kernel_export_deadline,unixepoch()+45)
             WHERE operation_id=? RETURNING kernel_export_deadline<=unixepoch()",
            [&self.id],
            |row| row.get(0),
        )?;
        let result = if expired {
            Err(Fault::new("E_CAPTURE_TIMEOUT", "Kernel CoW anchor import did not settle while the source was held"))
        } else if self.stage == "exporting" {
            self.capture(c, objects, escrow, ep)
        } else {
            let started = Instant::now();
            crate::kernel_mm_anchor::acquire(c, &self.id, &self.resource)
                .and_then(|_| ep.command(&format!("CAPTURE_KERNEL_IMPORTED {}", self.scope())))
                .and_then(|_| {
                    self.capture_timing("anchor_confirmed", started);
                    self.advance(c, "source_return")
                })
        };
        match result {
            Err(error) if expired || matches!(error.code,
                "E_CAPTURE_LOST" | "E_KERNEL_ANCHOR_UNAVAILABLE" | "E_FENCE_UNPROVEN" | "E_INVALID_REQUEST" | "E_STATE_CONFLICT") =>
            {
                c.db.execute(
                    "UPDATE managed_fork_batches SET stage='kernel_abandon',error=? WHERE operation_id=? AND stage=?",
                    params![error.message, self.id, self.stage],
                )?;
                Ok(())
            }
            result => result,
        }
    }
    fn kernel_abandon(&self, c: &mut Catalog, ep: &Endpoint) -> Result<()> {
        let scope = self.scope();
        let inv = ep.inventory()?;
        match inv.source_disposition.as_str() {
            "HELD" => {
                crate::kernel_mm_anchor::quiesce_unpublished(c, &self.id, &self.resource)?;
                ep.command(&format!("CAPTURE_KERNEL_ABANDON {scope}"))?;
                ep.command(&format!("CAPTURE_FINISH {scope} RETURN_STANDBY"))?;
            }
            "STANDBY" | "WAKING" if self.original == "RUNNING" => {
                ep.command(&format!("STANDBY_WAKE {scope}"))?;
            }
            current if current == self.original => {
                let reason: Option<String> = c.db.query_row(
                    "SELECT error FROM managed_fork_batches WHERE operation_id=?",
                    [&self.id],
                    |row| row.get(0),
                )?;
                finish_abort(c, &self.id, reason.as_deref())?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod backend_tests {
    use super::{retry, Catalog, Control, MemoryForkBackend, Request};
    use serde_json::json;

    #[test]
    fn requested_backend_is_chosen_before_capture() {
        let default = MemoryForkBackend::default();
        assert_eq!(default.select(true, true, false).unwrap(), "native");
        assert_eq!(
            default.select(true, false, true).unwrap_err().code,
            "E_CAPABILITY_UNSUPPORTED"
        );
        assert_eq!(
            MemoryForkBackend::KernelCow.select(true, true, false).unwrap_err().code,
            "E_CAPABILITY_UNSUPPORTED"
        );
        let auto = MemoryForkBackend::Auto;
        assert_eq!(auto.select(true, true, false).unwrap(), "native");
        assert_eq!(auto.select(true, false, true).unwrap(), "kernel_cow");
        assert!(auto.select(true, false, false).is_err());
        assert_eq!(default.select(false, false, true).unwrap(), "kernel_cow");
    }

    #[test]
    fn retry_records_original_anchor_loss_before_reserving_a_new_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let mut catalog = Catalog::open(&dir.path().join("catalog.sqlite"), "boot", "session").unwrap();
        let bundle = format!("sha256:{}", "3".repeat(64));
        let digest = format!("sha256:{}", "1".repeat(64));
        catalog.register_bundle(&bundle, &digest).unwrap();
        catalog.db.execute_batch(
            "INSERT INTO operations
               SELECT 'batch','fork_batch',executable_sha256,'deep','source-vm',bundle_digest,
                      1,'source-inc','COMPLETED','NONE',2 FROM runtime_bundles;
             INSERT INTO operations
               SELECT 'child-attempt','restore_target',executable_sha256,'deep','child-vm',bundle_digest,
                      0,NULL,'ABORTED','ABORT',2 FROM runtime_bundles;
             INSERT INTO executions(incarnation_id,route_id,instance_id,execution_epoch,bundle_digest,host_boot_id,
                                    pid,pid_start_time,uid,phase,last_operation_id)
               SELECT 'source-inc','deep','source-vm',1,bundle_digest,'boot',123,1,1001,'exited','batch'
               FROM runtime_bundles;
             INSERT INTO managed_fork_batches(operation_id,source_incarnation,serve_instance,capture_id,template,children,
               session,token,anchor,network_gate,original,stage,source_released,memory_fork_backend,selected_memory_fork_backend)
               VALUES('batch','source-inc','serve','cut','{}','[]',1,'hold','gate',0,'RUNNING','complete',1,'auto','kernel_cow');
             INSERT INTO instance_bindings VALUES('deep','child-vm',0,NULL,NULL);
             INSERT INTO managed_fork_children(batch_id,ordinal,name,instance_id,operation_id,prior_epoch)
               VALUES('batch',0,'child','child-vm','child-attempt',0);
             INSERT INTO managed_budget_holds(instance_id,operation_id,vcpus,memory_mib,storage_bytes,state)
               VALUES('child-vm','child-attempt',1,64,1,'released');
             INSERT INTO resources VALUES('cut','descriptor','available','volatile',1,'{}','sha256:ram','batch',1);
             INSERT INTO root_refs VALUES('fork_capture','batch','cut','active',1,'batch');
             INSERT INTO kernel_mm_anchors(capture_id,operation_id,source_incarnation,source_epoch,source_session,
               host_boot_id,regions_json,layout_digest,helper_id,helper_pid,helper_start,executable_dev,executable_ino,resource_id)
               VALUES('cut','batch','source-inc',1,1,'boot','[{\x22guest_start\x22:0,\x22size\x22:4096}]','layout',
                      '1234567890abcdef1234567890abcdef',2147483647,1,1,1,'cut');"
        ).unwrap();
        let request: Request = serde_json::from_value(json!({
            "protocol":"WorkerResource/1","method":"RetryManagedFork","request_id":"retry",
            "route_id":"deep","operation_id":"batch","request_digest":digest,"bundle_digest":bundle,
            "expected":{"instance_id":"source-vm","incarnation_id":"source-inc","execution_epoch":1},
        })).unwrap();
        let error = retry(&mut catalog, &request, Control { expected_revision: 2 }).unwrap_err();
        assert_eq!(error.code, "E_CAPTURE_LOST");
        assert_eq!(catalog.resource("cut").unwrap()["state"], "lost");
        let operation = catalog.operation("batch").unwrap();
        assert_eq!(operation.phase, "COMPLETED");
        assert_eq!(operation.fork.unwrap()["children"][0]["attempt"], 0);
    }
}

#[cfg(test)]
mod relay_tests {
    use super::{
        active_credential_relay_hold, credential_relay_fork_eligible, source_exited, Catalog,
        Execution, Inventory,
    };
    use serde_json::json;

    #[test]
    fn credential_relay_fork_requires_a_running_source_and_its_original_active_hold() {
        let mut inventory: Inventory = serde_json::from_value(json!({
            "protocol":"CaptureControl/1", "devices":[], "source_disposition":"RUNNING",
            "last_session":1, "guest_gate":"idle", "measured_helper":true,
        })).unwrap();
        assert!(!credential_relay_fork_eligible("independent_fork", &inventory));
        inventory.credential_relay_fork = Some(true);
        for operation in ["independent_fork", "fork_batch"] {
            assert!(credential_relay_fork_eligible(operation, &inventory));
        }
        for operation in ["vm_snapshot", "hibernate", "vm_rollback"] {
            assert!(!credential_relay_fork_eligible(operation, &inventory));
        }
        inventory.source_disposition = "STANDBY".into();
        assert!(!credential_relay_fork_eligible("independent_fork", &inventory));

        let dir = tempfile::tempdir().unwrap();
        let catalog = Catalog::open(&dir.path().join("catalog.sqlite"), "boot", "session").unwrap();
        let bundle = format!("sha256:{}", "3".repeat(64));
        let digest = format!("sha256:{}", "1".repeat(64));
        catalog.register_bundle(&bundle, &digest).unwrap();
        catalog.db.execute_batch(
            "INSERT INTO lifecycle_policies(instance_id,bundle_digest,revision,policy_json)
               SELECT 'source-vm',bundle_digest,1,'{}' FROM runtime_bundles;
             INSERT INTO lifecycle_protections(instance_id,id,kind,principal,incarnation_id,epoch,revision,state,reason) VALUES
               ('source-vm','access-0-ssh','hold','grant','source-inc',2,1,'active','ssh'),
               ('source-vm','access-1-suspect','hold','grant','source-inc',2,1,'suspect','credential_proxy'),
               ('source-vm','access-2-epoch','hold','grant','source-inc',1,1,'active','credential_proxy'),
               ('source-vm','access-3-other','hold','grant','other-inc',2,1,'active','credential_proxy'),
               ('source-vm','access-4-lease','lease','grant','source-inc',2,1,'active','credential_proxy'),
               ('source-vm','access-5-current','hold','grant','source-inc',2,1,'active','credential_proxy'),
               ('source-vm','access-6-current','hold','other-grant','source-inc',2,1,'active','credential_proxy');"
        ).unwrap();
        let mut source = Execution {
            incarnation_id: "source-inc".into(), instance_id: "source-vm".into(),
            route_id: "deep".into(), execution_epoch: 2, bundle_digest: bundle,
            host_boot_id: "boot".into(), pid: 123, pid_start_time: 1, uid: 1001,
            phase: "registered".into(), last_operation_id: "launch".into(),
        };
        let hold = active_credential_relay_hold(&catalog.db, &source).unwrap().unwrap();
        assert_eq!(hold, "access-5-current");
        assert_eq!(active_credential_relay_hold(&catalog.db, &source).unwrap(), Some(hold.clone()));
        catalog.db.execute("UPDATE lifecycle_protections SET state='released' WHERE id=?", [&hold]).unwrap();
        assert_eq!(active_credential_relay_hold(&catalog.db, &source).unwrap().unwrap(), "access-6-current");
        source.phase = "unknown".into();
        assert!(active_credential_relay_hold(&catalog.db, &source).unwrap().is_none());
    }

    #[test]
    fn a_relay_preserving_fork_cannot_succeed_if_the_original_execution_exits() {
        let dir = tempfile::tempdir().unwrap();
        let mut catalog = Catalog::open(&dir.path().join("catalog.sqlite"), "boot", "session").unwrap();
        let bundle = format!("sha256:{}", "3".repeat(64));
        let digest = format!("sha256:{}", "1".repeat(64));
        catalog.register_bundle(&bundle, &digest).unwrap();
        catalog.db.execute_batch(
            "INSERT INTO operations
               SELECT 'batch','independent_fork',executable_sha256,'deep','source-vm',bundle_digest,
                      1,'source-inc','NEW','NONE',2 FROM runtime_bundles;
             INSERT INTO executions(incarnation_id,route_id,instance_id,execution_epoch,bundle_digest,host_boot_id,
                                    pid,pid_start_time,uid,phase,last_operation_id)
               SELECT 'source-inc','deep','source-vm',1,bundle_digest,'boot',123,1,1001,'exited','batch'
                      FROM runtime_bundles;
             INSERT INTO managed_fork_batches(operation_id,source_incarnation,serve_instance,capture_id,template,children,
               session,token,anchor,network_gate,original,stage,checkpoint,credential_relay_hold)
               VALUES('batch','source-inc','serve','cut','{}','[]',1,'hold','gate',0,'RUNNING','waking',X'01','access-held');
             INSERT INTO resources VALUES('cut','descriptor','available','volatile',1,'{}','sha256:ram','batch',1);
             INSERT INTO root_refs VALUES('fork_capture','batch','cut','active',1,'batch');"
        ).unwrap();
        let tx = catalog.db.transaction().unwrap();
        source_exited(&tx, "source-inc").unwrap();
        tx.commit().unwrap();
        let op = catalog.operation("batch").unwrap();
        assert_eq!(op.phase, "ABORTED");
        let receipt = op.fork.unwrap();
        assert_eq!(receipt["source_relay_retention_applied"], false);
        assert_eq!(receipt["error"], "original execution exited before its credential relay returned");
        let capture_pin: String = catalog.db.query_row(
            "SELECT state FROM root_refs WHERE owner_kind='fork_capture' AND owner_id='batch'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(capture_pin, "dropped");
    }
}

pub(crate) struct Actor {
    active: HashSet<String>,
    tx: mpsc::Sender<(String, Result<String>)>,
    rx: mpsc::Receiver<(String, Result<String>)>,
}
impl Default for Actor {
    fn default() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            active: HashSet::new(),
            tx,
            rx,
        }
    }
}
impl Actor {
    pub(crate) fn tick(&mut self, c: &mut Catalog, objects: &File, escrow: &mut Escrow, boot: &str) -> Result<()> {
        while let Ok((id, result)) = self.rx.try_recv() {
            self.active.remove(&id);
            match result {
                Ok(value)
                    if serde_json::from_str::<Value>(&value)
                        .is_ok_and(|v| v["state"] == "complete") =>
                {
                    c.db.execute("UPDATE managed_fork_batches SET stage='exporting',error=NULL WHERE operation_id=? AND stage='pivoting'",[id])?;
                }
                reply => {
                    let detail = match reply {
                        Err(e) => e.message,
                        Ok(v) => v,
                    };
                    c.db.execute(
                        "UPDATE managed_fork_batches SET error=? WHERE operation_id=?",
                        params![detail, id],
                    )?;
                }
            }
        }
        let jobs = {
            // Keep the original command stable across reconnects. The running
            // VMM may already have accepted it even before the first catalog write.
            let mut q=c.db.prepare("SELECT operation_id,source_incarnation,capture_id,session,token,anchor,stage,original,network_gate,
                json_remove(pivot_json,'$.admitted_grant_id','$.reconciled_writer'),(SELECT kind FROM operations o WHERE o.operation_id=b.operation_id),
                selected_memory_fork_backend='kernel_cow',credential_relay_hold
                FROM managed_fork_batches b WHERE stage IN ('failure_return','cancel_preflight','children','cancel_gate','arming','parking','standby','holding','pivoting','source_return','waking','kernel_confirming','kernel_abandon')
                OR (stage='exporting' AND EXISTS (SELECT 1 FROM operations o WHERE o.operation_id=b.operation_id AND o.kind IN ('independent_fork','fork_batch'))) ORDER BY rowid")?;
            let result = q
                .query_map([], |r| {
                    Ok(Job {
                        id: r.get(0)?,
                        inc: r.get(1)?,
                        resource: r.get(2)?,
                        session: r.get(3)?,
                        token: r.get(4)?,
                        anchor: r.get(5)?,
                        stage: r.get(6)?,
                        original: r.get(7)?,
                        network: r.get(8)?,
                        pivot: r.get(9)?,
                        kind: r.get(10)?,
                        kernel_cow: r.get(11)?,
                        credential_relay_hold: r.get(12)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            result
        };
        for job in jobs {
            if let Err(e) = self.step(c, objects, escrow, boot, &job) {
                if job.stage == "kernel_abandon" {
                    eprintln!("resourced Kernel CoW source return {}: {}", job.id, e.message);
                    continue;
                }
                c.db.execute("UPDATE managed_fork_batches SET error=? WHERE operation_id=? AND error IS NOT ?",params![e.message,job.id,e.message])?;
            }
        }
        Ok(())
    }
    fn step(&mut self, c: &mut Catalog, objects: &File, escrow: &mut Escrow, boot: &str, j: &Job) -> Result<()> {
        if j.stage == "children" {
            return dispatch_children(c, j);
        }
        if j.stage=="cancel_preflight" {return finish_abort(c,&j.id,None)}
        let ep = Endpoint::load(&c.db, &j.inc, boot)?;
        let scope = j.scope();
        if matches!(j.stage.as_str(), "standby" | "holding") && j.credential_relay_hold.is_some() {
            let source = c.execution(&j.inc)?;
            if active_credential_relay_hold(&c.db, &source)?.is_none() {
                return j.fail_capture(c, "credential relay holds ended before the source cut");
            }
        }
        match j.stage.as_str() {
            "cancel_gate" => {
                let inv=ep.inventory()?;
                let done = if inv.source_disposition=="RUNNING" && inv.last_session<j.session {
                    true
                } else {
                    let phase=j.gate(&ep,"QUERY","")?;
                    match phase.as_str() {
                        "preparing" | "armed" | "parked" => {
                            j.gate(&ep,"ABORT","")?;
                            false
                        }
                        "aborted" | "expired_thawed" | "failed_thawed" => true,
                        _ => false,
                    }
                };
                if done {
                    finish_abort(c,&j.id,None)?;
                }
            }
            "arming" => {
                if matches!(j.kind.as_str(), "vm_snapshot" | "hibernate" | "vm_rollback") {
                    crate::saved_files::record_mounts(c, &ep, &j.id)?;
                }
                let state = j.gate(&ep, "PREPARE", "2500 15000")?;
                if matches!(state.as_str(),"failed_thawed"|"expired_thawed"|"aborted") {
                    return finish_abort(c,&j.id,Some(&state));
                }
                if state == "armed" {
                    j.advance(c, "parking")?
                }
            }
            "parking" => {
                let state = j.gate(&ep, "QUERY", "")?;
                if matches!(state.as_str(),"failed_thawed"|"expired_thawed"|"aborted") {
                    return finish_abort(c,&j.id,Some(&state));
                }
                if state == "armed" {
                    j.gate(
                        &ep,
                        if j.network { "PARK_NETWORK" } else { "PARK" },
                        &j.anchor,
                    )?;
                } else if state == "parked" {
                    j.advance(c, "standby")?
                }
            }
            "standby" => {
                let started = Instant::now();
                let verb = if j.credential_relay_hold.is_some() {
                    "STANDBY_FORK_ENTER"
                } else {
                    "STANDBY_ENTER"
                };
                let status = match ep.command(&format!("{verb} {scope} managed")) {
                    Err(fault) if j.credential_relay_hold.is_some() && fault.code == "E_NATIVE_REFUSED" => {
                        return j.fail_capture(c, &fault.message);
                    }
                    result => result?,
                };
                if serde_json::from_str::<Value>(&status).map_err(invalid)?["source_disposition"]
                    == "STANDBY"
                {
                    j.capture_timing("source_parked", started);
                    j.advance(c, "holding")?
                }
            }
            "failure_return" => {
                let inv=ep.inventory()?;
                if matches!(inv.source_disposition.as_str(), "HELD" | "FAILED_HELD") {
                    ep.command(&format!("CAPTURE_CANCEL {scope}"))?;
                    return Ok(());
                }
                if matches!(inv.source_disposition.as_str(), "STANDBY" | "WAKING") && j.original == "RUNNING" {
                    ep.command(&format!("STANDBY_WAKE {scope}"))?;
                    return Ok(());
                }
                if inv.source_disposition == "GUEST_HELD" && j.credential_relay_hold.is_some() {
                    j.gate(&ep, "ABORT", "")?;
                    return Ok(());
                }
                if inv.source_disposition==j.original {
                    let reason:String=c.db.query_row("SELECT coalesce(error,'native capture refused') FROM managed_fork_batches WHERE operation_id=?",[&j.id],|r|r.get(0))?;
                    finish_abort(c,&j.id,Some(&reason))?;
                }
            }
            "holding" => {
                let started = Instant::now();
                let command = if !j.kernel_cow {
                    format!("CAPTURE_PREPARE {scope} parked")
                } else if j.original == "STANDBY" {
                    let (session, token, anchor) = standby_scope(c, &j.inc)?;
                    j.check_anchor(&anchor)?;
                    format!("CAPTURE_KERNEL_PREPARE {scope} {session} {token}")
                } else {
                    format!("CAPTURE_KERNEL_PREPARE {scope}")
                };
                let status = match ep.command(&command) {
                    Err(fault) if fault.code == "E_NATIVE_REFUSED" && (j.credential_relay_hold.is_some()
                        || fault.message.starts_with("ENOTSUP") || fault.message.starts_with("EIO held capture:")) => {
                        return j.fail_capture(c, &fault.message);
                    }
                    result=>result?
                };
                let status = serde_json::from_str::<Value>(&status).map_err(invalid)?;
                if status["phase"] == "failed" {
                    let reason = status["error"].as_str().unwrap_or("native source failed to reach the capture boundary");
                    j.fail_capture(c, reason)?;
                } else if status["source_disposition"] == "HELD" {
                    j.capture_timing("held_prepare", started);
                    if j.credential_relay_hold.is_some() && status["credential_relay_fork"] != true {
                        return j.fail_capture(c, "VMM did not confirm source credential relay retention");
                    }
                    j.advance(
                        c,
                        if j.pivot.is_some() {
                            "pivoting"
                        } else {
                            "exporting"
                        },
                    )?
                }
            }
            "pivoting" => {
                if !self.active.contains(&j.id) {
                    let command = format!(
                        "CAPTURE_BLOCK_PIVOT {scope} {}",
                        j.pivot
                            .as_deref()
                            .ok_or_else(|| conflict("missing pivot plan"))?
                    );
                    let id = j.id.clone();
                    let tx = self.tx.clone();
                    self.active.insert(id.clone());
                    thread::spawn(move || {
                        let answer = ep.command_with_timeout(&command, std::time::Duration::from_secs(90));
                        let _ = tx.send((id, answer));
                    });
                }
            }
            "exporting" | "kernel_confirming" if j.kernel_cow => j.kernel_export(c, objects, escrow, &ep)?,
            "kernel_abandon" => j.kernel_abandon(c, &ep)?,
            "exporting" => j.capture(c, objects, escrow, &ep)?,
            "source_return" => {
                let started = Instant::now();
                let status = ep.command(&format!("CAPTURE_FINISH {scope} RETURN_STANDBY"))?;
                if serde_json::from_str::<Value>(&status).map_err(invalid)?["source_disposition"]
                    == "STANDBY"
                {
                    j.capture_timing("source_returned_to_standby", started);
                    if j.original == "STANDBY" {
                        release(c, j)?
                    } else {
                        j.advance(c, "waking")?
                    }
                }
            }
            "waking" => {
                let started = Instant::now();
                let status = ep.command(&format!("STANDBY_WAKE {scope}"))?;
                if serde_json::from_str::<Value>(&status).map_err(invalid)?["source_disposition"]
                    == "RUNNING"
                {
                    j.capture_timing("source_returned_to_running", started);
                    release(c, j)?
                }
            }
            _ => return Err(conflict("unknown source capture stage")),
        }
        Ok(())
    }
}
/// A source pivot is one step in a managed operation. The fenced source exit
/// may release the parent, but only its actor can publish the terminal result.
pub(crate) fn source_exited(tx:&rusqlite::Transaction<'_>,inc:&str)->Result<()> {
    let mut q=tx.prepare("SELECT b.operation_id,o.kind,b.checkpoint IS NOT NULL AND b.stage!='kernel_abandon',
        p.phase,b.credential_relay_hold IS NOT NULL FROM managed_fork_batches b JOIN operations o USING(operation_id)
        LEFT JOIN statepoints p USING(capture_id) WHERE b.source_incarnation=? AND b.source_released=0 AND o.phase='NEW'")?;
    let jobs=q.query_map([inc],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,bool>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,bool>(4)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
    drop(q);
    for (id,kind,volatile,phase,preserve_relay) in jobs {
        if phase.as_deref()==Some("stop_committed") {continue}
        let next=match kind.as_str() {
            "independent_fork"|"fork_batch" if volatile && !preserve_relay=>"children",
            "vm_snapshot" if matches!(phase.as_deref(),Some("exporting"|"durable"))=>"checkpoint_export",
            _=>"aborted"
        };
        let error = if next == "aborted" {
            Some(if preserve_relay { "original execution exited before its credential relay returned" }
                else { "source exited before the managed capture was committed" })
        } else {
            None
        };
        tx.execute("UPDATE managed_fork_batches SET stage=?,source_released=1,error=? WHERE operation_id=?",params![next,error,id])?;
        if next=="aborted" {
            drop_capture_pins(tx, &id)?;
            tx.execute("UPDATE operations SET phase='ABORTED',decision='ABORT',revision=revision+1 WHERE operation_id=?",[&id])?;
            tx.execute("UPDATE managed_budget_holds SET state='released' WHERE operation_id=? AND state='reserved'",[&id])?;
        }
        tx.execute("UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",[&id])?;
    }
    Ok(())
}
pub(crate) fn finish_abort(c:&mut Catalog,id:&str,error:Option<&str>)->Result<()> {
    let tx=c.db.transaction()?;
    tx.execute("UPDATE managed_fork_batches SET source_released=1,stage='aborted',error=? WHERE operation_id=?",params![error,id])?;
    drop_capture_pins(&tx, id)?;
    tx.execute("UPDATE operations SET phase='ABORTED',decision='ABORT',revision=revision+1 WHERE operation_id=? AND phase='NEW'",[id])?;
    tx.execute("UPDATE managed_budget_holds SET state='released' WHERE operation_id=? AND state='reserved'",[id])?;
    tx.execute("UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",[id])?;
    tx.commit()?;
    Ok(())
}
fn drop_capture_pins(tx: &rusqlite::Transaction<'_>, id: &str) -> Result<()> {
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind IN ('fork_capture','kernel_anchor_export') AND owner_id=? AND state='active'", [id])?;
    Ok(())
}
fn release(c: &mut Catalog, j: &Job) -> Result<()> {
    if matches!(j.kind.as_str(),"vm_snapshot"|"hibernate"|"vm_rollback") &&
        c.db.query_row("SELECT cancel_requested FROM managed_fork_batches WHERE operation_id=?",[&j.id],|r|r.get::<_,bool>(0))? {
        return finish_abort(c,&j.id,None);
    }
    let tx = c.db.transaction()?;
    tx.execute(
        "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
        [&j.id],
    )?;
    let next=if j.kind=="vm_snapshot" {"checkpoint_export"} else {"children"};
    tx.execute("UPDATE managed_fork_batches SET source_released=1,stage=?,error=NULL WHERE operation_id=?",params![next,j.id])?;
    tx.commit()?;
    Ok(())
}
fn dispatch_children(c: &mut Catalog, j: &Job) -> Result<()> {
    let parent = c.operation(&j.id)?;
    let (template, disks, namespace): (String, String, String) = c.db.query_row(
        "SELECT template,disk_json,serve_instance FROM managed_fork_batches WHERE operation_id=?",
        [&j.id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let base: Machine = serde_json::from_str(&template).map_err(invalid)?;
    let disks: BTreeMap<String, (String,String)> = serde_json::from_str(&disks).map_err(invalid)?;
    let mut pending = {
        let mut q=c.db.prepare("SELECT ch.operation_id,ch.name,ch.instance_id,ch.prior_epoch FROM managed_fork_children ch LEFT JOIN operations o ON o.operation_id=ch.operation_id WHERE ch.batch_id=? AND o.operation_id IS NULL AND ch.cancelled=0 AND ch.capture_lost=0 AND ch.admission_error IS NULL ORDER BY ch.ordinal")?;
        let rows = q
            .query_map([&j.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    if j.kernel_cow && !pending.is_empty() {
        if let Err(error) = crate::kernel_mm_anchor::acquire(c, &j.id, &j.resource) {
            if error.code != "E_CAPTURE_LOST" {
                return Err(error);
            }
            let tx = c.db.transaction()?;
            tx.execute(
                "UPDATE managed_fork_children AS ch SET capture_lost=1
                 WHERE batch_id=? AND cancelled=0 AND capture_lost=0 AND admission_error IS NULL
                   AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.operation_id=ch.operation_id)",
                [&j.id],
            )?;
            tx.execute(
                "UPDATE managed_fork_batches SET error=? WHERE operation_id=?",
                params![error.message, j.id],
            )?;
            tx.commit()?;
            pending.clear();
        }
    }
    match c.ready() {
        Ok(()) => (),
        Err(error) if error.code == "E_RECOVERING" => pending.clear(),
        Err(error) => return Err(error),
    }
    for (op, name, instance, epoch) in pending {
        let mut machine = base.clone();
        machine.name = name.clone();
        machine.memory_fork_profile = j.kernel_cow.then(|| PROFILE.to_owned());
        for d in &mut machine.disks {
            d.volume_id = None;
            d.generation_id = disks.get(&d.device_id).ok_or_else(||conflict("capture omits declared disk"))?.0.clone();
        }
        let expected = crate::ipc::Expected { instance_id: instance.clone(), incarnation_id: None, execution_epoch: epoch };
        let mut devices = machine.devices(c, &op, &parent.route_id, &parent.bundle_digest, &expected)?;
        for device in &mut devices {
            if device.disk.read_only {
                device.volume_id=disks.get(&device.disk.device_id).ok_or_else(||conflict("captured read-only volume missing"))?.1.clone();
            }
        }
        let inc = key(&op, "vmm", 0);
        let digest = format!(
            "sha256:{}",
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(format!(
                "{}:{}:{}",
                parent.request_digest, j.resource, name
            )))
        );
        let tx = c.db.transaction()?;
        tx.execute(
            "INSERT INTO operations VALUES(?,'restore_target',?,?,?,?,?,NULL,'NEW','NONE',1)",
            params![op, digest, parent.route_id, instance, parent.bundle_digest, epoch],
        )?;
        if tx.execute("INSERT INTO instance_bindings(route_id,instance_id,execution_epoch,active_operation_id)
             VALUES(?,?,?,?) ON CONFLICT(route_id,instance_id) DO UPDATE SET active_operation_id=excluded.active_operation_id
             WHERE incarnation_id IS NULL AND active_operation_id IS NULL AND execution_epoch=excluded.execution_epoch",
             params![parent.route_id,instance,epoch,op])? != 1 {
            return Err(conflict("child binding changed before dispatch"));
        }
        tx.execute("INSERT INTO managed_launches(operation_id,incarnation_id,serve_instance,machine_name,spec_json,devices_json,vcpus,memory_mib) VALUES(?,?,?,?,?,?,?,?)",
            params![op,inc,namespace,name,serde_json::to_string(&machine).map_err(invalid)?,serde_json::to_string(&devices).map_err(invalid)?,machine.cpus,machine.memory_mib])?;
        tx.execute("UPDATE managed_budget_holds SET operation_id=? WHERE operation_id=? AND instance_id=? AND state='reserved'",params![op,j.id,instance])?;
        tx.execute("INSERT OR IGNORE INTO root_refs SELECT 'operation',?,resource_id,'active',1,? FROM root_refs WHERE owner_kind='fork_capture' AND owner_id=? AND state='active'",params![op,op,j.id])?;
        tx.commit()?;
    }
    let (total, done, failed, retryable): (i64,i64,i64,i64) = c.db.query_row(
        "SELECT COUNT(*),COUNT(CASE WHEN o.phase IN ('COMPLETED','ABORTED') OR (o.phase IS NULL AND (ch.cancelled=1 OR ch.capture_lost=1 OR ch.admission_error IS NOT NULL)) THEN 1 END),
             COUNT(CASE WHEN o.phase='ABORTED' OR ch.cancelled=1 OR ch.capture_lost=1 OR ch.admission_error IS NOT NULL THEN 1 END),
             COUNT(CASE WHEN o.phase='ABORTED' AND ch.cancelled=0 AND ch.capture_lost=0 THEN 1 END)
         FROM managed_fork_children ch LEFT JOIN operations o ON o.operation_id=ch.operation_id WHERE ch.batch_id=?",
         [&j.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if total == done && total > 0 {
        let tx = c.db.transaction()?;
        tx.execute("UPDATE managed_fork_batches SET stage='complete' WHERE operation_id=?", [&j.id])?;
        tx.execute("UPDATE operations SET phase='COMPLETED',revision=revision+1 WHERE operation_id=? AND phase='NEW'",[&j.id])?;
        if retryable == 0 {
            drop_capture_pins(&tx, &j.id)?;
        }
        if failed > 0 {
            tx.execute("UPDATE managed_budget_holds SET state='released' WHERE operation_id=? AND state='reserved'",[&j.id])?;
        }
        tx.commit()?;
    }
    Ok(())
}

fn sealed_file(bytes: &[u8]) -> Result<std::os::fd::OwnedFd> {
    use std::{
        fs::File,
        io::{Seek, Write},
        os::fd::{AsRawFd, FromRawFd},
    };
    let fd = unsafe {
        libc::memfd_create(
            c"smolvm-capture".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(statepoint_capture::host_io(std::io::Error::last_os_error()));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|_| file.rewind())
        .map_err(statepoint_capture::host_io)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(statepoint_capture::host_io(std::io::Error::last_os_error()));
    }
    Ok(file.into())
}
pub(crate) fn metadata(
    c: &Catalog,
    op: &Operation,
) -> Result<(Value, Vec<crate::ipc::FdEntry>, Vec<std::os::fd::OwnedFd>)> {
    let spec = restore(c, &op.operation_id)?.ok_or_else(|| invalid("missing fork source"))?;
    let (checkpoint,descriptor):(Vec<u8>,String)=c.db.query_row(
        "SELECT b.checkpoint,t.descriptor_json FROM managed_fork_batches b JOIN fd_transfers t ON t.resource_id=b.capture_id WHERE b.operation_id=? AND b.source_released=1 AND t.state='committed'",
        [&spec.batch_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?.ok_or_else(||Fault::new("E_RESOURCE_UNAVAILABLE","capture metadata or RAM unavailable"))?;
    let files = vec![
        sealed_file(&checkpoint)?,
        sealed_file(descriptor.as_bytes())?,
    ];
    let table = ["checkpoint", "ram_descriptor"]
        .iter()
        .enumerate()
        .map(|(index, role)| crate::ipc::FdEntry {
            index,
            resource_id: spec.capture_id.clone(),
            role: role.to_string(),
        })
        .collect();
    Ok((
        json!({"capture_id":spec.capture_id,"checkpoint_bytes":checkpoint.len(),"descriptor_bytes":descriptor.len()}),
        table,
        files,
    ))
}
pub(crate) fn kernel_metadata(
    c: &Catalog,
    op: &Operation,
) -> Result<(Value, Vec<crate::ipc::FdEntry>, Vec<std::os::fd::OwnedFd>, crate::managed_kernel_cow::Import)> {
    use sha2::{Digest, Sha256};
    let target = &op.operation_id;
    let restore = restore(c, target)?.ok_or_else(|| invalid("missing fork source"))?;
    let checkpoint: Vec<u8> = c.db.query_row(
        "SELECT b.checkpoint FROM managed_fork_batches b JOIN managed_fork_children ch ON ch.batch_id=b.operation_id
         WHERE b.operation_id=? AND ch.operation_id=? AND ch.cancelled=0 AND b.source_released=1
           AND b.selected_memory_fork_backend='kernel_cow' AND b.checkpoint IS NOT NULL",
        params![restore.batch_id, target],
        |row| row.get(0),
    ).optional()?.ok_or_else(|| conflict("target has no authorized Kernel CoW capture"))?;
    let (anchor, donor) = crate::kernel_mm_anchor::acquire(c, &restore.batch_id, &restore.capture_id)?;
    let checkpoint_digest = format!("sha256:{:x}", Sha256::digest(&checkpoint));
    let import = crate::managed_kernel_cow::Import {
        capture_id: restore.capture_id.clone(),
        proof_digest: format!("sha256:{:x}", Sha256::digest(format!(
            "KernelCowImport/1\0{}\0{target}\0{}\0{checkpoint_digest}",
            restore.capture_id, anchor.layout_digest,
        ))),
    };
    let descriptors = vec![donor, sealed_file(&checkpoint)?];
    let table = ["kernel_mm_anchor", "checkpoint"]
        .into_iter()
        .enumerate()
        .map(|(index, role)| crate::ipc::FdEntry {
            index,
            resource_id: restore.capture_id.clone(),
            role: role.into(),
        })
        .collect();
    Ok((
        json!({"capture_id":restore.capture_id, "checkpoint_bytes":checkpoint.len(), "regions":anchor.regions}),
        table,
        descriptors,
        import,
    ))
}
pub(crate) fn activation_input(c: &Catalog, op: &Operation) -> Result<Value> {
    let spec = restore(c, &op.operation_id)?.ok_or_else(|| invalid("missing fork activation"))?;
    let selected: String = c.db.query_row(
        "SELECT selected_memory_fork_backend FROM managed_fork_batches WHERE operation_id=?",
        [&spec.batch_id],
        |row| row.get(0),
    )?;
    let profile = if selected == "kernel_cow" { PROFILE } else { "parked" };
    let profile_digest = format!(
        "sha256:{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(format!(
            "{}:{profile}:{}",
            op.bundle_digest, spec.helper_digest
        ))
    );
    let mut plan = json!({"capture_resource_id":spec.capture_id,"capture_anchor":spec.anchor,"profile_digest":profile_digest,"helper_digest":spec.helper_digest});
    if let Some(network)=crate::activation_catalog::captured_network_input(c,&spec.capture_id,op)? {
        plan["network"]=network;
    }
    Ok(plan)
}
pub(crate) fn identity_frame(
    c: &Catalog,
    op: &Operation,
    record: &crate::activation_catalog::ActivationReceipt,
) -> Result<String> {
    let (name, old): (String, Option<String>) = c.db.query_row(
        "SELECT name,frame_hex FROM managed_fork_children WHERE operation_id=?",
        [&op.operation_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if let Some(frame) = old {
        return Ok(frame);
    }
    let encoded = build_identity_frame(op, &name, record)?;
    c.db.execute(
        "UPDATE managed_fork_children SET frame_hex=? WHERE operation_id=? AND frame_hex IS NULL",
        params![encoded, op.operation_id],
    )?;
    Ok(encoded)
}

pub(crate) fn build_identity_frame(
    op: &Operation,
    name: &str,
    record: &crate::activation_catalog::ActivationReceipt,
) -> Result<String> {
    let network = record.binding.network.as_ref();
    let mut frame = vec![0u8; 192];
    frame[..5].copy_from_slice(if network.is_some() {
        b"SGI2\x02"
    } else {
        b"SGI1\x01"
    });
    hex::decode_to_slice(&record.challenge, &mut frame[8..24]).map_err(invalid)?;
    frame[24..32].copy_from_slice(&(record.binding.execution.epoch as u64).to_le_bytes());
    hex::decode_to_slice(&record.context_digest, &mut frame[32..64]).map_err(invalid)?;
    getrandom::fill(&mut frame[64..112]).map_err(invalid)?;
    let host = if name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric()
    {
        name.to_ascii_lowercase()
    } else {
        key(&op.operation_id, "vm", 0)
    };
    frame[112] = host.len() as u8;
    frame[113..113 + host.len()].copy_from_slice(host.as_bytes());
    if let Some(network) = network {
        frame.extend_from_slice(&network.identity_bytes()?)
    }
    Ok(hex::encode(frame))
}
