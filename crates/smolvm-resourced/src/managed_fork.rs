//! One held source cut per admitted batch, independent of the HTTP connection.
use crate::admission::{self, Capacity};
use crate::catalog::{Catalog, Operation};
use crate::escrow::Escrow;
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::managed::{key, machine_id, Machine, Restore};
use crate::native_control::Endpoint;
use crate::statepoint_capture::{self, Export, Purpose};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    sync::mpsc,
    thread,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub children: Vec<String>,
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
pub(crate) fn restore(c: &Catalog, child: &str) -> Result<Option<Restore>> {
    Ok(c.db.query_row("SELECT b.operation_id,b.capture_id,b.anchor,b.helper_digest,b.pivot_json IS NOT NULL FROM managed_fork_children ch JOIN managed_fork_batches b ON b.operation_id=ch.batch_id WHERE ch.operation_id=? AND b.source_released=1",[child],
        |r|Ok(Restore{batch_id:r.get(0)?,capture_id:r.get(1)?,anchor:r.get(2)?,helper_digest:r.get(3)?,source_pivot:r.get(4)?,durable:None})).optional()?)
}
pub(crate) fn receipt(c: &Catalog, id: &str) -> Result<Option<Value>> {
    let Some((stage,capture,original,released,error))=c.db.query_row(
        "SELECT stage,capture_id,original,source_released,error FROM managed_fork_batches WHERE operation_id=?",[id],
        |r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,bool>(3)?,r.get::<_,Option<String>>(4)?))).optional()? else {return Ok(None)};
    let mut stmt = c.db.prepare(
        "SELECT ch.name,ch.instance_id,ch.operation_id,
             CASE WHEN ch.cancelled=1 AND o.operation_id IS NULL THEN 'ABORTED' ELSE COALESCE(o.phase,'RESERVED') END,
             m.incarnation_id,ch.prior_epoch,ch.attempt,ch.cancelled
         FROM managed_fork_children ch LEFT JOIN operations o ON o.operation_id=ch.operation_id
         LEFT JOIN managed_launches m ON m.operation_id=ch.operation_id
         WHERE ch.batch_id=? ORDER BY ch.ordinal")?;
    let rows = stmt.query_map([id], |r| Ok(json!({
        "name":r.get::<_,String>(0)?, "instance_id":r.get::<_,String>(1)?, "operation_id":r.get::<_,String>(2)?,
        "phase":r.get::<_,String>(3)?, "incarnation_id":r.get::<_,Option<String>>(4)?,
        "execution_epoch":r.get::<_,i64>(5)?+1, "attempt":r.get::<_,i64>(6)?, "cancelled":r.get::<_,bool>(7)?
    })))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let successful = rows.iter().filter(|r|r["phase"] == "COMPLETED").count();
    let failed = rows.iter().filter(|r|r["phase"] == "ABORTED").count();
    let outcome = match (stage.as_str(), successful, failed) {
        ("aborted", _, _) => "cancelled",
        ("complete", _, 0) => "applied",
        ("complete", 0, _) => "failed",
        ("complete", _, _) => "partial",
        _ => "pending",
    };
    Ok(Some(json!({"stage":stage, "capture_id":capture, "original_source_disposition":original,
        "source_released":released, "children":rows, "completed_count":successful,
        "failed_count":failed, "outcome":outcome, "error":error})))
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
    if !matches!(kind, "independent_fork" | "fork_batch")
        || input.children.is_empty()
        || input.children.len() > 32
        || kind == "independent_fork" && input.children.len() != 1
        || unique.len() != input.children.len()
        || input.children.iter().any(|n| !valid_id(n) || n.len() > 63)
    {
        return Err(invalid("invalid child names or batch size"));
    }
    let names = serde_json::to_string(&input.children).map_err(invalid)?;
    if let Some(prior) =
        c.db.query_row(
            "SELECT children FROM managed_fork_batches WHERE operation_id=?",
            [id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        if names != prior {
            return Err(Fault::new("E_IDEMPOTENCY_CONFLICT", "child set changed"));
        }
        return c.begin(r, kind);
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
    crate::product_volumes::require_capture_policy(c, &source, true)?;
    let start = c.operation(&source.last_operation_id)?;
    let template = crate::managed::plan(c, &start)?.ok_or_else(|| {
        Fault::new(
            "E_CAPABILITY_UNSUPPORTED",
            "source lacks managed block provenance",
        )
    })?;
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
    let (session, token, anchor) = if inv.source_disposition == "STANDBY" {
        c.db.query_row("SELECT n.session,n.token,n.anchor FROM native_standby s JOIN native_transitions n USING(operation_id) WHERE s.incarnation_id=? AND n.mode='managed'",[incarnation],
            |r|Ok((r.get::<_,u32>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).optional()?.ok_or_else(||conflict("source requires managed standby"))?
    } else {
        (
            inv.last_session
                .checked_add(1)
                .ok_or_else(|| conflict("Guest gate session exhausted"))?,
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
        if previous.incarnation_id!=incarnation || previous.state!="attached"{return Err(conflict("source writer epoch changed"))}
        Ok(json!({"operation_id":id,"request_digest":r.operation()?.1,"previous_grant_revision":previous.revision,"next_grant_id":key(id,"grant",0),"destinations":dest}).to_string())
    }).transpose()?;
    let network = inv.devices.iter().any(|dev| dev["virtio_type"] == 1);
    let initial = if inv.source_disposition == "STANDBY" {
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
        tx.execute("INSERT INTO managed_fork_batches(operation_id,source_incarnation,serve_instance,capture_id,template,children,session,token,anchor,network_gate,original,stage,pivot_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![id,incarnation,namespace,key(id,"ram",0),template_bytes,names,session,token,anchor,network,inv.source_disposition,initial,pivot])?;
        for (i,name) in input.children.iter().enumerate(){
            let instance=machine_id(&namespace,name);
            let present:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM instance_bindings WHERE route_id=? AND instance_id=?)",params![route,instance],|r|r.get(0))?;
            if present || instance==expected.instance_id{return Err(conflict("fork child name is already allocated"))}
            admission::reserve(tx,id,&instance,capacity)?;
            tx.execute("INSERT INTO managed_fork_children(batch_id,ordinal,name,instance_id,operation_id,prior_epoch) VALUES(?,?,?,?,?,0)",params![id,i as i64,name,instance,key(id,"fork",i)])?;
        }
        Ok(())
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Control {
    expected_revision: i64,
}

fn control_scope(c: &Catalog, r: &Request) -> Result<Operation> {
    let op = c.matching_operation(r)?;
    let expected = r.scope()?.2;
    if !matches!(op.kind.as_str(), "fork_batch" | "independent_fork")
        || op.expected_execution_epoch != expected.execution_epoch
        || op.expected_incarnation_id != expected.incarnation_id {
        return Err(Fault::new("E_STALE_EXECUTION","request differs from the admitted fork source"));
    }
    Ok(op)
}

pub(crate) fn retry(c: &mut Catalog, r: &Request, control: Control) -> Result<Operation> {
    let op = control_scope(c,r)?;
    let id = &op.operation_id;
    let tx = c.db.transaction()?;
    let replay: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_fork_retries WHERE batch_id=? AND prior_revision=?)",
        params![id,control.expected_revision], |r|r.get(0))?;
    if replay {
        drop(tx);
        return Ok(op);
    }
    if op.revision != control.expected_revision {
        return Err(Fault::new("E_STALE_REVISION","batch retry revision changed"));
    }
    if op.phase != "COMPLETED" {
        return Err(conflict("wait for the existing target attempts to settle"));
    }
    let failed = {
        let mut stmt = tx.prepare("SELECT ch.ordinal,ch.attempt,ch.instance_id,b.execution_epoch,
            h.vcpus,h.memory_mib,h.storage_bytes
            FROM managed_fork_children ch JOIN operations o ON ch.operation_id=o.operation_id
            JOIN managed_budget_holds h ON h.operation_id=o.operation_id AND h.instance_id=ch.instance_id
            JOIN instance_bindings b ON b.route_id=o.route_id AND b.instance_id=ch.instance_id
            WHERE ch.batch_id=? AND ch.cancelled=0 AND o.phase='ABORTED' AND h.state='released'
              AND b.incarnation_id IS NULL AND b.active_operation_id IS NULL")?;
        let rows=stmt.query_map([id],|row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,
            row.get::<_,String>(2)?,row.get::<_,i64>(3)?,Capacity { vcpus:row.get(4)?,memory_mib:row.get(5)?,storage_bytes:row.get(6)? })))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    if failed.is_empty() {
        return Err(conflict("batch has no fenced failed targets to retry"));
    }
    for (ordinal, prior_attempt, instance, epoch, capacity) in failed {
        admission::reserve(&tx,id,&instance,capacity)?;
        let attempt=prior_attempt+1;
        let child=key(&format!("{id}/{ordinal}"),"attempt",attempt as usize);
        tx.execute("UPDATE managed_fork_children SET operation_id=?,prior_epoch=?,attempt=?,frame_hex=NULL
            WHERE batch_id=? AND ordinal=? AND attempt=?",params![child,epoch,attempt,id,ordinal,prior_attempt])?;
    }
    tx.execute("INSERT INTO managed_fork_retries VALUES(?,?)",params![id,op.revision])?;
    tx.execute("UPDATE managed_fork_batches SET stage='children',error=NULL WHERE operation_id=? AND source_released=1",[id])?;
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
    let tx=c.db.transaction()?;
    tx.execute("UPDATE managed_fork_batches SET cancel_requested=1,
        stage=CASE WHEN stage IN ('arming','parking') THEN 'cancel_gate' ELSE stage END WHERE operation_id=?",[id])?;
    tx.execute("UPDATE managed_fork_children AS ch SET cancelled=1 WHERE batch_id=?
         AND NOT EXISTS(SELECT 1 FROM operations o WHERE o.operation_id=ch.operation_id AND o.phase='COMPLETED')
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
    network: bool,
    pivot: Option<String>,
}
impl Job {
    fn scope(&self) -> String {
        format!("{} {}", self.session, self.token)
    }
    fn advance(&self, c: &Catalog, next: &str) -> Result<()> {
        c.db.execute(
            "UPDATE managed_fork_batches SET stage=?,error=NULL WHERE operation_id=? AND stage=?",
            params![next, self.id, self.stage],
        )?;
        Ok(())
    }
    fn gate(&self, ep: &Endpoint, verb: &str, tail: &str) -> Result<String> {
        let reply = ep.command(&format!("GUEST_GATE_{verb} {} {tail}", self.scope()))?;
        let fields: Vec<_> = reply.split_whitespace().collect();
        if fields.len() != 4
            || fields[0].parse::<u32>() != Ok(self.session)
            || fields[1] != self.token
            || fields[3] != "0"
        {
            return Err(conflict(format!("unexpected Guest gate result {reply}")));
        }
        Ok(fields[2].to_owned())
    }
    fn capture(&self, c: &Catalog, escrow: &mut Escrow, ep: &Endpoint) -> Result<()> {
        let op = c.operation(&self.id)?;
        let source = c.execution(&self.inc)?;
        let export = Export {
            capture_id: self.resource.clone(),
            representation_id: key(&self.id, "metadata", 0),
            purpose: Purpose::Checkpoint,
            session: self.session,
            hold_token: self.token.clone(),
        };
        let mut capture = statepoint_capture::acquire(ep, &export)?;
        if capture.anchor != self.anchor {
            return Err(conflict("observed capture anchor changed"));
        }
        let roots = statepoint_capture::disk_roots(c, &op, &source, &export, &capture.devices)?;
        let disks: BTreeMap<_, _> = capture
            .devices
            .iter()
            .filter_map(|d| d.managed_source())
            .map(|(d, (g,v))| (d.to_string(), (g.to_string(),v.to_string())))
            .collect();
        escrow.import_native(c, &self.resource, &op, &source, &mut capture)?;
        crate::activation_catalog::pin_source_tap(c, &self.resource, &source, self.network)?;
        let tx = c.db.unchecked_transaction()?;
        for root in roots {
            tx.execute(
                "INSERT OR IGNORE INTO root_refs VALUES('fork_capture',?,?,'active',1,?)",
                params![self.id, root, self.id],
            )?;
        }
        tx.execute("UPDATE managed_fork_batches SET stage='source_return',checkpoint=?,disk_json=?,helper_digest=?,error=NULL WHERE operation_id=? AND stage='exporting'",
            params![capture.checkpoint,serde_json::to_string(&disks).map_err(invalid)?,capture.helper_digest,self.id])?;
        tx.commit()?;
        Ok(())
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
    pub(crate) fn tick(&mut self, c: &mut Catalog, escrow: &mut Escrow, boot: &str) -> Result<()> {
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
            let mut q=c.db.prepare("SELECT operation_id,source_incarnation,capture_id,session,token,anchor,stage,original,network_gate,pivot_json FROM managed_fork_batches WHERE stage NOT IN ('complete','aborted') ORDER BY rowid")?;
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
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            result
        };
        for job in jobs {
            if let Err(e) = self.step(c, escrow, boot, &job) {
                c.db.execute("UPDATE managed_fork_batches SET error=? WHERE operation_id=? AND error IS NOT ?",params![e.message,job.id,e.message])?;
            }
        }
        Ok(())
    }
    fn step(&mut self, c: &mut Catalog, escrow: &mut Escrow, boot: &str, j: &Job) -> Result<()> {
        if j.stage == "children" {
            return dispatch_children(c, j);
        }
        let ep = Endpoint::load(&c.db, &j.inc, boot)?;
        let scope = j.scope();
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
                    let tx=c.db.transaction()?;
                    tx.execute("UPDATE managed_fork_batches SET source_released=1,stage='aborted',error=NULL WHERE operation_id=?",[&j.id])?;
                    tx.execute("UPDATE operations SET phase='ABORTED',decision='ABORT',revision=revision+1 WHERE operation_id=?",[&j.id])?;
                    tx.execute("UPDATE managed_budget_holds SET state='released' WHERE operation_id=? AND state='reserved'",[&j.id])?;
                    tx.execute("UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",[&j.id])?;
                    tx.commit()?;
                }
            }
            "arming" => {
                let state = j.gate(&ep, "PREPARE", "2500 15000")?;
                if state == "armed" {
                    j.advance(c, "parking")?
                }
            }
            "parking" => {
                let state = j.gate(&ep, "QUERY", "")?;
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
                let status = ep.command(&format!("STANDBY_ENTER {scope} managed"))?;
                if serde_json::from_str::<Value>(&status).map_err(invalid)?["source_disposition"]
                    == "STANDBY"
                {
                    j.advance(c, "holding")?
                }
            }
            "holding" => {
                let status = ep.command(&format!("CAPTURE_PREPARE {scope} parked"))?;
                if serde_json::from_str::<Value>(&status).map_err(invalid)?["source_disposition"]
                    == "HELD"
                {
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
            "exporting" => j.capture(c, escrow, &ep)?,
            "source_return" => {
                let status = ep.command(&format!("CAPTURE_FINISH {scope} RETURN_STANDBY"))?;
                if serde_json::from_str::<Value>(&status).map_err(invalid)?["source_disposition"]
                    == "STANDBY"
                {
                    if j.original == "STANDBY" {
                        release(c, j)?
                    } else {
                        j.advance(c, "waking")?
                    }
                }
            }
            "waking" => {
                let status = ep.command(&format!("STANDBY_WAKE {scope}"))?;
                if serde_json::from_str::<Value>(&status).map_err(invalid)?["source_disposition"]
                    == "RUNNING"
                {
                    release(c, j)?
                }
            }
            _ => return Err(conflict("unknown source capture stage")),
        }
        Ok(())
    }
}
fn release(c: &mut Catalog, j: &Job) -> Result<()> {
    let tx = c.db.transaction()?;
    tx.execute(
        "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
        [&j.id],
    )?;
    tx.execute("UPDATE managed_fork_batches SET source_released=1,stage='children',error=NULL WHERE operation_id=?",[&j.id])?;
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
    let pending = {
        let mut q=c.db.prepare("SELECT ch.operation_id,ch.name,ch.instance_id,ch.prior_epoch FROM managed_fork_children ch LEFT JOIN operations o ON o.operation_id=ch.operation_id WHERE ch.batch_id=? AND o.operation_id IS NULL AND ch.cancelled=0 ORDER BY ch.ordinal")?;
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
    for (op, name, instance, epoch) in pending {
        let mut machine = base.clone();
        machine.name = name.clone();
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
        "SELECT COUNT(*),COUNT(CASE WHEN o.phase IN ('COMPLETED','ABORTED') OR (o.phase IS NULL AND ch.cancelled=1) THEN 1 END),
             COUNT(CASE WHEN o.phase='ABORTED' OR ch.cancelled=1 THEN 1 END),
             COUNT(CASE WHEN o.phase='ABORTED' AND ch.cancelled=0 THEN 1 END)
         FROM managed_fork_children ch LEFT JOIN operations o ON o.operation_id=ch.operation_id WHERE ch.batch_id=?",
         [&j.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if total == done && total > 0 {
        let tx = c.db.transaction()?;
        tx.execute("UPDATE managed_fork_batches SET stage='complete' WHERE operation_id=?", [&j.id])?;
        tx.execute("UPDATE operations SET phase='COMPLETED',revision=revision+1 WHERE operation_id=? AND phase='NEW'",[&j.id])?;
        if retryable == 0 {
            tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='fork_capture' AND owner_id=? AND state='active'",[&j.id])?;
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
pub(crate) fn activation_input(c: &Catalog, op: &Operation) -> Result<Value> {
    let spec = restore(c, &op.operation_id)?.ok_or_else(|| invalid("missing fork activation"))?;
    let profile_digest = format!(
        "sha256:{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(format!(
            "{}:parked:{}",
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
