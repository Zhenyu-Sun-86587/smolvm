//! Drives the durable export and stop phases of the shared managed capture actor.
use crate::catalog::{Catalog, Operation};
use crate::ipc::{Expected, Fault, Request, Result, PROTOCOL};
use crate::managed::key;
use crate::statepoint_capture::{Export, Purpose};
use crate::statepoints::StatePoints;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::fs::File;

pub(crate) fn receipt(c: &Catalog, op: &Operation) -> Result<Option<Value>> {
    let row = c.db.query_row(
        "SELECT stage,capture_id,restore_capture_id,original,source_released,error,target_operation_id
         FROM managed_fork_batches WHERE operation_id=?", [&op.operation_id],
        |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,
                r.get::<_,String>(3)?,r.get::<_,bool>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Option<String>>(6)?))
    ).optional()?;
    let Some((stage,capture,target,original,released,error,target_operation))=row else {return Ok(None)};
    let point=c.statepoint(&capture)?;
    let durable = point.as_ref().filter(|p| matches!(p.phase.as_str(),"durable"|"stop_committed"|"hibernated"));
    let child = target_operation.as_deref().map(|id| c.operation(id)).transpose()?;
    let target_point=target.as_deref().map(|id|c.require_statepoint(id)).transpose()?;
    let represented=target_point.as_ref().or(durable);
    Ok(Some(json!({
        "stage":stage, "capture_id":target.as_ref().unwrap_or(&capture),
        "rescue_capture_id":target.as_ref().map(|_|&capture), "target_operation_id":target_operation,
        "original_source_disposition":original, "source_released":released,
        "phase":point.as_ref().map(|p|&p.phase),
        "volume_map":child.as_ref().and_then(|op|op.statepoint.as_ref()).and_then(|p|p.get("volume_map")),
        "rescue_manifest_digest":target.as_ref().and_then(|_|durable).and_then(|p|p.manifest_digest.as_ref()),
        "representation_id":represented.map(|p|&p.point.representation_id),
        "manifest_digest":represented.and_then(|p|p.manifest_digest.as_ref()),
        "error":error.as_ref().or_else(||point.as_ref().and_then(|p|p.error.as_ref()))
    })))
}

pub(crate) fn request(op: &Operation, payload: Value) -> Request {
    Request {
        protocol:PROTOCOL.into(), method:"ManagedStatePoint".into(),request_id:"statepoint-reconcile".into(),
        operation_id:Some(op.operation_id.clone()),request_digest:Some(op.request_digest.clone()),
        route_id:Some(op.route_id.clone()),bundle_digest:Some(op.bundle_digest.clone()),
        expected:Some(Expected {instance_id:op.instance_id.clone(),incarnation_id:op.expected_incarnation_id.clone(),
                                execution_epoch:op.expected_execution_epoch}),
        fd_table:Vec::new(),payload,
    }
}

struct Job {
    id: String,
    stage: String,
    capture: String,
    session: u32,
    token: String,
    original: String,
    target: Option<String>,
    mode: Option<String>,
    kernel: bool,
}

impl Job {
    fn next(&self,c: &Catalog,stage:&str) -> Result<()> {
        c.db.execute("UPDATE managed_fork_batches SET stage=?,error=NULL WHERE operation_id=? AND stage=?",
                     params![stage,self.id,self.stage])?;
        Ok(())
    }
    fn step(&self, c:&mut Catalog, points:&mut StatePoints, objects:&File, boot:&str) -> Result<Option<Request>> {
        let op=c.operation(&self.id)?;
        let capture=&self.capture;
        let purpose=match op.kind.as_str(){
            "vm_snapshot"=>Purpose::Checkpoint, "hibernate"=>Purpose::Hibernate, "vm_rollback"=>Purpose::RollbackRescue,
            _=>return Err(Fault::invalid("unexpected durable capture kind"))
        };
        let export=Export {capture_id:capture.clone(), representation_id:key(&self.id,"representation",0),
                           purpose,session:self.session,hold_token:self.token.clone()};
        let req=request(&op,json!(export));
        if self.stage=="restore_preflight" {
            let target=self.target.as_ref().ok_or_else(||Fault::invalid("missing rollback target"))?;
            let prepare=request(&op,json!({"capture_id":target,"volume_restore_policy":self.mode}));
            let result=points.prepare_restore(c,objects,&prepare)?;
            if result["phase"]=="prepared" {
                points.require_rollback_target(c,&req,&op,target)?;
                self.next(c,if self.original=="STANDBY"{"holding"}else{"arming"})?;
            }
            return Ok(None);
        }
        if matches!(self.stage.as_str(),"rollback_target"|"rollback_activating") {
            let target=self.target.as_deref().ok_or_else(||Fault::invalid("missing accepted rollback target"))?;
            let mode=if self.mode.as_deref()==Some("exact") {crate::managed_state_restore::RestoreMode::Exact}
                else {crate::managed_state_restore::RestoreMode::CloneConflicts};
            let template:String=c.db.query_row("SELECT json_extract(template,'$.name') FROM managed_fork_batches WHERE operation_id=?",[&self.id],|r|r.get(0))?;
            let child=crate::managed_state_restore::queue_rollback(c,&op,&template,target,capture,mode)?;
            let tx=c.db.transaction()?;
            let terminal=matches!(child.phase.as_str(),"COMPLETED"|"ABORTED");
            tx.execute("UPDATE managed_fork_batches SET target_operation_id=?,stage=?,error=? WHERE operation_id=?",
                params![child.operation_id, if terminal {"complete"} else {"rollback_activating"},
                   child.statepoint.as_ref().and_then(|p|p["error"].as_str()),self.id])?;
            if terminal {
                tx.execute("UPDATE operations SET phase=?,decision=?,revision=revision+1 WHERE operation_id=? AND phase='NEW'",
                    params![child.phase,child.decision,self.id])?;
            }
            tx.commit()?;
            return Ok(None);
        }
        let cancel:bool=c.db.query_row("SELECT cancel_requested FROM managed_fork_batches WHERE operation_id=?",[&self.id],|r|r.get(0))?;
        if cancel {
            if c.statepoint(capture)?.is_none() {
                self.next(c, if self.kernel { "kernel_abandon" } else { "source_return" })?;
            } else {
                self.next(c,"abort_export")?;
            }
            return Ok(None);
        }
        let incarnation=op.expected_incarnation_id.as_deref().ok_or_else(||Fault::invalid("missing capture source"))?;
        let source=c.execution(incarnation)?;
        let mut record=c.statepoint(capture)?;
        if record.as_ref().is_none_or(|p|p.phase=="exporting") {
            if self.kernel && self.stage == "exporting" && !points.export_in_progress(capture) {
                let expired: bool = c.db.query_row(
                    "UPDATE managed_fork_batches
                     SET kernel_export_deadline=coalesce(kernel_export_deadline,unixepoch()+45)
                     WHERE operation_id=? RETURNING kernel_export_deadline<=unixepoch()",
                    [&self.id], |row| row.get(0),
                )?;
                if expired {
                    return Err(Fault::new("E_CAPTURE_TIMEOUT", "kernel CoW StatePoint anchor did not settle while the source was held"));
                }
            }
            if record.is_some() {
                record=Some(points.query(c,objects,&req,capture)?);
            }
            if record.as_ref().is_none_or(|p|p.phase=="exporting") && !points.export_in_progress(capture) {
                record=Some(points.begin(c,objects,boot,&req,&source)?);
            }
        }
        let record=record.ok_or_else(||Fault::invalid("missing admitted export"))?;
        match self.stage.as_str() {
            "exporting" if purpose == Purpose::Checkpoint => self.next(c,"source_return")?,
            "exporting" => self.next(c,"durable_hold")?,
            "checkpoint_export" if record.phase=="durable" => {
                let tx=c.db.transaction()?;
                tx.execute("UPDATE managed_fork_batches SET stage='complete',error=NULL WHERE operation_id=? AND source_released=1",[&self.id])?;
                tx.execute("UPDATE operations SET phase='COMPLETED',revision=revision+1 WHERE operation_id=? AND phase='NEW'",[&self.id])?;
                tx.commit()?;
            }
            "durable_hold" if record.phase=="durable" || record.phase=="stop_committed" => {
                if crate::machine_migration::source_operation(c, &op.operation_id)? {
                    return Ok(None);
                }
                if let Some(target)=&self.target {
                    let preflight=request(&op,json!({"capture_id":target,"volume_restore_policy":self.mode}));
                    if points.prepare_restore(c,objects,&preflight)?["phase"]!="prepared" {return Ok(None)}
                }
                return Ok(Some(request(&op,json!({"capture_id":capture,"expected_revision":record.revision,
                                                  "restore_capture_id":self.target}))));
            }
            _ => (),
        }
        Ok(None)
    }
}

pub(crate) fn tick(c:&mut Catalog, points:&mut StatePoints, objects:&File, boot:&str)->Result<Vec<Request>> {
    let jobs={
        let mut stmt=c.db.prepare("SELECT b.operation_id,b.stage,b.capture_id,b.session,b.token,b.original,b.restore_capture_id,b.volume_restore_policy,
          b.selected_memory_fork_backend='kernel_cow'
          FROM managed_fork_batches b JOIN operations o USING(operation_id)
          WHERE o.kind IN ('vm_snapshot','hibernate','vm_rollback') AND b.stage IN ('restore_preflight','exporting','checkpoint_export','durable_hold','rollback_target','rollback_activating')")?;
        let rows=stmt.query_map([],|r|Ok(Job {id:r.get(0)?,stage:r.get(1)?,capture:r.get(2)?,session:r.get(3)?,token:r.get(4)?,
                                             original:r.get(5)?,target:r.get(6)?,mode:r.get(7)?,kernel:r.get(8)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let mut stops=Vec::new();
    for job in jobs {
        match job.step(c,points,objects,boot) {
            Ok(Some(stop))=>stops.push(stop),
            Ok(None)=>(),
            Err(error)=>{
                c.db.execute("UPDATE managed_fork_batches SET error=? WHERE operation_id=? AND error IS NOT ?",params![error.message,job.id,error.message])?;
                if job.kernel && (error.code == "E_CAPTURE_LOST" || job.stage == "exporting"
                    && matches!(error.code, "E_CAPTURE_TIMEOUT" | "E_KERNEL_ANCHOR_UNAVAILABLE" | "E_STATE_CONFLICT" | "E_INVALID_REQUEST"))
                {
                    let (released, phase) = c.db.query_row(
                        "SELECT b.source_released,p.phase FROM managed_fork_batches b
                         LEFT JOIN statepoints p USING(capture_id) WHERE b.operation_id=?",
                        [&job.id], |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Option<String>>(1)?)),
                    )?;
                    if released {
                        if phase.as_deref() == Some("exporting") {
                            let failed = c.require_statepoint(&job.capture)?;
                            c.abort_statepoint(&failed)?;
                        }
                        crate::managed_fork::finish_abort(c, &job.id, Some(&error.message))?;
                    } else {
                        let next = if phase.is_some() { "abort_export" } else { "kernel_abandon" };
                        c.db.execute(
                            "UPDATE managed_fork_batches SET stage=? WHERE operation_id=? AND stage=?",
                            params![next, job.id, job.stage],
                        )?;
                    }
                }
                if job.stage=="restore_preflight" && (crate::statepoints::terminal_backing_fault(&error)
                    || matches!(error.code,"E_STATEPOINT_CORRUPT"|"E_VOLUME_GENERATION_MISMATCH"|"E_BUNDLE_UNAVAILABLE")) {
                    let tx=c.db.transaction()?;
                    tx.execute("UPDATE operations SET phase='ABORTED',decision='ABORT',revision=revision+1 WHERE operation_id=? AND phase='NEW'",[&job.id])?;
                    tx.execute("UPDATE managed_fork_batches SET stage='aborted',source_released=1 WHERE operation_id=?",[&job.id])?;
                    tx.execute("UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",[&job.id])?;
                    tx.commit()?;
                }
            }
        }
    }
    Ok(stops)
}
