//! A single Worker actor journals each transition before it submits native work.
use super::*;
use crate::catalog::Operation;
use crate::native_control::Endpoint;

#[derive(Default)]
pub(crate) struct Controller {
    cache_reclaim: pressure::CacheReclaim,
}
struct Machine {
    expected: Expected,
    bundle: String,
    active: Option<String>,
    rev: i64,
    policy: Policy,
    seq: i64,
    idle: Option<i64>,
    grace: i64,
    freeze: Option<i64>,
    freeze_session: Option<u32>,
    next: i64,
}
impl Machine {
    fn load(c: &Catalog, id: &str) -> Result<Self> {
        let (rev, policy) = row_policy(&c.db, id)?;
        Ok(c.db.query_row("SELECT p.bundle_digest,b.incarnation_id,coalesce(b.execution_epoch,0),b.active_operation_id,
            p.activity_seq,p.idle_since,p.grace_until,p.freeze_seq,p.next_attempt,p.freeze_session FROM lifecycle_policies p LEFT JOIN instance_bindings b ON b.instance_id=p.instance_id AND b.route_id='deep'
            WHERE p.instance_id=?",[id],|r|Ok(Self{expected:Expected{instance_id:id.into(),incarnation_id:r.get(1)?,execution_epoch:r.get(2)?},
                bundle:r.get(0)?,active:r.get(3)?,rev,policy,seq:r.get(4)?,idle:r.get(5)?,grace:r.get(6)?,freeze:r.get(7)?,next:r.get(8)?,freeze_session:r.get(9)?}))?)
    }
    fn demand(&self, db: &Connection) -> Result<bool> {
        Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_protections WHERE instance_id=? AND (kind='wake' AND state='pending'
            OR incarnation_id=? AND kind='hold' AND state IN ('active','suspect')))",params![self.expected.instance_id,self.expected.incarnation_id],|r|r.get(0))?)
    }
    fn saved(&self, db: &Connection) -> Result<Option<String>> {
        Ok(db.query_row("SELECT p.capture_id FROM statepoints p JOIN operations o USING(operation_id) JOIN executions e ON e.incarnation_id=p.source_incarnation_id
            WHERE o.instance_id=? AND e.execution_epoch=? AND p.phase='hibernated' AND json_extract(p.export_json,'$.purpose') IN ('hibernate','rollback_rescue')
            ORDER BY p.rowid DESC LIMIT 1",params![self.expected.instance_id,self.expected.execution_epoch],|r|r.get(0)).optional()?)
    }
    fn name(&self, db: &Connection) -> Result<String> {
        Ok(db.query_row("SELECT l.machine_name FROM managed_launches l JOIN operations o USING(operation_id) WHERE o.instance_id=? AND o.phase='COMPLETED'
            ORDER BY o.expected_execution_epoch DESC LIMIT 1",[&self.expected.instance_id],|r|r.get(0))?)
    }
}
struct Observation {
    power: String,
    gate: Option<u32>,
    blockers: Vec<String>,
}

fn idle_deadlines(m: &Machine, observed: &Observation, since: i64) -> (Option<i64>, Option<i64>) {
    if !observed.blockers.is_empty() || !matches!(observed.power.as_str(), "RUNNING" | "STANDBY") {
        return (None, None);
    }
    let deadline = |seconds| (since + i64::from(seconds) * 1000).max(m.grace).max(m.next);
    let standby = (m.policy.auto_standby && observed.power == "RUNNING")
        .then(|| deadline(m.policy.standby_after_seconds));
    let hibernate = m
        .policy
        .auto_hibernate
        .then(|| deadline(m.policy.hibernate_after_seconds));
    (standby, hibernate)
}

fn can_save(db: &Connection, expected: &Expected, unreserved_bytes: u64) -> Result<bool> {
    let memory: Option<u32> = db
        .query_row(
            "SELECT memory_mib FROM managed_launches WHERE incarnation_id=?
             AND coalesce(json_extract(spec_json,'$.live_compute_growth'),0)=0",
            [&expected.incarnation_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(memory.is_some_and(|mib| unreserved_bytes >= crate::admission::capture_storage(mib.into())))
}

fn next_action(
    c: &Catalog,
    m: &Machine,
    observed: &Observation,
    now: i64,
) -> Result<Option<Value>> {
    if let Some(d) = pending(&c.db, &m.expected.instance_id)? {
        if d.stage == "queued"
            && (decision_changed(m, &d, observed)
                || d.origin == "wake" && !m.demand(&c.db)?
                || d.kind == "hibernate"
                    && !can_save(
                        &c.db,
                        &m.expected,
                        crate::admission::unreserved_storage(&c.db)?,
                    )?)
        {
            return Ok(None);
        }
        return Ok(Some(
            json!({"kind":d.kind,"origin":d.origin,"eligible_after_ms":0}),
        ));
    }
    let (standby, hibernate) = idle_deadlines(m, observed, m.idle.unwrap_or(now));
    let save_available = hibernate.is_some()
        && can_save(
            &c.db,
            &m.expected,
            crate::admission::unreserved_storage(&c.db)?,
        )?;
    let hibernate_due = hibernate.is_some_and(|deadline| deadline <= now);
    let next = if hibernate_due {
        hibernate
            .filter(|_| save_available)
            .map(|deadline| (deadline, "hibernate"))
    } else {
        [
            standby.map(|deadline| (deadline, "standby")),
            hibernate
                .filter(|_| save_available)
                .map(|deadline| (deadline, "hibernate")),
        ]
        .into_iter()
        .flatten()
        .min()
    };
    Ok(next.map(|(deadline,kind)| json!({"kind":kind,"origin":"idle","eligible_after_ms":deadline.saturating_sub(now).max(0)})))
}

fn observe(c: &Catalog, m: &Machine, boot: &str, now: i64) -> Result<Observation> {
    let mut blockers = Vec::new();
    let id = &m.expected.instance_id;
    let mut gate = None;
    let power = if let Some(inc) = m.expected.incarnation_id.as_deref() {
        let result = Endpoint::load(&c.db, inc, boot).and_then(|ep| ep.inventory());
        match result {
            Ok(inv) => {
                if !inv.measured_helper || inv.standby_blocker.is_some() {
                    blockers.push(
                        inv.standby_blocker
                            .unwrap_or_else(|| "Guest helper unavailable".into()),
                    )
                }
                if inv.source_disposition == "STANDBY" && inv.guest_gate == "parked" {
                    let pinned:bool=c.db.query_row("SELECT EXISTS(SELECT 1 FROM native_standby s JOIN native_transitions n USING(operation_id)
                        WHERE s.incarnation_id=? AND n.mode='managed' AND n.session=? AND n.stage='complete')",params![inc,inv.last_session],|r|r.get(0))?;
                    if pinned {
                        gate = Some(inv.last_session)
                    }
                }
                inv.source_disposition
            }
            Err(_) => {
                blockers.push("unknown:native_inventory".into());
                "UNKNOWN".into()
            }
        }
    } else if m.saved(&c.db)?.is_some() {
        "HIBERNATED".into()
    } else {
        "STOPPED".into()
    };
    if m.policy.keep_running {
        blockers.push("keep_running".into())
    }
    if m.active.is_some() {
        blockers.push("operation_in_progress".into())
    }
    let protections: Vec<String> = {
        let mut q=c.db.prepare("SELECT kind||':'||reason FROM lifecycle_protections WHERE instance_id=?
              AND ((kind='wake' AND state='pending') OR (incarnation_id=? AND state IN ('active','suspect') AND (kind='hold' OR kind='lease' AND ?))) ORDER BY id")?;
        let items = q
            .query_map(
                params![
                    id,
                    m.expected.incarnation_id,
                    m.policy.activity.protect_running_leases
                ],
                |r| r.get(0),
            )?
            .collect::<rusqlite::Result<_>>()?;
        items
    };
    blockers.extend(protections);
    for collector in COLLECTORS {
        let report:Option<(i64,String)>=c.db.query_row("SELECT valid_until,busy_json FROM lifecycle_reports WHERE instance_id=? AND collector=? AND incarnation_id=?",
            params![id,collector,m.expected.incarnation_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let controlled = collector == "guest"
            && gate.is_some()
            && gate == m.freeze_session
            && m.freeze == Some(m.seq);
        match report {
            Some((expires, reasons)) if expires >= now || controlled => {
                for reason in serde_json::from_str::<Vec<String>>(&reasons).map_err(invalid)? {
                    blockers.push(format!("{collector}:{reason}"))
                }
            }
            _ => blockers.push(format!("unknown:{collector}")),
        }
    }
    if power == "STANDBY" && gate.is_none() {
        blockers.push("unknown:standby_hold".into())
    }
    Ok(Observation {
        power,
        gate,
        blockers,
    })
}

pub(super) fn status(c: &Catalog, expected: &Expected) -> Result<Value> {
    let m = Machine::load(c, &expected.instance_id)?;
    let boot: String =
        c.db.query_row("SELECT host_boot_id FROM worker_state", [], |r| r.get(0))?;
    let now = monotonic()?;
    let o = observe(c, &m, &boot, now)?;
    let next = next_action(c, &m, &o, now)?;
    let decision:Option<Value>=c.db.query_row("SELECT id,kind,origin,stage,error,start_memory,end_memory,created_at,finished_at FROM lifecycle_decisions
        WHERE instance_id=? ORDER BY rowid DESC LIMIT 1",[&expected.instance_id],|r|Ok(json!({"operation_id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,
        "origin":r.get::<_,String>(2)?,"stage":r.get::<_,String>(3)?,"error":r.get::<_,Option<String>>(4)?,"start_worker_memory_bytes":r.get::<_,Option<i64>>(5)?,
        "end_worker_memory_bytes":r.get::<_,Option<i64>>(6)?,"created_at_ms":r.get::<_,i64>(7)?,"finished_at_ms":r.get::<_,Option<i64>>(8)?}))).optional()?;
    let pressure: Option<(bool, String)> =
        c.db.query_row(
            "SELECT throttled,sample_json FROM lifecycle_pressure WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let balloon = crate::resource_resize::pressure_hint::latest(&c.db)?;
    let collectors = {
        let mut query=c.db.prepare("SELECT collector,session,seq,valid_until FROM lifecycle_reports WHERE instance_id=? AND incarnation_id=?")?;
        let rows=query.query_map(params![expected.instance_id,expected.incarnation_id],|r|Ok((r.get::<_,String>(0)?,json!({"session":r.get::<_,String>(1)?,"seq":r.get::<_,i64>(2)?,"fresh":r.get::<_,i64>(3)?>=now}))))?.collect::<rusqlite::Result<BTreeMap<_,_>>>()?;
        rows
    };
    Ok(
        json!({"collectors":collectors,"instance_id":expected.instance_id,"incarnation_id":expected.incarnation_id,"execution_epoch":expected.execution_epoch,
        "binding_revision":protections::revision(expected)?,"power":o.power,"statepoint":m.saved(&c.db)?,"applied_revision":m.rev,"effective_policy":m.policy,"activity_seq":m.seq,
        "first_launch_supported":true,
        "blockers":o.blockers,"controlled_suspended":o.gate.is_some() && o.gate==m.freeze_session && m.freeze==Some(m.seq),"idle_ms":m.idle.map(|v|now.saturating_sub(v)),
        "last_decision":decision,"next_action":next,"pressure":pressure.map(|(held,raw)|json!({"admission_throttled":held,"sample":serde_json::from_str::<Value>(&raw).ok(),"last_balloon":balloon}))}),
    )
}
struct Decision {
    id: String,
    kind: String,
    origin: String,
    stage: String,
    rev: i64,
    seq: i64,
    expected: Expected,
}
fn pending(db: &Connection, id: &str) -> Result<Option<Decision>> {
    Ok(db.query_row("SELECT id,kind,origin,stage,policy_revision,activity_seq,incarnation_id,epoch FROM lifecycle_decisions
        WHERE instance_id=? AND stage IN ('queued','dispatching','running')",[id],|r|Ok(Decision{
            id:r.get(0)?,kind:r.get(1)?,origin:r.get(2)?,stage:r.get(3)?,rev:r.get(4)?,seq:r.get(5)?,
            expected:Expected{instance_id:id.to_owned(),incarnation_id:r.get(6)?,execution_epoch:r.get(7)?}})).optional()?)
}
fn decision_changed(m: &Machine, d: &Decision, o: &Observation) -> bool {
    m.expected != d.expected
        || m.active.is_some()
        || d.rev != m.rev
        || d.origin != "wake"
            && (m.seq != d.seq
                || !o.blockers.is_empty()
                || !matches!(o.power.as_str(), "RUNNING" | "STANDBY"))
}

fn record(
    c: &Catalog,
    m: &Machine,
    kind: &str,
    origin: &str,
    o: &Observation,
    start: Option<u64>,
) -> Result<()> {
    let tx = Transaction::new_unchecked(&c.db, TransactionBehavior::Immediate)?;
    let n: i64 = tx.query_row(
        "SELECT coalesce(max(rowid),0)+1 FROM lifecycle_decisions",
        [],
        |r| r.get(0),
    )?;
    let id = format!(
        "lifecycle-{:x}",
        Sha256::digest(format!(
            "{}:{}:{}:{n}",
            m.bundle, m.expected.instance_id, m.expected.execution_epoch
        ))
    );
    let ready = kind == "authorize_access";
    tx.execute("INSERT INTO lifecycle_decisions(id,instance_id,incarnation_id,epoch,policy_revision,activity_seq,kind,origin,stage,disposition,created_at,finished_at,start_memory)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",params![id,m.expected.instance_id,m.expected.incarnation_id,m.expected.execution_epoch,m.rev,m.seq,kind,origin,
        if ready{"completed"}else{"queued"},o.power,wall()?,if ready{Some(wall()?)}else{None},start.map(|v|v as i64)])?;
    if origin == "wake" {
        tx.execute("UPDATE lifecycle_protections SET wake_operation=?,revision=revision+1 WHERE instance_id=? AND kind='wake' AND state='pending'
            AND wake_operation IS NULL",params![id,m.expected.instance_id])?;
    }
    tx.commit()?;
    Ok(())
}
fn request(m: &Machine, d: &Decision) -> Request {
    Request {
        protocol: crate::ipc::PROTOCOL.into(),
        method: "WorkerLifecycleDecision".into(),
        request_id: d.id.clone(),
        operation_id: Some(d.id.clone()),
        request_digest: Some(format!(
            "sha256:{:x}",
            Sha256::digest(format!("{}:{}", d.id, d.kind))
        )),
        route_id: Some("deep".into()),
        bundle_digest: Some(m.bundle.clone()),
        expected: Some(d.expected.clone()),
        fd_table: Vec::new(),
        payload: Value::Null,
    }
}
fn stop_candidate(c: &mut Catalog, m: &Machine, d: &Decision, op: &Operation) -> Result<()> {
    let mut r = request(m, d);
    r.payload = json!({"expected_revision":op.revision});
    let outcome = if d.kind == "standby" {
        crate::native_operations::cancel(c, &r, r.payload()?)
    } else {
        crate::managed_fork::cancel(c, &r, r.payload()?)
    };
    match outcome {
        Err(e)
            if matches!(
                e.code,
                "E_OPERATION_HAS_EFFECTS" | "E_ALREADY_COMMITTED" | "E_STALE_REVISION"
            ) =>
        {
            Ok(())
        }
        result => result.map(|_| ()),
    }
}
fn step(
    c: &mut Catalog,
    m: &Machine,
    d: &Decision,
    boot: &str,
    p: &pressure::Pressure,
) -> Result<()> {
    let id = &m.expected.instance_id;
    let op = match c.operation(&d.id) {
        Ok(op) => Some(op),
        Err(e) if e.code == "E_NOT_FOUND" => None,
        Err(e) => return Err(e),
    };
    if let Some(op) = op {
        if op.phase == "NEW" {
            if d.origin != "wake"
                && (d.rev != m.rev || m.demand(&c.db)? || m.policy.keep_running || m.seq != d.seq)
            {
                stop_candidate(c, m, d, &op)?;
            }
            c.db.execute(
                "UPDATE lifecycle_decisions SET stage='running' WHERE id=? AND stage!='running'",
                [&d.id],
            )?;
            if d.origin == "wake" {
                attach_more(&c.db, id, &d.id)?
            }
            return Ok(());
        }
        let ok = op.phase == "COMPLETED";
        let tx = c.db.transaction()?;
        tx.execute(
            "UPDATE lifecycle_decisions SET stage=?,finished_at=?,end_memory=?,error=? WHERE id=?",
            params![
                if ok { "completed" } else { "aborted" },
                wall()?,
                p.sample.slice_current.map(|v| v as i64),
                if ok {
                    None
                } else {
                    Some("native transition aborted")
                },
                d.id
            ],
        )?;
        if ok && d.origin == "wake" {
            tx.execute("UPDATE lifecycle_policies SET grace_until=?,idle_since=NULL,freeze_seq=NULL WHERE instance_id=?",
                params![monotonic()?+i64::from(m.policy.min_running_after_wake_seconds)*1000,id])?;
            tx.execute("UPDATE lifecycle_reports SET valid_until=0 WHERE instance_id=? AND collector='guest'",[id])?;
        } else if !ok {
            tx.execute(
                "UPDATE lifecycle_policies SET next_attempt=? WHERE instance_id=?",
                params![
                    monotonic()? + i64::from(m.policy.retry_backoff_seconds) * 1000,
                    id
                ],
            )?;
            tx.execute("UPDATE lifecycle_protections SET wake_operation=NULL,revision=revision+1 WHERE wake_operation=? AND kind='wake' AND state='pending'",[&d.id])?;
        }
        tx.commit()?;
        return Ok(());
    }
    let must_wake = m.demand(&c.db)?;
    let obs = observe(c, m, boot, monotonic()?)?;
    let invalidated = decision_changed(m, d, &obs)
        || (d.origin == "wake" && !must_wake)
        || (d.origin != "wake"
            && (d.origin == "pressure" && !p.eligible
                || d.kind == "hibernate"
                    && !can_save(
                        &c.db,
                        &m.expected,
                        crate::admission::unreserved_storage(&c.db)?,
                    )?));
    if invalidated {
        c.db.execute("UPDATE lifecycle_decisions SET stage='cancelled',finished_at=?,error='evidence changed before dispatch' WHERE id=?",params![wall()?,d.id])?;
        c.db.execute("UPDATE lifecycle_protections SET wake_operation=NULL,revision=revision+1 WHERE wake_operation=? AND kind='wake' AND state='pending'",[&d.id])?;
        return Ok(());
    }
    if d.origin == "pressure" && d.kind == "hibernate"
        && crate::resource_resize::pressure_hint::before_hibernate(c, boot, &d.expected, &d.id)?
    {
        return Ok(());
    }
    if d.stage == "queued" {
        c.db.execute(
            "UPDATE lifecycle_decisions SET stage='dispatching' WHERE id=?",
            [&d.id],
        )?;
    }
    let r = request(m, d);
    let outcome = match d.kind.as_str() {
        "standby" | "wake" => crate::native_operations::submit(
            c,
            boot,
            &r,
            serde_json::from_value(json!({"kind":d.kind})).map_err(invalid)?,
        ),
        "hibernate" => crate::managed_fork::submit(
            c,
            boot,
            &r,
            "hibernate",
            serde_json::from_value(json!({})).map_err(invalid)?,
        ),
        "vm_restore" => {
            let capture = m
                .saved(&c.db)?
                .ok_or_else(|| conflict("wake StatePoint is unavailable"))?;
            let name = m.name(&c.db)?;
            crate::managed_state_restore::submit(
                c,
                &r,
                serde_json::from_value(json!({"name":name,"capture_id":capture,"mode":"exact"}))
                    .map_err(invalid)?,
            )
        }
        "launch" => cold_launch(c, m, d, &r),
        _ => return Err(invalid("unexpected lifecycle decision")),
    };
    match outcome {
        Ok(_) => {
            c.db.execute(
                "UPDATE lifecycle_decisions SET stage='running' WHERE id=?",
                [&d.id],
            )?;
        }
        Err(e) => {
            let tx = c.db.transaction()?;
            tx.execute(
                "UPDATE lifecycle_decisions SET stage='aborted',finished_at=?,error=? WHERE id=?",
                params![wall()?, e.message, d.id],
            )?;
            tx.execute(
                "UPDATE lifecycle_policies SET last_error=?,next_attempt=? WHERE instance_id=?",
                params![
                    e.message,
                    monotonic()? + i64::from(m.policy.retry_backoff_seconds) * 1000,
                    id
                ],
            )?;
            tx.execute("UPDATE lifecycle_protections SET wake_operation=NULL,revision=revision+1 WHERE wake_operation=? AND kind='wake' AND state='pending'",[&d.id])?;
            tx.commit()?;
        }
    }
    Ok(())
}

fn cold_launch(c: &mut Catalog, m: &Machine, d: &Decision, request: &Request) -> Result<Operation> {
    let id = &m.expected.instance_id;
    let raw: Option<String> = if d.expected.execution_epoch == 0 {
        c.db.query_row("SELECT first_launch_json FROM lifecycle_protections WHERE instance_id=? AND wake_operation=?
            AND kind='wake' AND state='pending' AND first_launch_json IS NOT NULL ORDER BY rowid DESC LIMIT 1",
            params![id,d.id],|row|row.get(0)).optional()?
    } else {
        c.db.query_row("SELECT spec_json FROM managed_launches m JOIN operations o USING(operation_id)
            WHERE o.instance_id=? AND o.phase='COMPLETED' ORDER BY o.expected_execution_epoch DESC LIMIT 1",
            [id],|row|row.get(0)).optional()?
    };
    let raw = raw.ok_or_else(|| conflict("the authorized cold wake has no launch plan"))?;
    crate::managed::submit(c, request, serde_json::from_str(&raw).map_err(invalid)?)
}

fn attach_more(db: &Connection, machine: &str, op: &str) -> Result<()> {
    db.execute("UPDATE lifecycle_protections SET wake_operation=?,revision=revision+1 WHERE instance_id=? AND kind='wake' AND state='pending'
                AND wake_operation IS NULL",params![op,machine])?;
    Ok(())
}
impl Controller {
    pub(crate) fn tick(&mut self, c: &mut Catalog, boot: &str) -> Result<()> {
        protections::expire(&c.db)?;
        let p = pressure::refresh(&c.db, &mut self.cache_reclaim)?;
        let ids = {
            let mut q=c.db.prepare("SELECT instance_id FROM lifecycle_policies ORDER BY json_extract(policy_json,'$.reclaim_priority'),idle_since,instance_id")?;
            let rows = q
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut pressure_inflight:bool=c.db.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_decisions WHERE origin='pressure' AND stage IN ('queued','dispatching','running'))",[],|r|r.get(0))?;
        for id in ids {
            match self.machine(c, &id, boot, &p, &mut pressure_inflight) {
                Ok(()) => (),
                Err(e) => {
                    c.db.execute("UPDATE lifecycle_policies SET last_error=? WHERE instance_id=? AND last_error IS NOT ?",params![e.message,id,e.message])?;
                }
            }
        }
        Ok(())
    }
    fn machine(
        &self,
        c: &mut Catalog,
        id: &str,
        boot: &str,
        p: &pressure::Pressure,
        pressure_inflight: &mut bool,
    ) -> Result<()> {
        let m = Machine::load(c, id)?;
        if let Some(d) = pending(&c.db, id)? {
            return step(c, &m, &d, boot, p);
        }
        let now = monotonic()?;
        let new_epoch=c.db.execute("UPDATE lifecycle_policies SET last_incarnation=?,grace_until=?,idle_since=NULL,freeze_seq=NULL,activity_seq=activity_seq+1
            WHERE instance_id=? AND last_incarnation IS NOT ?",params![m.expected.incarnation_id,now+i64::from(m.policy.min_running_after_wake_seconds)*1000,id,m.expected.incarnation_id])?;
        if new_epoch > 0 {
            return Ok(());
        }
        let obs = observe(c, &m, boot, now)?;
        let demand = m.demand(&c.db)?;
        if let Some(active) = &m.active {
            // A pending access may race an explicitly requested hibernate as well.
            if demand {
                let op = c.operation(active)?;
                if op.kind == "hibernate" && op.phase == "NEW" {
                    let mut req = crate::managed_statepoint::request(
                        &op,
                        json!({"expected_revision":op.revision}),
                    );
                    req.method = "CancelNativeOperation".into();
                    if let Err(e) = crate::managed_fork::cancel(c, &req, req.payload()?) {
                        if !matches!(e.code, "E_OPERATION_HAS_EFFECTS" | "E_ALREADY_COMMITTED") {
                            return Err(e);
                        }
                    }
                }
            }
            return Ok(());
        }
        if demand && now >= m.next {
            let unbound:bool=c.db.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_protections WHERE instance_id=? AND kind='wake' AND state='pending' AND wake_operation IS NULL)",[id],|r|r.get(0))?;
            let kind = match obs.power.as_str() {
                "RUNNING" if unbound => Some("authorize_access"),
                "STANDBY" => Some("wake"),
                "HIBERNATED" => Some("vm_restore"),
                "STOPPED" if m.policy.wake_conditions.allow_cold_start => Some("launch"),
                _ => None,
            };
            if let Some(kind) = kind {
                return record(c, &m, kind, "wake", &obs, p.sample.slice_current);
            }
        }
        if !obs.blockers.is_empty() || !matches!(obs.power.as_str(), "RUNNING" | "STANDBY") {
            c.db.execute("UPDATE lifecycle_policies SET idle_since=NULL,freeze_seq=NULL WHERE instance_id=? AND (idle_since IS NOT NULL OR freeze_seq IS NOT NULL)",[id])?;
            return Ok(());
        }
        let since = m.idle.unwrap_or(now);
        if m.idle.is_none() {
            c.db.execute(
                "UPDATE lifecycle_policies SET idle_since=? WHERE instance_id=?",
                params![since, id],
            )?;
        }
        if now < m.grace || now < m.next {
            return Ok(());
        }
        let idle_ms = now.saturating_sub(since);
        let (standby, hibernate) = idle_deadlines(&m, &obs, since);
        let pressure = p.eligible
            && !*pressure_inflight
            && m.policy.pressure_reclaim == "idle_only"
            && idle_ms >= 1_000;
        if m.policy.auto_hibernate
            && (hibernate.is_some_and(|deadline| deadline <= now) || pressure)
        {
            if can_save(&c.db, &m.expected, p.sample.disk_available)? {
                record(
                    c,
                    &m,
                    "hibernate",
                    if pressure { "pressure" } else { "idle" },
                    &obs,
                    p.sample.slice_current,
                )?;
                *pressure_inflight |= pressure;
            }
        } else if standby.is_some_and(|deadline| deadline <= now) {
            record(c, &m, "standby", "idle", &obs, p.sample.slice_current)?;
        }
        Ok(())
    }
}
