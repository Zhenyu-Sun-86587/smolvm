//! Durable Worker-owned transitions on a single registered VMM.
use crate::catalog::{Catalog, Operation};
use crate::ipc::{Fault, Request, Result};
use crate::native_control::{actor_db, Endpoint};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::time::{Duration, Instant};
use std::{collections::HashMap, io, thread};

#[derive(Debug, Serialize, Deserialize)]
pub struct Progress {
    pub stage: String,
    pub mode: String,
    pub source_disposition: String,
    pub last_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    kind: String,
    #[serde(default)]
    parameters: Parameters,
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    mode: Option<String>,
}

pub(crate) fn progress(db: &Connection, id: &str) -> Result<Option<Progress>> {
    Ok(db
        .query_row(
            "SELECT stage,mode,disposition,last_error FROM native_transitions WHERE operation_id=?",
            [id],
            |r| {
                Ok(Progress {
                    stage: r.get(0)?,
                    mode: r.get(1)?,
                    source_disposition: r.get(2)?,
                    last_error: r.get(3)?,
                })
            },
        )
        .optional()?)
}
fn unsupported(message: &str) -> Fault {
    Fault::new("E_CAPABILITY_UNSUPPORTED", message)
}
fn nonce() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| Fault::new("E_HOST_IO", "failed to generate native control challenge"))?;
    Ok(hex::encode(bytes))
}
struct Session {
    number: u32,
    token: String,
    anchor: String,
    network: bool,
    mode: String,
}
impl Session {
    fn scope(&self) -> String {
        format!("{} {}", self.number, self.token)
    }
}
fn session(row: &rusqlite::Row, offset: usize) -> rusqlite::Result<Session> {
    Ok(Session {
        number: row.get(offset)?,
        token: row.get(offset + 1)?,
        anchor: row.get(offset + 2)?,
        network: row.get(offset + 3)?,
        mode: row.get(offset + 4)?,
    })
}

pub fn submit(catalog: &mut Catalog, boot: &str, r: &Request, input: Input) -> Result<Operation> {
    let (id, _) = r.operation()?;
    let (route, _, expected) = r.scope()?;
    if route != "deep" {
        return Err(unsupported(
            "native operations require the deep runtime route",
        ));
    }
    let incarnation = expected
        .incarnation_id
        .as_deref()
        .ok_or_else(|| Fault::invalid("native operation requires a live incarnation"))?;
    let mode = match (input.kind.as_str(), input.parameters.mode.as_deref()) {
        ("standby", None | Some("managed")) => "managed",
        ("standby", Some("raw")) => "raw",
        ("wake", None) => "",
        ("standby" | "wake", _) => {
            return Err(Fault::invalid("unsupported native transition parameters"))
        }
        _ => {
            return Err(unsupported(
                "no verified native handler for this operation kind",
            ))
        }
    };
    if let Some(previous) = progress(&catalog.db, id)? {
        if input.kind == "standby" && previous.mode != mode {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "native operation mode changed",
            ));
        }
        catalog.begin(r, &input.kind)?;
        return catalog.operation(id);
    }
    if catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id=?)",
        [id],
        |r| r.get::<_, bool>(0),
    )? {
        return Err(Fault::new(
            "E_IDEMPOTENCY_CONFLICT",
            "operation ID belongs to a different handler",
        ));
    }
    let registered = catalog.execution(incarnation)?;
    if !registered.matches(
        route,
        r.bundle_digest.as_deref().unwrap_or_default(),
        expected,
    ) {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "native operation scope changed",
        ));
    }
    let endpoint = Endpoint::load(&catalog.db, incarnation, boot)?;
    let observed = endpoint.inventory()?;
    if let Err(fault) = catalog.ready() {
        if fault.code != "E_RECOVERING" {
            return Err(fault);
        }
        let broker: String =
            catalog
                .db
                .query_row("SELECT broker_session_id FROM worker_state", [], |r| {
                    r.get(0)
                })?;
        catalog.complete_recovery(&broker)?;
    }
    let binding = if input.kind == "wake" {
        let s=catalog.db.query_row("SELECT n.session,n.token,n.anchor,n.network_gate,n.mode FROM native_standby p JOIN native_transitions n USING(operation_id) WHERE p.incarnation_id=?",[incarnation],|r|session(r,0)).optional()?
            .ok_or_else(||Fault::new("E_STATE_CONFLICT","execution has no Worker-owned standby"))?;
        if observed.source_disposition != "STANDBY" {
            return Err(Fault::new(
                "E_STATE_CONFLICT",
                "native VMM is outside the recorded standby",
            ));
        }
        s
    } else {
        if observed.source_disposition != "RUNNING" {
            return Err(Fault::new("E_STATE_CONFLICT", "source is not running"));
        }
        if mode == "managed" && !observed.measured_helper {
            return Err(unsupported(
                "managed standby requires an installed measured helper",
            ));
        }
        let latest: u32 = catalog.db.query_row(
            "SELECT coalesce(max(session),0) FROM native_transitions WHERE incarnation_id=?",
            [incarnation],
            |r| r.get(0),
        )?;
        let network = observed.devices.iter().any(|d| d["virtio_type"] == 1);
        if mode == "managed"
            && observed
                .devices
                .iter()
                .any(|d| d["virtio_type"] == 1 && d["tap"].is_null())
        {
            return Err(unsupported("managed network standby requires a Worker TAP"));
        }
        Session {
            number: latest
                .max(observed.last_session)
                .checked_add(1)
                .ok_or_else(|| Fault::invalid("native session exhausted"))?,
            token: nonce()?,
            anchor: nonce()?,
            mode: mode.into(),
            network,
        }
    };
    catalog.begin_with(r,&input.kind,|tx|{
        tx.execute("INSERT INTO native_transitions(operation_id,incarnation_id,mode,session,token,anchor,network_gate,stage,disposition)
            VALUES(?,?,?,?,?,?,?,'accepted',?)",params![id,incarnation,binding.mode,binding.number,binding.token,binding.anchor,binding.network,observed.source_disposition])?;
        Ok(())
    })?;
    catalog.operation(id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    expected_revision: i64,
}

pub fn cancel(catalog: &mut Catalog, r: &Request, cancel: Cancel) -> Result<Operation> {
    let op = catalog.matching_operation(r)?;
    let (_, _, expected) = r.scope()?;
    if op.expected_incarnation_id != expected.incarnation_id
        || op.expected_execution_epoch != expected.execution_epoch
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "cancellation targets a different incarnation",
        ));
    }
    let id = &op.operation_id;
    let tx = catalog
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = progress(&tx, id)?
        .ok_or_else(|| unsupported("operation has no native cancellation handler"))?;
    if current.stage == "aborted" || current.stage == "aborting" {
        drop(tx);
        return catalog.operation(id);
    }
    let revision: i64 = tx.query_row(
        "SELECT revision FROM operations WHERE operation_id=?",
        [id],
        |r| r.get(0),
    )?;
    if revision != cancel.expected_revision {
        return Err(Fault::new(
            "E_STALE_REVISION",
            "native operation revision changed",
        ));
    }
    match current.stage.as_str() {
        "accepted" => {
            finish(&tx, id, false, &current.source_disposition, None)?;
        }
        "preparing" | "parking" => {
            advance(&tx, id, "aborting", "UNKNOWN")?;
        }
        _ => {
            return Err(Fault::new(
                "E_ALREADY_COMMITTED",
                "native operation already crossed its cancellation boundary",
            ))
        }
    }
    tx.commit()?;
    catalog.operation(id)
}

fn advance(db: &Connection, id: &str, stage: &str, disposition: &str) -> Result<()> {
    db.execute(
        "UPDATE native_transitions SET stage=?,disposition=?,last_error=NULL WHERE operation_id=?",
        params![stage, disposition, id],
    )?;
    db.execute(
        "UPDATE operations SET revision=revision+1 WHERE operation_id=?",
        [id],
    )?;
    Ok(())
}

fn finish(
    db: &Connection,
    id: &str,
    success: bool,
    disposition: &str,
    error: Option<&str>,
) -> Result<()> {
    advance(
        db,
        id,
        if success { "complete" } else { "aborted" },
        disposition,
    )?;
    if let Some(error) = error {
        db.execute(
            "UPDATE native_transitions SET last_error=? WHERE operation_id=?",
            params![error, id],
        )?;
    }
    if success && disposition == "STANDBY" {
        db.execute("INSERT INTO native_standby(incarnation_id,operation_id) SELECT incarnation_id,operation_id FROM native_transitions WHERE operation_id=?",[id])?;
    }
    if success && disposition == "RUNNING" {
        db.execute("DELETE FROM native_standby WHERE incarnation_id=(SELECT incarnation_id FROM native_transitions WHERE operation_id=?)",[id])?;
    }
    db.execute(
        "UPDATE operations SET phase=?,decision=? WHERE operation_id=? AND phase='NEW'",
        params![
            if success { "COMPLETED" } else { "ABORTED" },
            if success { "NONE" } else { "ABORT" },
            id
        ],
    )?;
    db.execute(
        "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
        [id],
    )?;
    Ok(())
}

enum Next<'a> {
    Again,
    Advance(&'a str, &'a str),
    Finish(bool, &'a str, Option<String>),
}
struct Transition {
    id: String,
    kind: String,
    incarnation: String,
    stage: String,
    session: Session,
}
impl Transition {
    fn load(db: &Connection, id: &str) -> Result<Self> {
        Ok(db.query_row("SELECT o.kind,n.incarnation_id,n.stage,n.session,n.token,n.anchor,n.network_gate,n.mode
            FROM operations o JOIN native_transitions n USING(operation_id) WHERE operation_id=?",[id],
            |r|Ok(Self{id:id.to_owned(),kind:r.get(0)?,incarnation:r.get(1)?,stage:r.get(2)?,session:session(r,3)?}))?)
    }
    fn gate(&self, ep: &Endpoint, verb: &str, tail: &str) -> Result<(String, i32)> {
        let result = ep.command(&format!(
            "GUEST_GATE_{verb} {} {tail}",
            self.session.scope()
        ))?;
        let fields: Vec<_> = result.split_ascii_whitespace().collect();
        if fields.len() != 4
            || fields[0].parse::<u32>() != Ok(self.session.number)
            || fields[1] != self.session.token
        {
            return Err(Fault::new(
                "E_PROTOCOL_UNSUPPORTED",
                "Guest gate returned a different session",
            ));
        }
        let error = fields[3]
            .parse()
            .map_err(|_| Fault::invalid("invalid Guest gate error"))?;
        Ok((fields[2].into(), error))
    }
    fn step(&self, ep: &Endpoint) -> Result<Next<'static>> {
        let s = &self.session;
        if self.stage == "accepted" {
            return Ok(match (self.kind.as_str(), s.mode.as_str()) {
                ("wake", _) => Next::Advance("waking", "STANDBY"),
                ("standby", "managed") => Next::Advance("preparing", "RUNNING"),
                ("standby", "raw") => Next::Advance("entering", "UNKNOWN"),
                _ => return Err(unsupported("unknown native operation")),
            });
        }
        if matches!(self.stage.as_str(), "preparing" | "parking" | "aborting") {
            let (phase, error) = match self.stage.as_str() {
                "preparing" => self.gate(ep, "PREPARE", "2500 15000")?,
                "parking" => {
                    let state = self.gate(ep, "QUERY", "")?;
                    if state.0 == "armed" {
                        self.gate(
                            ep,
                            if s.network { "PARK_NETWORK" } else { "PARK" },
                            &s.anchor,
                        )?
                    } else {
                        state
                    }
                }
                _ => {
                    let state = match self.gate(ep, "QUERY", "") {
                        Err(fault)
                            if fault.code == "E_NATIVE_REFUSED"
                                && fault.message.starts_with("ESTALE ") =>
                        {
                            let inventory = ep.inventory()?;
                            if inventory.last_session < s.number
                                && inventory.source_disposition == "RUNNING"
                            {
                                return Ok(Next::Finish(false, "RUNNING", None));
                            }
                            return Err(fault);
                        }
                        result => result?,
                    };
                    if matches!(state.0.as_str(), "preparing" | "armed" | "parked") {
                        self.gate(ep, "ABORT", "")?
                    } else {
                        state
                    }
                }
            };
            return Ok(match (self.stage.as_str(), phase.as_str()) {
                (_, "expired_thawed" | "failed_thawed") => Next::Finish(
                    false,
                    "RUNNING",
                    Some(format!("Guest gate {phase} ({error})")),
                ),
                ("aborting", "aborted") => Next::Finish(false, "RUNNING", None),
                ("preparing", "armed") => Next::Advance("parking", "GUEST_HELD"),
                ("parking", "parked") => Next::Advance("entering", "GUEST_HELD"),
                (_, "preparing" | "parking" | "aborting") => Next::Again,
                _ => {
                    return Err(Fault::new(
                        "E_NATIVE_UNAVAILABLE",
                        format!("unexpected Guest gate state {phase} ({error})"),
                    ))
                }
            });
        }
        let command = match self.stage.as_str() {
            "entering" => format!("STANDBY_ENTER {} {}", s.scope(), s.mode),
            "waking" => format!("STANDBY_WAKE {}", s.scope()),
            _ => return Err(unsupported("unknown native operation stage")),
        };
        let receipt: Value = serde_json::from_str(&ep.command(&command)?)
            .map_err(|_| Fault::invalid("invalid VMM standby receipt"))?;
        if receipt["protocol"] != "CaptureControl/1"
            || receipt["session"] != s.number
            || receipt["hold_token"] != s.token
            || receipt["mode"] != s.mode
        {
            return Err(Fault::new(
                "E_PROTOCOL_UNSUPPORTED",
                "VMM receipt belongs to a different transition",
            ));
        }
        Ok(
            match (self.stage.as_str(), receipt["source_disposition"].as_str()) {
                ("entering", Some("STANDBY")) => Next::Finish(true, "STANDBY", None),
                ("waking", Some("RUNNING")) => Next::Finish(true, "RUNNING", None),
                ("waking", Some("WAKING")) => Next::Again,
                _ => {
                    return Err(Fault::new(
                        "E_NATIVE_UNAVAILABLE",
                        "VMM could not confirm its source disposition",
                    ))
                }
            },
        )
    }
    fn drive(&self, db: &mut Connection, boot: &str) -> Result<bool> {
        let endpoint = Endpoint::load(db, &self.incarnation, boot)?;
        let outcome = self.step(&endpoint)?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            progress(&tx, &self.id)?.ok_or_else(|| Fault::invalid("missing transition"))?;
        if current.stage != self.stage {
            return Ok(true);
        } // Concurrent cancellation has its own reconciliation.
        match outcome {
            Next::Again => return Ok(false),
            Next::Advance(phase, state) => advance(&tx, &self.id, phase, state)?,
            Next::Finish(success, state, error) => {
                finish(&tx, &self.id, success, state, error.as_deref())?
            }
        }
        tx.commit()?;
        Ok(true)
    }
}

fn pending(db: &Connection) -> Result<Vec<String>> {
    let mut query=db.prepare("SELECT operation_id FROM native_transitions WHERE stage NOT IN ('complete','aborted') ORDER BY rowid")?;
    let ids = query
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(ids)
}
fn run(mut db: Connection, boot: String, signals: Receiver<()>) {
    let mut retry = HashMap::<String, Instant>::new();
    loop {
        let mut wait = Duration::from_secs(1);
        match pending(&db) {
            Ok(ids) => {
                for id in ids {
                    if retry.get(&id).is_some_and(|at| *at > Instant::now()) {
                        continue;
                    }
                    let attempt = Transition::load(&db, &id).and_then(|t| t.drive(&mut db, &boot));
                    match attempt {
                        Ok(progress) => {
                            retry.remove(&id);
                            wait = wait.min(if progress {
                                Duration::ZERO
                            } else {
                                Duration::from_millis(15)
                            })
                        }
                        Err(fault) => {
                            // An uncertain reply never releases the operation slot.
                            // Retrying the same token observes the original decision.
                            let detail = format!("{}: {}", fault.code, fault.message);
                            let _=db.execute("UPDATE native_transitions SET last_error=?,disposition='UNKNOWN' WHERE operation_id=? AND stage NOT IN ('complete','aborted') AND last_error IS NOT ?",params![detail,id,detail]);
                            retry.insert(id, Instant::now() + Duration::from_secs(1));
                        }
                    }
                }
            }
            Err(error) => eprintln!("native transition journal: {error}"),
        }
        if signals.recv_timeout(wait) == Err(std::sync::mpsc::RecvTimeoutError::Disconnected) {
            return;
        }
    }
}
pub(crate) fn start(path: &Path, boot: &str) -> io::Result<SyncSender<()>> {
    let db = actor_db(path)?;
    let (tx, rx) = sync_channel(1);
    let boot = boot.to_owned();
    thread::Builder::new()
        .name("native-operations".into())
        .spawn(move || run(db, boot, rx))?;
    Ok(tx)
}
