//! Single Worker owner for automatic lifecycle decisions and access protection.
mod policy;
mod pressure;
pub(crate) mod protections;
mod scheduler;
use crate::catalog::Catalog;
use crate::ipc::{valid_id, Expected, Fault, Request, Result};
use policy::Policy;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) use pressure::check_admission;
pub(crate) use scheduler::Controller;
const COLLECTORS: [&str; 3] = ["guest", "host", "platform"];

fn clock_ms(clock: libc::clockid_t) -> Result<i64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(clock, &mut ts) } != 0 {
        return Err(Fault::new("E_HOST_IO", "cannot read lifecycle clock"));
    }
    Ok(ts
        .tv_sec
        .saturating_mul(1000)
        .saturating_add(ts.tv_nsec / 1_000_000))
}
pub(crate) fn monotonic() -> Result<i64> {
    clock_ms(libc::CLOCK_BOOTTIME)
}
fn wall() -> Result<i64> {
    clock_ms(libc::CLOCK_REALTIME)
}
fn changed(detail: &str) -> Fault {
    Fault::new("E_STALE_REVISION", detail)
}
fn conflict(detail: &str) -> Fault {
    Fault::new("E_STATE_CONFLICT", detail)
}
fn invalid(e: impl ToString) -> Fault {
    Fault::invalid(e.to_string())
}

pub(crate) fn recover(db: &Connection) -> Result<()> {
    db.execute("UPDATE lifecycle_reports SET valid_until=0", [])?;
    db.execute("UPDATE lifecycle_policies SET idle_since=NULL,freeze_seq=NULL,last_incarnation=NULL,grace_until=0,next_attempt=0,activity_seq=activity_seq+1",[])?;
    db.execute("UPDATE lifecycle_protections SET state='suspect',revision=revision+1 WHERE kind='hold' AND state='active'",[])?;
    Ok(())
}

pub(crate) fn confirm_native(db: &Connection, operation: &str, disposition: &str) -> Result<()> {
    let now = monotonic()?;
    if disposition == "STANDBY" {
        db.execute("UPDATE lifecycle_policies AS p SET freeze_seq=activity_seq,
            freeze_session=(SELECT session FROM native_transitions WHERE operation_id=?1)
            WHERE p.instance_id=(SELECT instance_id FROM operations WHERE operation_id=?1)
            AND EXISTS(SELECT 1 FROM native_transitions n JOIN lifecycle_reports r ON r.incarnation_id=n.incarnation_id
                WHERE n.operation_id=?1 AND n.mode='managed' AND r.instance_id=p.instance_id AND r.collector='guest'
                AND r.valid_until>=?2 AND r.busy_json='[]')",params![operation,now])?;
    } else if disposition == "RUNNING" {
        db.execute("UPDATE lifecycle_policies SET idle_since=NULL,freeze_seq=NULL,freeze_session=NULL,
            grace_until=?2+1000*json_extract(policy_json,'$.min_running_after_wake_seconds'),activity_seq=activity_seq+1
            WHERE instance_id=(SELECT instance_id FROM operations WHERE operation_id=?1)",params![operation,now])?;
        db.execute(
            "UPDATE lifecycle_reports SET valid_until=0 WHERE collector='guest' AND incarnation_id=
            (SELECT incarnation_id FROM native_transitions WHERE operation_id=?)",
            [operation],
        )?;
    }
    Ok(())
}

pub(crate) fn row_policy(db: &Connection, id: &str) -> Result<(i64, Policy)> {
    let (rev, raw): (i64, String) = db
        .query_row(
            "SELECT revision,policy_json FROM lifecycle_policies WHERE instance_id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| Fault::new("E_NOT_FOUND", "no applied lifecycle policy"))?;
    Ok((rev, serde_json::from_str(&raw).map_err(invalid)?))
}

pub(crate) fn binding(c: &Catalog, r: &Request) -> Result<(Expected, Option<String>)> {
    let (route, _, expected) = r.scope()?;
    if route != "deep" {
        return Err(invalid("lifecycle owner requires the deep route"));
    }
    let row =
        c.query_binding(&r.derived("QueryBinding", json!({"instance_id":expected.instance_id})))?;
    let actual = Expected {
        instance_id: expected.instance_id.clone(),
        incarnation_id: row["incarnation_id"].as_str().map(str::to_owned),
        execution_epoch: row["execution_epoch"]
            .as_i64()
            .ok_or_else(|| invalid("missing binding epoch"))?,
    };
    Ok((
        actual,
        row["active_operation_id"].as_str().map(str::to_owned),
    ))
}
fn bump(tx: &Transaction<'_>, id: &str, reset_idle: bool) -> Result<()> {
    tx.execute(
        "UPDATE lifecycle_policies SET activity_seq=activity_seq+1,
        idle_since=CASE WHEN ? THEN NULL ELSE idle_since END WHERE instance_id=?",
        params![reset_idle, id],
    )?;
    tx.execute("UPDATE lifecycle_decisions SET stage='cancelled',finished_at=?,error='new activity or policy'
        WHERE instance_id=? AND stage='queued' AND origin<>'wake'",params![wall()?,id])?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apply {
    expected_applied_revision: i64,
    new_revision: i64,
    effective_policy: Policy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    collector: String,
    session: String,
    seq: i64,
    valid_for_ms: i64,
    #[serde(default)]
    supersedes: Option<String>,
    counts: BTreeMap<String, Option<i64>>,
}
fn apply(tx: &Transaction<'_>, r: &Request, instance: &str, bundle: &str) -> Result<Value> {
    let input: Apply = r.payload()?;
    input.effective_policy.validate()?;
    let previous: Option<(i64, String)> = tx
        .query_row(
            "SELECT revision,bundle_digest FROM lifecycle_policies WHERE instance_id=?",
            [instance],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let revision = previous.as_ref().map_or(0, |p| p.0);
    if previous.as_ref().is_some_and(|p| p.1 != bundle)
        || revision != input.expected_applied_revision
        || input.new_revision
            != revision
                .checked_add(1)
                .ok_or_else(|| invalid("policy revision exhausted"))?
    {
        return Err(changed("applied lifecycle revision changed"));
    }
    let encoded = serde_json::to_string(&input.effective_policy).map_err(invalid)?;
    let until =
        monotonic()? + i64::from(input.effective_policy.min_running_after_wake_seconds) * 1000;
    tx.execute("INSERT INTO lifecycle_policies(instance_id,bundle_digest,revision,policy_json,grace_until)VALUES(?,?,?,?,?)
        ON CONFLICT(instance_id) DO UPDATE SET revision=excluded.revision,policy_json=excluded.policy_json",
        params![instance,bundle,input.new_revision,encoded,until])?;
    tx.execute(
        "UPDATE lifecycle_reports SET valid_until=0 WHERE instance_id=?",
        [instance],
    )?;
    tx.execute(
        "UPDATE lifecycle_policies SET freeze_seq=NULL WHERE instance_id=?",
        [instance],
    )?;
    bump(tx, instance, false)?;
    Ok(
        json!({"instance_id":instance,"applied_revision":input.new_revision,"effective_policy":input.effective_policy}),
    )
}

fn report(tx: &Transaction<'_>, r: &Request, expected: &Expected) -> Result<Value> {
    let input: Report = r.payload()?;
    let inc = expected
        .incarnation_id
        .as_ref()
        .ok_or_else(|| conflict("activity requires a current execution"))?;
    if !COLLECTORS.contains(&input.collector.as_str())
        || !valid_id(&input.session)
        || input.seq < 1
        || !(250..=120_000).contains(&input.valid_for_ms)
        || input.counts.values().flatten().any(|v| *v < 0)
    {
        return Err(invalid("invalid collector scope, counters or freshness"));
    }
    let required: &[&str] = match input.collector.as_str() {
        "guest" => &["task", "exec", "inbound", "outbound"],
        "platform" => &["task", "exec", "stream"],
        _ => &["inbound", "outbound"],
    };
    if required.iter().any(|k| !input.counts.contains_key(*k))
        || input.counts.keys().any(|key| {
            !required.contains(&key.as_str())
                && !(input.collector == "platform" && key == "legacy_lease")
        })
    {
        return Err(invalid(
            "activity report must describe the complete collector scope",
        ));
    }
    let previous:Option<(String,i64,String)>=tx.query_row("SELECT session,seq,incarnation_id FROM lifecycle_reports WHERE instance_id=? AND collector=?",
        params![expected.instance_id,input.collector],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if let Some((session, seq, previous_inc)) = &previous {
        if session == &input.session && (input.seq <= *seq || previous_inc != inc) {
            return Err(changed("collector sequence or execution changed"));
        }
        if session != &input.session
            && previous_inc == inc
            && input.supersedes.as_ref() != Some(session)
        {
            return Err(changed("collector replacement requires its predecessor"));
        }
    }
    if previous.as_ref().is_none_or(|p| p.0 != input.session)
        && tx.execute(
            "INSERT OR IGNORE INTO lifecycle_sessions VALUES(?,?,?)",
            params![expected.instance_id, input.collector, input.session],
        )? != 1
    {
        return Err(changed("collector session has been retired"));
    }
    let (_, policy) = row_policy(tx, &expected.instance_id)?;
    let mut blockers = Vec::new();
    for (kind, count) in input.counts {
        match count {
            None => blockers.push(format!("unknown:{kind}")),
            Some(n) if n > 0 && policy.protects(&kind) => blockers.push(kind),
            _ => (),
        }
    }
    let valid = monotonic()? + input.valid_for_ms;
    let busy = serde_json::to_string(&blockers).map_err(invalid)?;
    let prior: Option<String> = tx
        .query_row(
            "SELECT busy_json FROM lifecycle_reports WHERE instance_id=? AND collector=?",
            params![expected.instance_id, input.collector],
            |r| r.get(0),
        )
        .optional()?;
    tx.execute("INSERT INTO lifecycle_reports VALUES(?,?,?,?,?,?,?) ON CONFLICT(instance_id,collector)
        DO UPDATE SET incarnation_id=excluded.incarnation_id,session=excluded.session,seq=excluded.seq,valid_until=excluded.valid_until,busy_json=excluded.busy_json",
        params![expected.instance_id,inc,input.collector,input.session,input.seq,valid,busy])?;
    if !blockers.is_empty() || prior.as_deref() != Some(busy.as_str()) {
        bump(tx, &expected.instance_id, !blockers.is_empty())?
    }
    Ok(
        json!({"instance_id":expected.instance_id,"incarnation_id":inc,"collector":input.collector,"session":input.session,"seq":input.seq,"blockers":blockers}),
    )
}

pub(crate) fn handle(c: &mut Catalog, r: &Request) -> Result<Value> {
    let (_, bundle, expected) = r.scope()?;
    if r.method == "QueryLifecycleEvents" {
        let (actual, _) = binding(c, r)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Since {
            after: i64,
        }
        let since: Since = r.payload()?;
        if since.after < 0 {
            return Err(invalid("negative event cursor"));
        }
        let mut q=c.db.prepare("SELECT seq,decision_id,kind,origin,stage,occurred_at,error FROM lifecycle_events WHERE instance_id=? AND seq>? ORDER BY seq LIMIT 100")?;
        let rows=q.query_map(params![actual.instance_id,since.after],|r|Ok(json!({"seq":r.get::<_,i64>(0)?,"operation_id":r.get::<_,String>(1)?,
            "kind":r.get::<_,String>(2)?,"origin":r.get::<_,String>(3)?,"stage":r.get::<_,String>(4)?,"occurred_at_ms":r.get::<_,i64>(5)?,"error":r.get::<_,Option<String>>(6)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        return Ok(json!({"events":rows}));
    }
    if r.method == "GetLifecycleStatus" {
        let (actual, _) = binding(c, r)?;
        return scheduler::status(c, &actual);
    }
    if r.method == "QueryProtection" {
        let (actual, _) = binding(c, r)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Query {
            protection_id: String,
            principal: String,
        }
        let input: Query = r.payload()?;
        let owner: Option<String> =
            c.db.query_row(
                "SELECT principal FROM lifecycle_protections WHERE instance_id=? AND id=?",
                params![actual.instance_id, input.protection_id],
                |r| r.get(0),
            )
            .optional()?;
        if owner.as_ref() != Some(&input.principal) {
            return Err(Fault::new("E_NOT_FOUND", "protection not found"));
        }
        return protections::receipt(&c.db, &actual.instance_id, &input.protection_id);
    }
    let (id, digest) = r.operation()?;
    let scope = json!([r.method, r.route_id, bundle, expected, r.payload, digest]);
    let fingerprint = format!("sha256:{:x}", Sha256::digest(scope.to_string()));
    // Take the WAL writer before reading the binding and request receipt. A
    // concurrent native state transition must serialize with this decision.
    let tx = Transaction::new_unchecked(&c.db, TransactionBehavior::Immediate)?;
    let (actual, _) = binding(c, r)?;
    if let Some((prior, answer)) = tx
        .query_row(
            "SELECT digest,reply FROM lifecycle_requests WHERE instance_id=? AND request_id=?",
            params![expected.instance_id, id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()?
    {
        if prior != fingerprint {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "lifecycle request changed",
            ));
        }
        return serde_json::from_str(&answer).map_err(invalid);
    }
    if actual != *expected
        && !matches!(
            r.method.as_str(),
            "ApplyLifecyclePolicy" | "CloseAccessProtection"
        )
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "lifecycle request refers to a different execution",
        ));
    }
    if r.method != "ApplyLifecyclePolicy" {
        row_policy(&tx, &expected.instance_id)?;
    }
    let reply = match r.method.as_str() {
        "ApplyLifecyclePolicy" => apply(&tx, r, &expected.instance_id, bundle)?,
        "ReportActivity" => report(&tx, r, expected)?,
        _ => protections::mutate(&tx, r, expected)?,
    };
    tx.execute(
        "INSERT INTO lifecycle_requests VALUES(?,?,?,?)",
        params![expected.instance_id, id, fingerprint, reply.to_string()],
    )?;
    tx.commit()?;
    Ok(reply)
}
