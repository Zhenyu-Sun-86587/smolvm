//! Access registrations, running leases and wake demands in the instance journal.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    protection_id: String,
    principal: String,
    reason: Option<String>,
    expected_revision: Option<i64>,
    semantics_version: Option<i64>,
    ttl_seconds: Option<i64>,
    token: Option<String>,
    trigger: Option<String>,
    expected_binding_revision: Option<i64>,
    authorization_revision: Option<i64>,
    endpoint_revision: Option<i64>,
    wake_operation: Option<String>,
    authorized: Option<bool>,
    first_launch: Option<crate::managed::Machine>,
}

pub(crate) fn revision(expected: &Expected) -> Result<i64> {
    expected
        .execution_epoch
        .checked_mul(2)
        .and_then(|v| v.checked_sub(i64::from(expected.incarnation_id.is_some())))
        .ok_or_else(|| invalid("binding revision exhausted"))
}

pub(super) fn expire(db: &Connection) -> Result<()> {
    let now = monotonic()?;
    db.execute("UPDATE lifecycle_protections SET state=CASE WHEN semantics=1 OR expires_boot<>(SELECT host_boot_id FROM worker_state) THEN 'suspect' ELSE 'released' END,
            reason=CASE WHEN semantics=1 THEN 'renewal overdue' WHEN expires_boot<>(SELECT host_boot_id FROM worker_state) THEN 'host boot changed' ELSE 'expired' END,
            revision=revision+1 WHERE kind='lease' AND state='active' AND (expires_at<=? OR expires_boot<>(SELECT host_boot_id FROM worker_state))",[now])?;
    Ok(())
}

fn valid_token(input: &Input) -> Result<String> {
    let token = input
        .token
        .as_deref()
        .ok_or_else(|| invalid("missing lease token"))?;
    if !(24..=256).contains(&token.len()) {
        return Err(invalid("invalid lease token length"));
    }
    Ok(format!("{:x}", Sha256::digest(token)))
}
fn deadline(input: &Input) -> Result<i64> {
    let ttl = input
        .ttl_seconds
        .filter(|n| (1..=86400 * 30).contains(n))
        .ok_or_else(|| invalid("invalid lease TTL"))?;
    Ok(monotonic()? + 1000 * ttl)
}

fn running_access(tx: &Transaction<'_>, route: &str, expected: &Expected) -> Result<bool> {
    let Some(incarnation) = expected.incarnation_id.as_deref() else {
        return Ok(false);
    };
    let changing: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM instance_bindings b JOIN operations o ON o.operation_id=b.active_operation_id
         WHERE b.instance_id=? AND o.kind IN ('standby','hibernate','stop','vm_rollback'))",
        [&expected.instance_id], |row| row.get(0))?;
    if changing
        || crate::managed_fork::source_is_pivoting(tx, route, &expected.instance_id, incarnation)?
    {
        return Ok(false);
    }
    let boot: String = tx.query_row("SELECT host_boot_id FROM worker_state", [], |row| {
        row.get(0)
    })?;
    let inventory = crate::native_control::Endpoint::load(tx, incarnation, &boot)?.inventory()?;
    Ok(inventory.source_disposition == "RUNNING")
}

pub(super) fn receipt(db: &Connection, instance: &str, id: &str) -> Result<Value> {
    let offset = wall()?.saturating_sub(monotonic()?);
    Ok(db.query_row("SELECT kind,state,revision,reason,incarnation_id,epoch,semantics,wake_operation,authorization_revision,endpoint_revision,expires_at
        FROM lifecycle_protections WHERE instance_id=? AND id=?",params![instance,id],|r|
        Ok(json!({"protection_id":id,"instance_id":instance,"kind":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?,"revision":r.get::<_,i64>(2)?,
            "reason":r.get::<_,String>(3)?,"incarnation_id":r.get::<_,Option<String>>(4)?,"execution_epoch":r.get::<_,i64>(5)?,
            "expires_at_unix_ms":r.get::<_,Option<i64>>(10)?.map(|d|d.saturating_add(offset)),"semantics_version":r.get::<_,i64>(6)?,"wake_operation":r.get::<_,Option<String>>(7)?,"authorization_revision":r.get::<_,Option<i64>>(8)?,
            "endpoint_revision":r.get::<_,Option<i64>>(9)?})))?)
}

pub(crate) fn mutate(tx: &Transaction<'_>, r: &Request, expected: &Expected) -> Result<Value> {
    let input: Input = r.payload()?;
    let machine = &expected.instance_id;
    let id = &input.protection_id;
    if !valid_id(id) || !valid_id(&input.principal) {
        return Err(invalid("invalid protection or principal identifier"));
    }
    expire(tx)?;
    let prior:Option<(String,i64,String,String,i64,Option<String>,Option<String>,Option<String>)>=tx.query_row(
        "SELECT kind,revision,state,principal,semantics,token_hash,incarnation_id,wake_operation FROM lifecycle_protections WHERE instance_id=? AND id=?",params![machine,id],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional()?;
    let (_, policy) = row_policy(tx, machine)?;
    let first_launch = if let Some(plan) = &input.first_launch {
        if r.method != "RequestWake" || expected.execution_epoch != 0 || expected.incarnation_id.is_some()
            || !matches!(input.trigger.as_deref(), Some("api_access" | "service_access"))
            || !policy.wake_conditions.allow_cold_start
            || plan.boot_profile != "system-debian-v1"
        {
            return Err(conflict("first launch requires an authorized cold wake on an empty System binding"));
        }
        crate::managed::serve_id(machine, &plan.name)?;
        let raw = serde_json::to_string(plan).map_err(invalid)?;
        if raw.len() > 16 * 1024 {
            return Err(invalid("first launch plan exceeds the catalog limit"));
        }
        Some(raw)
    } else {
        None
    };
    match r.method.as_str() {
        "CloseAccessProtection" => {
            // A platform connection owns one random ID for its full lifetime,
            // including a demand promoted to a hold on a new execution.
            if !id.starts_with("access-") {
                return Err(invalid("expected a platform access ID"));
            }
            if let Some((kind, _, state, owner, ..)) = prior {
                if owner != input.principal || kind == "lease" {
                    return Err(Fault::new("E_PERMISSION_DENIED", "access owner differs"));
                }
                if state != "released" {
                    release(tx, machine, id, "connection closed")?;
                    bump(tx, machine, true)?;
                }
            } else {
                // A close can overtake a delayed first RPC. Recording it in
                // the same transaction prevents that RPC from creating a hold.
                tx.execute("INSERT INTO lifecycle_protections(instance_id,id,kind,principal,incarnation_id,epoch,revision,state,reason)
                    VALUES(?,?,'hold',?,?,?,1,'released','connection closed before admission')",
                    params![machine,id,input.principal,expected.incarnation_id,expected.execution_epoch])?;
            }
        }
        "AcquireActivityHold" | "AcquireRunningLease" | "RequestWake" => {
            if prior.is_some() || input.expected_revision.unwrap_or(0) != 0 {
                return Err(changed("protection ID was already allocated"));
            }
            let reason = input.reason.as_deref().unwrap_or("access");
            if reason.len() > 200 {
                return Err(invalid("protection reason too long"));
            }
            let mut version = 0;
            let mut token = None;
            let mut until = None;
            let kind = match r.method.as_str() {
                "AcquireRunningLease" => {
                    version = input.semantics_version.unwrap_or(1);
                    if !matches!(version, 1 | 2) || expected.incarnation_id.is_none() {
                        return Err(conflict("lease needs a confirmed execution"));
                    }
                    token = Some(valid_token(&input)?);
                    until = Some(deadline(&input)?);
                    "lease"
                }
                "RequestWake" => {
                    let trigger = input
                        .trigger
                        .as_deref()
                        .ok_or_else(|| invalid("missing wake trigger"))?;
                    if input.expected_binding_revision != Some(revision(expected)?) {
                        return Err(changed("wake binding changed"));
                    }
                    if input.authorization_revision.is_none_or(|n| n < 1)
                        || input.endpoint_revision.is_none_or(|n| n < 1)
                    {
                        return Err(Fault::new(
                            "E_PERMISSION_DENIED",
                            "wake is unauthorized for this entry point",
                        ));
                    }
                    if expected.execution_epoch == 0 && first_launch.is_none() {
                        return Err(conflict("a fresh System binding needs its first launch plan"));
                    }
                    if policy.permits_wake(trigger) {
                        "wake"
                    } else if matches!(trigger, "api_access" | "service_access")
                        && running_access(tx, r.scope()?.0, expected)?
                    {
                        "hold"
                    } else {
                        return Err(Fault::new(
                            "E_PERMISSION_DENIED",
                            "wake is disabled for this entry point",
                        ));
                    }
                }
                _ if running_access(tx, r.scope()?.0, expected)? => "hold",
                _ => return Err(conflict("offline access requires a wake demand")),
            };
            if kind != "wake" {
                let blocked:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM statepoints WHERE source_incarnation_id=? AND phase IN ('stop_committed','hibernated'))",
                    [&expected.incarnation_id],|r|r.get(0))?;
                if blocked {
                    return Err(conflict("saved execution requires a logical wake demand"));
                }
                let live:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM executions WHERE incarnation_id=? AND phase='registered')",
                    [&expected.incarnation_id],|r|r.get(0))?;
                if !live {
                    return Err(conflict("execution is not confirmed"));
                }
            }
            tx.execute("INSERT INTO lifecycle_protections(instance_id,id,kind,principal,incarnation_id,epoch,semantics,revision,state,reason,expires_at,
                authorization_revision,endpoint_revision,token_hash,expires_boot,first_launch_json)
                VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,(SELECT host_boot_id FROM worker_state),?)",
                params![machine,id,kind,input.principal,expected.incarnation_id,expected.execution_epoch,version,if kind=="wake"{"pending"}else{"active"},
                        reason,until,input.authorization_revision,input.endpoint_revision,token,first_launch])?;
            bump(tx, machine, true)?;
        }
        "RenewRunningLease"
        | "ReleaseRunningLease"
        | "ReleaseActivityHold"
        | "CancelWakeDemand"
        | "AuthorizeWakeActivation" => {
            let (kind, rev, state, principal, version, token, inc, wake) =
                prior.ok_or_else(|| Fault::new("E_NOT_FOUND", "protection not found"))?;
            if input.principal != principal {
                return Err(Fault::new(
                    "E_PERMISSION_DENIED",
                    "protection belongs to another principal",
                ));
            }
            if input.expected_revision != Some(rev) {
                return Err(changed("protection revision changed"));
            }
            if state == "released" {
                return Err(conflict("protection has already ended"));
            }
            match r.method.as_str() {
                "RenewRunningLease" | "ReleaseRunningLease" => {
                    if kind != "lease"
                        || inc != expected.incarnation_id
                        || token.as_ref() != Some(&valid_token(&input)?)
                    {
                        return Err(Fault::new(
                            "E_PERMISSION_DENIED",
                            "lease token or execution does not match",
                        ));
                    }
                    if r.method == "RenewRunningLease" {
                        if version == 2 && state != "active" {
                            return Err(conflict(
                                "lease must be acquired on the current execution",
                            ));
                        }
                        tx.execute("UPDATE lifecycle_protections SET state='active',expires_at=?,expires_boot=(SELECT host_boot_id FROM worker_state),revision=revision+1
                                    WHERE instance_id=? AND id=?",params![deadline(&input)?,machine,id])?;
                    } else {
                        release(tx, machine, id, "released by owner")?
                    }
                }
                "ReleaseActivityHold" if kind == "hold" && inc == expected.incarnation_id => {
                    release(tx, machine, id, "access completed")?
                }
                "CancelWakeDemand" if kind == "wake" => release(tx, machine, id, "wake cancelled")?,
                "AuthorizeWakeActivation" if kind == "wake" && state == "pending" => {
                    if wake.is_none() || wake != input.wake_operation {
                        return Err(conflict("wake operation changed"));
                    }
                    let completed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_decisions d JOIN operations o ON o.operation_id=d.id
                        JOIN instance_bindings b ON b.instance_id=d.instance_id AND b.route_id='deep'
                        JOIN executions e ON e.incarnation_id=b.incarnation_id WHERE d.id=? AND o.phase='COMPLETED' AND
                        (e.last_operation_id=o.operation_id OR (d.kind='wake' AND d.incarnation_id=b.incarnation_id) OR d.kind='authorize_access' AND d.incarnation_id=b.incarnation_id))",
                        [&wake],|r|r.get(0))?;
                    // Running access has no native transition. Its journal records the observed execution instead.
                    let observed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_decisions WHERE id=? AND kind='authorize_access' AND stage='completed'
                        AND incarnation_id=? AND epoch=?)",params![wake,expected.incarnation_id,expected.execution_epoch],|r|r.get(0))?;
                    if !(completed || observed) || expected.incarnation_id.is_none() {
                        return Err(conflict("wake target has not been confirmed"));
                    }
                    if input.authorized == Some(false) {
                        release(tx, machine, id, "authorization revoked")?
                    } else if input.authorized == Some(true)
                        && input.authorization_revision.is_some_and(|v| v > 0)
                        && input.endpoint_revision.is_some_and(|v| v > 0)
                    {
                        tx.execute("UPDATE lifecycle_protections SET kind='hold',state='active',incarnation_id=?,epoch=?,authorization_revision=?,endpoint_revision=?,revision=revision+1
                            WHERE instance_id=? AND id=?",params![expected.incarnation_id,expected.execution_epoch,input.authorization_revision,input.endpoint_revision,machine,id])?;
                    } else {
                        return Err(Fault::new(
                            "E_PERMISSION_DENIED",
                            "wake must be reauthorized at the entry point",
                        ));
                    }
                }
                _ => return Err(conflict("protection type or execution differs")),
            }
            bump(tx, machine, true)?;
        }
        _ => return Err(invalid("unknown lifecycle protection method")),
    }
    receipt(tx, machine, id)
}
fn release(tx: &Transaction<'_>, machine: &str, id: &str, reason: &str) -> Result<()> {
    tx.execute("UPDATE lifecycle_protections SET state='released',reason=?,revision=revision+1 WHERE instance_id=? AND id=?",params![reason,machine,id])?;
    Ok(())
}
