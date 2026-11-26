//! Retire one fenced System binding without taking ownership of its descendants.
use crate::catalog::{Catalog, Operation, VolumeHead};
use crate::ipc::{Expected, Fault, Request, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Deserialize;
use serde_json::json;
use std::fs::File;

pub(crate) const KIND: &str = "retire_instance";
pub(crate) const METHOD: &str = "RetireStoppedInstance";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    name: String,
}

pub(crate) fn is_retired(db: &Connection, route: &str, instance: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM operations WHERE route_id=? AND instance_id=?
         AND kind='retire_instance' AND phase='COMPLETED')",
        params![route, instance],
        |row| row.get(0),
    )?)
}

fn state_conflict(message: &str) -> Fault {
    Fault::new("E_STATE_CONFLICT", message)
}

fn ensure_fenced(tx: &Transaction<'_>, route: &str, expected: &Expected) -> Result<()> {
    let unsafe_source: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM executions e WHERE e.route_id=?1 AND e.instance_id=?2
            AND (e.phase!='exited' OR EXISTS(SELECT 1 FROM writer_reservations r WHERE r.incarnation_id=e.incarnation_id)))
         OR EXISTS(SELECT 1 FROM network_attachments a WHERE a.route_id=?1 AND a.instance_id=?2
            AND (a.state='unknown' OR EXISTS(SELECT 1 FROM network_tap_leases t WHERE t.attachment_id=a.attachment_id AND t.state!='retired')))
         OR EXISTS(SELECT 1 FROM managed_budget_holds WHERE instance_id=?2 AND state!='released')
         OR EXISTS(SELECT 1 FROM statepoints p JOIN executions e ON e.incarnation_id=p.source_incarnation_id
            WHERE e.route_id=?1 AND e.instance_id=?2 AND e.execution_epoch=?3 AND p.phase IN ('hibernated','stop_committed'))
         OR EXISTS(SELECT 1 FROM managed_fork_batches f JOIN operations o USING(operation_id)
            WHERE o.route_id=?1 AND o.instance_id=?2 AND o.phase='NEW' AND f.source_released=0)",
        params![route, expected.instance_id, expected.execution_epoch],
        |row| row.get(0),
    )?;
    if unsafe_source {
        return Err(state_conflict("source execution, writers, network or saved state are not fenced"));
    }
    let changing_volume: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM product_volume_attachments a
         JOIN product_volume_operations v USING(volume_id)
         WHERE a.instance_id=? AND a.state='reserved' AND v.result_json IS NULL)",
        [&expected.instance_id],
        |row| row.get(0),
    )?;
    if changing_volume {
        return Err(Fault::new("E_OPERATION_IN_PROGRESS", "an attached volume is changing"));
    }
    Ok(())
}

fn plan(
    tx: &Transaction<'_>,
    route: &str,
    bundle: &str,
    expected: &Expected,
    name: &str,
) -> Result<(Option<String>, Vec<VolumeHead>)> {
    ensure_fenced(tx, route, expected)?;
    if expected.execution_epoch == 0 {
        let prior: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE route_id=?1 AND instance_id=?2)
             OR EXISTS(SELECT 1 FROM lifecycle_policies WHERE instance_id=?2 AND bundle_digest!=?3)",
            params![route, expected.instance_id, bundle],
            |row| row.get(0),
        )?;
        if prior {
            return Err(state_conflict("first-start slot no longer belongs to this binding"));
        }
        return Ok((None, Vec::new()));
    }
    let (stop, devices): (String, String) = tx.query_row(
        "SELECT s.operation_id,m.devices_json FROM executions e
         JOIN managed_launches m ON m.operation_id=e.last_operation_id AND m.incarnation_id=e.incarnation_id
         JOIN operations s ON s.expected_incarnation_id=e.incarnation_id AND s.instance_id=e.instance_id
            AND s.route_id=e.route_id AND s.bundle_digest=e.bundle_digest AND s.expected_execution_epoch=e.execution_epoch
         JOIN native_stop_commits c ON c.operation_id=s.operation_id
         JOIN native_transitions n ON n.operation_id=s.operation_id AND n.incarnation_id=e.incarnation_id
         WHERE e.route_id=? AND e.bundle_digest=? AND e.instance_id=? AND e.execution_epoch=? AND e.phase='exited'
            AND m.machine_name=? AND json_extract(m.spec_json,'$.boot_profile')='system-debian-v1'
            AND s.kind='stop' AND s.phase='COMPLETED' AND n.stage='complete' AND n.disposition='EXITED' AND n.mode='managed'",
        params![route, bundle, expected.instance_id, expected.execution_epoch, name],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?.ok_or_else(|| state_conflict("retirement requires a confirmed manual System Stop on this epoch"))?;
    let mut query = tx.prepare(
        "SELECT json_extract(d.value,'$.volume_id'),h.head_resource_id FROM json_each(?) d
         LEFT JOIN volume_heads h ON h.volume_id=json_extract(d.value,'$.volume_id')
         WHERE json_extract(d.value,'$.head_id') IS NOT NULL
         AND NOT EXISTS(SELECT 1 FROM product_volumes v WHERE v.volume_id=json_extract(d.value,'$.volume_id'))",
    )?;
    let mut heads = Vec::new();
    for row in query.query_map([devices], |row| Ok((row.get(0)?, row.get::<_, Option<String>>(1)?)))? {
        let (volume_id, head) = row?;
        let head_resource_id = head.ok_or_else(|| state_conflict("machine-private disk no longer has its writable head"))?;
        heads.push(VolumeHead { volume_id, head_resource_id });
    }
    Ok((Some(stop), heads))
}

pub(crate) fn submit(catalog: &mut Catalog, request: &Request) -> Result<Operation> {
    let input: Input = request.payload()?;
    let (id, _) = request.operation()?;
    let (route, bundle, expected) = request.scope()?;
    if route != "deep" || expected.incarnation_id.is_some() {
        return Err(state_conflict("retirement requires an empty System binding"));
    }
    crate::managed::serve_id(&expected.instance_id, &input.name)?;
    catalog.begin_with(request, KIND, |tx| {
        let (stop, heads) = plan(tx, route, bundle, expected, &input.name)?;
        let encoded = serde_json::to_string(&heads).map_err(|error| Fault::invalid(error.to_string()))?;
        tx.execute("INSERT INTO managed_retirements VALUES(?,?,?)", params![id, stop, encoded])?;
        Ok(())
    })
}

fn release_instance_links(tx: &Transaction<'_>, route: &str, instance: &str) -> Result<()> {
    tx.execute("UPDATE product_volumes SET revision=revision+1 WHERE volume_id IN (
        SELECT volume_id FROM product_volume_attachments WHERE instance_id=? AND state='reserved')", [instance])?;
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='product_attachment' AND state='active'
        AND owner_id IN (SELECT attachment_id FROM product_volume_attachments WHERE instance_id=? AND state='reserved')", [instance])?;
    tx.execute("UPDATE product_volume_attachments SET state='detached',revision=revision+1
        WHERE instance_id=? AND state='reserved'", [instance])?;
    tx.execute("UPDATE private_packet_wake_rules SET enabled=0,revision=revision+1
        WHERE enabled=1 AND EXISTS(SELECT 1 FROM network_attachments a WHERE a.route_id=? AND a.instance_id=?
        AND a.attachment_id IN (source_attachment,target_attachment))", params![route, instance])?;
    tx.execute("UPDATE lifecycle_protections SET state='released',reason='instance retired',revision=revision+1
        WHERE state!='released' AND (instance_id=?2 OR (instance_id,id) IN (
            SELECT d.instance_id,d.protection_id FROM private_packet_wake_demands d JOIN private_packet_wake_rules r ON r.id=d.rule_id
            WHERE EXISTS(SELECT 1 FROM network_attachments a WHERE a.route_id=?1 AND a.instance_id=?2
                AND a.attachment_id IN (r.source_attachment,r.target_attachment))))", params![route, instance])?;
    tx.execute("DELETE FROM private_packet_wake_demands WHERE instance_id=?2 OR rule_id IN (
        SELECT r.id FROM private_packet_wake_rules r WHERE EXISTS(SELECT 1 FROM network_attachments a
            WHERE a.route_id=?1 AND a.instance_id=?2 AND a.attachment_id IN (r.source_attachment,r.target_attachment)))",
        params![route, instance])?;
    tx.execute("UPDATE lifecycle_decisions SET stage='cancelled',finished_at=unixepoch()*1000,error='instance retired'
        WHERE instance_id=? AND stage IN ('queued','dispatching','running')", [instance])?;
    tx.execute("UPDATE network_attachments SET state='released',revision=revision+1
        WHERE route_id=? AND instance_id=? AND state='reserved'", params![route, instance])?;
    Ok(())
}

fn drive(catalog: &mut Catalog, objects: &File, operation: &Operation) -> Result<()> {
    let request = crate::managed_statepoint::request(operation, json!({})).derived(METHOD, json!({}));
    catalog.active_operation(&request)?;
    let (route, _, expected) = request.scope()?;
    let id = &operation.operation_id;
    let encoded: String = catalog.db.query_row(
        "SELECT private_heads_json FROM managed_retirements WHERE operation_id=?",
        [id],
        |row| row.get(0),
    )?;
    let heads: Vec<VolumeHead> = serde_json::from_str(&encoded).map_err(|error| Fault::new("E_CATALOG", error.to_string()))?;
    if !heads.is_empty() {
        crate::blocks::seal_heads(catalog, objects, &request, heads)?;
    }
    let tx = catalog.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if crate::catalog::binding(&tx, route, &expected.instance_id)? != (expected.execution_epoch, None, Some(id.clone())) {
        return Err(Fault::new("E_STALE_EXECUTION", "retiring binding changed before publication"));
    }
    ensure_fenced(&tx, route, expected)?;
    release_instance_links(&tx, route, &expected.instance_id)?;
    tx.execute("INSERT OR IGNORE INTO retired_instance_blocks SELECT b.resource_id,?1 FROM managed_blocks b
        JOIN resources r USING(resource_id) WHERE r.immutable=1 AND r.state IN ('available','deleting')
        AND json_extract(b.spec_json,'$.volume_id') IN (SELECT json_extract(value,'$.volume_id') FROM json_each(?2))",
        params![id, encoded])?;
    // Sealing pins each converted disk under this operation until the binding
    // retires. The resource graph still retains every independent consumer.
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='operation' AND owner_id=? AND state='active'", [id])?;
    tx.execute("DELETE FROM instance_bindings WHERE route_id=? AND instance_id=? AND active_operation_id=?",
        params![route, expected.instance_id, id])?;
    tx.execute("UPDATE operations SET phase='COMPLETED',revision=revision+1 WHERE operation_id=? AND phase='NEW'", [id])?;
    tx.commit()?;
    Ok(())
}

fn collectible(catalog: &Catalog) -> Result<Vec<(String, String, i64)>> {
    let mut query = catalog.db.prepare("SELECT r.resource_id,r.state,r.revision FROM retired_instance_blocks b
        JOIN resources r USING(resource_id) WHERE r.state IN ('deleting','deleted') OR (r.state='available'
        AND NOT EXISTS(SELECT 1 FROM root_refs WHERE resource_id=r.resource_id AND state='active')
        AND NOT EXISTS(SELECT 1 FROM resource_edges WHERE child_resource_id=r.resource_id)
        AND NOT EXISTS(SELECT 1 FROM fd_leases WHERE resource_id=r.resource_id AND state!='released')
        AND NOT EXISTS(SELECT 1 FROM writer_reservations WHERE head_resource_id=r.resource_id))
        ORDER BY b.rowid LIMIT 16")?;
    let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub(crate) fn reconcile(catalog: &mut Catalog, objects: &File) -> Result<()> {
    let pending = {
        let mut query = catalog.db.prepare("SELECT o.operation_id FROM managed_retirements r JOIN operations o USING(operation_id)
            WHERE o.phase='NEW' ORDER BY o.rowid LIMIT 16")?;
        let rows = query.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for id in pending {
        let operation = catalog.operation(&id)?;
        if let Err(error) = drive(catalog, objects, &operation) {
            eprintln!("resourced retiring {id}: {error}");
        }
    }
    if catalog.ready().is_err() {
        return Ok(());
    }
    for (resource, state, revision) in collectible(catalog)? {
        let revision = if state == "available" {
            match catalog.gc(&resource, revision, false) {
                Ok(_) => revision + 1,
                Err(error) if error.code == "E_RESOURCE_PINNED" => continue,
                Err(error) => return Err(error),
            }
        } else {
            revision
        };
        crate::blocks::collect(catalog, objects, &resource)?;
        if state != "deleted" {
            catalog.gc(&resource, revision, true)?;
        }
        catalog.db.execute("DELETE FROM retired_instance_blocks WHERE resource_id=?", [&resource])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_retirement_recovers_original_receipt_and_fences_wake() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.sqlite");
        let objects = File::open(directory.path()).unwrap();
        let bundle = format!("sha256:{}", "1".repeat(64));
        let request = Request {
            protocol: crate::ipc::PROTOCOL.into(),
            method: METHOD.into(),
            request_id: "retire-empty".into(),
            operation_id: Some("retire-empty".into()),
            request_digest: Some(format!("sha256:{}", "2".repeat(64))),
            route_id: Some("deep".into()),
            bundle_digest: Some(bundle.clone()),
            expected: Some(Expected {
                instance_id: crate::managed::machine_id(&"a".repeat(32), "empty"),
                incarnation_id: None,
                execution_epoch: 0,
            }),
            fd_table: Vec::new(),
            payload: json!({"name":"empty"}),
        };
        let mut first = Catalog::open(&path, "boot", "worker-before-restart").unwrap();
        first.register_bundle(&bundle, &bundle).unwrap();
        let accepted = submit(&mut first, &request).unwrap();
        assert_eq!(accepted.phase, "NEW");
        drop(first);

        let mut recovered = Catalog::open(&path, "boot", "worker-after-restart").unwrap();
        assert_eq!(recovered.ready().unwrap_err().code, "E_RECOVERING");
        reconcile(&mut recovered, &objects).unwrap();
        recovered.complete_recovery("worker-after-restart").unwrap();
        let receipt = submit(&mut recovered, &request).unwrap();
        assert_eq!(receipt.operation_id, accepted.operation_id);
        assert_eq!(receipt.phase, "COMPLETED");
        assert_eq!(receipt.revision, 2);

        let mut wake = request.derived("RequestWake", json!({}));
        wake.operation_id = Some("wake-deleted-slot".into());
        assert_eq!(crate::lifecycle_controller::handle(&mut recovered, &wake).unwrap_err().code, "E_STALE_EXECUTION");
        assert_eq!(recovered.begin(&wake, "launch").unwrap_err().code, "E_STALE_EXECUTION");
    }
}
