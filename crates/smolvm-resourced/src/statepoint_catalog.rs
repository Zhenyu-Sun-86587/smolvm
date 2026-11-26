//! StatePoint publication and STOP_COMMIT are atomic with their resource roots.

use crate::catalog::{Catalog, Operation};
use crate::ipc::{valid_id, Fault, Result};
use crate::statepoint_capture::{Export, Purpose};
use crate::statepoint_store::{Manifest, Point};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub(crate) struct Record {
    pub operation_id: String,
    pub export: Export,
    pub point: Point,
    pub phase: String,
    pub manifest_digest: Option<String>,
    pub restore_capture_id: Option<String>,
    pub error: Option<String>,
    pub revision: i64,
    #[serde(skip)]
    volatile_id: String,
}

// A failed restore can consume an execution epoch before publishing a new
// execution. Only a completed successor supersedes the original saved cut.
pub(crate) fn retained_statepoint(
    db: &Connection,
    route: &str,
    instance: &str,
    epoch: i64,
) -> Result<Option<String>> {
    Ok(db.query_row(
        "SELECT p.capture_id FROM statepoints p JOIN executions e ON e.incarnation_id=p.source_incarnation_id
         WHERE e.route_id=?1 AND e.instance_id=?2 AND e.execution_epoch<=?3 AND p.phase='hibernated'
         AND json_extract(p.export_json,'$.purpose') IN ('hibernate','rollback_rescue')
         AND NOT EXISTS(SELECT 1 FROM executions successor JOIN operations o ON o.operation_id=successor.last_operation_id
            WHERE successor.route_id=e.route_id AND successor.instance_id=e.instance_id
            AND successor.execution_epoch>e.execution_epoch AND successor.execution_epoch<=?3 AND o.phase='COMPLETED')
         ORDER BY e.execution_epoch DESC,p.rowid DESC LIMIT 1",
        params![route, instance, epoch],
        |row| row.get(0),
    ).optional()?)
}

fn row(row: &Row<'_>) -> rusqlite::Result<Record> {
    fn decode<T: serde::de::DeserializeOwned>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
        serde_json::from_str(&row.get::<_, String>(column)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                column,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
    }
    Ok(Record {
        operation_id: row.get(0)?,
        volatile_id: row.get(1)?,
        export: decode(row, 2)?,
        point: decode(row, 3)?,
        phase: row.get(4)?,
        manifest_digest: row.get(5)?,
        restore_capture_id: row.get(6)?,
        error: row.get(7)?,
        revision: row.get(8)?,
    })
}

fn conflict(message: &str) -> Fault {
    Fault::new("E_IDEMPOTENCY_CONFLICT", message)
}

fn changed(message: &str) -> Fault {
    Fault::new("E_STALE_REVISION", message)
}

fn root(purpose: Purpose) -> &'static str {
    match purpose {
        Purpose::Checkpoint => "statepoint_checkpoint",
        Purpose::Hibernate => "statepoint_hibernate",
        Purpose::RollbackRescue => "statepoint_rescue",
    }
}

fn insert_descriptor(
    tx: &Transaction<'_>,
    op: &str,
    id: &str,
    durability: &str,
    descriptor: &str,
) -> Result<()> {
    let digest = format!("sha256:{:x}", Sha256::digest(descriptor.as_bytes()));
    if tx.execute(
        "INSERT OR IGNORE INTO resources VALUES(?,'descriptor','available',?,1,?,?,?,1)",
        params![id, durability, descriptor, digest, op],
    )? != 1
    {
        return Err(conflict(
            "StatePoint representation ID has already been used",
        ));
    }
    Ok(())
}

fn add_disks(tx: &Transaction<'_>, id: &str, disks: &[String]) -> Result<()> {
    for disk in disks {
        if tx.execute(
            "INSERT INTO resource_edges SELECT ?,resource_id,'block_generation' FROM resources
            WHERE resource_id=? AND state='available' AND immutable=1 AND durability='durable'",
            params![id, disk],
        )? != 1
        {
            return Err(Fault::new(
                "E_RESOURCE_UNAVAILABLE",
                "captured disk generation is unavailable",
            ));
        }
    }
    Ok(())
}

fn release_export(tx: &Transaction<'_>, record: &Record, publish: bool) -> Result<()> {
    let mut roots = vec![&record.volatile_id];
    if publish {
        roots.extend(&record.point.disk_generations);
    }
    for id in roots {
        tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1
            WHERE owner_kind IN ('operation','pivot_recovery') AND owner_id=? AND resource_id=? AND state='active'",
            params![record.operation_id, id])?;
    }
    tx.execute(
        "UPDATE resources SET state='lost',revision=revision+1 WHERE resource_id=?1
        AND NOT EXISTS (SELECT 1 FROM root_refs WHERE resource_id=?1 AND state='active')
        AND NOT EXISTS (SELECT 1 FROM resource_edges WHERE child_resource_id=?1)",
        [&record.volatile_id],
    )?;
    tx.execute(
        "DELETE FROM resource_edges WHERE owner_resource_id=?1 AND EXISTS
        (SELECT 1 FROM resources WHERE resource_id=?1 AND state='lost')",
        [&record.volatile_id],
    )?;
    Ok(())
}

impl Catalog {
    pub(crate) fn statepoint(&self, id: &str) -> Result<Option<Record>> {
        if !valid_id(id) {
            return Err(Fault::invalid("invalid StatePoint capture ID"));
        }
        Ok(self
            .db
            .query_row(
                "SELECT operation_id,volatile_id,export_json,point_json,phase,
            manifest_digest,restore_capture_id,error,revision FROM statepoints WHERE capture_id=?",
                [id],
                row,
            )
            .optional()?)
    }

    pub(crate) fn require_statepoint(&self, id: &str) -> Result<Record> {
        self.statepoint(id)?
            .ok_or_else(|| Fault::new("E_NOT_FOUND", "StatePoint does not exist"))
    }

    pub(crate) fn start_statepoint(
        &mut self,
        op: &Operation,
        export: &Export,
        point: &Point,
    ) -> Result<Record> {
        let volatile_id = format!("volatile-{:x}", Sha256::digest(point.capture_id.as_bytes()));
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM resources WHERE resource_id=?)",
            [&point.representation_id],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(conflict(
                "durable StatePoint representation ID has already been used",
            ));
        }
        insert_descriptor(&tx, &op.operation_id, &volatile_id, "volatile", &json!({
            "schema":"StatePoint/1", "capture_id":point.capture_id,"representation_id":volatile_id,
            "source_ram_digest":point.source_ram_digest,"checkpoint_digest":point.checkpoint_digest,
        }).to_string())?;
        if tx.execute(
            "INSERT OR IGNORE INTO statepoints VALUES(?,?,?,?,?,?,?,'exporting',NULL,NULL,NULL,1)",
            params![
                point.capture_id,
                point.representation_id,
                volatile_id,
                op.operation_id,
                point.incarnation_id,
                json!(export).to_string(),
                json!(point).to_string()
            ],
        )? != 1
        {
            return Err(conflict(
                "StatePoint capture, representation or operation ID has already been used",
            ));
        }
        add_disks(&tx, &volatile_id, &point.disk_generations)?;
        tx.execute(
            "INSERT INTO root_refs VALUES('operation',?,?,'active',1,?)",
            params![op.operation_id, volatile_id, op.operation_id],
        )?;
        tx.commit()?;
        self.require_statepoint(&point.capture_id)
    }

    pub(crate) fn publish_statepoint(
        &mut self,
        record: &Record,
        manifest: &Manifest,
        digest: &str,
    ) -> Result<Record> {
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        if tx.execute("UPDATE statepoints SET phase='durable',manifest_digest=?,error=NULL,revision=revision+1
            WHERE capture_id=? AND phase='exporting' AND revision=?", params![digest, record.export.capture_id, record.revision])? != 1
        {
            return Err(changed("StatePoint publication phase changed"));
        }
        let id = &record.point.representation_id;
        insert_descriptor(&tx, &record.operation_id, id, "durable", &json!({
            "schema":"CaptureManifest/1","capture_id":manifest.statepoint.capture_id,"required_bundle":manifest.required_bundle,
            "manifest_digest":digest,"commit_id":manifest.commit_id,
        }).to_string())?;
        add_disks(&tx, id, &record.point.disk_generations)?;
        crate::activation_catalog::publish_statepoint_tap(&tx, record, digest)?;
        tx.execute(
            "INSERT INTO root_refs VALUES(?,?,?,'active',1,?)",
            params![
                root(record.export.purpose),
                record.export.capture_id,
                id,
                record.operation_id
            ],
        )?;
        if record.export.purpose == Purpose::Checkpoint {
            release_export(&tx, record, true)?;
        }
        tx.commit()?;
        self.require_statepoint(&record.export.capture_id)
    }

    pub(crate) fn statepoint_export_failure(&self, record: &Record, error: &str) -> Result<Record> {
        self.db.execute("UPDATE statepoints SET error=?,revision=revision+1 WHERE capture_id=? AND phase='exporting' AND revision=?",
            params![error, record.export.capture_id, record.revision])?;
        self.require_statepoint(&record.export.capture_id)
    }

    pub(crate) fn statepoint_stop(
        &mut self,
        record: &Record,
        restore_capture_id: Option<&str>,
    ) -> Result<Record> {
        if self.db.execute(
            "UPDATE statepoints SET phase='stop_committed',restore_capture_id=?,revision=revision+1
            WHERE capture_id=? AND phase='durable' AND revision=?",
            params![
                restore_capture_id,
                record.export.capture_id,
                record.revision
            ],
        )? != 1
        {
            return Err(changed("StatePoint stop decision changed"));
        }
        self.require_statepoint(&record.export.capture_id)
    }

    pub(crate) fn finish_statepoint_stop(&mut self, record: &Record) -> Result<Record> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.execute("UPDATE statepoints SET phase='hibernated',revision=revision+1
            WHERE capture_id=? AND phase='stop_committed' AND EXISTS
            (SELECT 1 FROM executions WHERE incarnation_id=statepoints.source_incarnation_id AND phase='exited')",
            [&record.export.capture_id])? != 1 {
            return Err(Fault::new("E_FENCE_UNPROVEN", "StatePoint source exit has not been proved"));
        }
        release_export(&tx, record, true)?;
        tx.execute("UPDATE managed_fork_batches SET source_released=1,error=NULL,
                    stage=CASE WHEN restore_capture_id IS NULL THEN 'complete' ELSE 'rollback_target' END
                    WHERE operation_id=?", [&record.operation_id])?;
        tx.execute(
            "UPDATE operations SET phase='COMPLETED',revision=revision+1
            WHERE operation_id=? AND phase='NEW' AND kind<>'vm_rollback'", [&record.operation_id])?;
        tx.execute("UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?1
                   AND NOT EXISTS(SELECT 1 FROM operations WHERE operation_id=?1 AND kind='vm_rollback')",[&record.operation_id])?;
        tx.commit()?;
        self.require_statepoint(&record.export.capture_id)
    }

    pub(crate) fn abort_statepoint(&mut self, record: &Record) -> Result<Record> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx.execute(
            "UPDATE statepoints SET phase='aborted',revision=revision+1
            WHERE capture_id=? AND phase IN ('exporting','durable') AND revision=?",
            params![record.export.capture_id, record.revision],
        )? != 1
        {
            return Err(changed("StatePoint crossed an irreversible decision"));
        }
        tx.execute(
            "UPDATE root_refs SET state='dropped',revision=revision+1
            WHERE owner_kind=? AND owner_id=? AND resource_id=? AND state='active'",
            params![
                root(record.export.purpose),
                record.export.capture_id,
                record.point.representation_id,
            ],
        )?;
        release_export(&tx, record, false)?;
        tx.commit()?;
        self.require_statepoint(&record.export.capture_id)
    }

    pub(crate) fn pending_statepoint_stops(&self) -> Result<Vec<Record>> {
        let mut query = self.db.prepare("SELECT operation_id,volatile_id,export_json,point_json,phase,
            manifest_digest,restore_capture_id,error,revision FROM statepoints WHERE phase='stop_committed'")?;
        let rows = query.query_map([], row)?.collect::<rusqlite::Result<_>>()?;
        Ok(rows)
    }
}
