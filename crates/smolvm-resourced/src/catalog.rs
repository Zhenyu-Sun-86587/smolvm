use crate::ipc::{valid_id, Expected, Fault, Request, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;

const OP_COLUMNS: &str = "operation_id,kind,request_digest,route_id,instance_id,bundle_digest,
    expected_execution_epoch,expected_incarnation_id,phase,decision,revision";
const EXEC_COLUMNS: &str = "incarnation_id,route_id,instance_id,execution_epoch,bundle_digest,
    host_boot_id,pid,pid_start_time,uid,phase,last_operation_id";
const ADD_FORK_RELAY_HOLD: &str =
    "ALTER TABLE managed_fork_batches ADD COLUMN credential_relay_hold TEXT;";

// Two pre-release version-30 catalogs exist. They committed either the
// CoW journal or the relay hold column. Preserve each layout's data.
fn migrate_capture_journal(tx: &Transaction<'_>) -> Result<()> {
    let (cow, relay, capture_loss, verified_backings): (bool, bool, bool, bool) = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='kernel_mm_anchors'),
                EXISTS(SELECT 1 FROM pragma_table_info('managed_fork_batches') WHERE name='credential_relay_hold'),
                EXISTS(SELECT 1 FROM pragma_table_info('managed_fork_children') WHERE name='capture_lost'),
                EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='verified_block_backings')",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if !cow {
        tx.execute_batch(include_str!("schema_kernel_mm_anchors.sql"))?;
    }
    if !relay {
        tx.execute_batch(ADD_FORK_RELAY_HOLD)?;
    }
    if !capture_loss {
        tx.execute_batch(include_str!("schema_kernel_fork_capture_loss.sql"))?;
    }
    if !verified_backings {
        tx.execute_batch(include_str!("schema_backing_identities.sql"))?;
    }
    tx.pragma_update(None, "user_version", 32)?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Operation {
    pub operation_id: String,
    pub kind: String,
    pub request_digest: String,
    pub route_id: String,
    pub instance_id: String,
    pub bundle_digest: String,
    pub expected_execution_epoch: i64,
    pub expected_incarnation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<crate::native_operations::Progress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_environment: Option<crate::boot_environment::Proof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Expected>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statepoint: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resize: Option<Value>,
    pub phase: String,
    pub decision: String,
    pub revision: i64,
}

fn operation_row(row: &Row<'_>) -> rusqlite::Result<Operation> {
    Ok(Operation {
        operation_id: row.get(0)?,
        kind: row.get(1)?,
        request_digest: row.get(2)?,
        route_id: row.get(3)?,
        instance_id: row.get(4)?,
        bundle_digest: row.get(5)?,
        expected_execution_epoch: row.get(6)?,
        expected_incarnation_id: row.get(7)?,
        native: None,
        boot_environment: None,
        execution: None,
        statepoint: None,
        fork: None,
        resize: None,
        phase: row.get(8)?,
        decision: row.get(9)?,
        revision: row.get(10)?,
    })
}

impl Operation {
    pub(crate) fn launches_execution(&self) -> bool {
        matches!(self.kind.as_str(), "launch" | "restore_target")
    }
}

#[derive(Debug, Serialize)]
pub struct Execution {
    pub incarnation_id: String,
    pub route_id: String,
    pub instance_id: String,
    pub execution_epoch: i64,
    pub bundle_digest: String,
    pub host_boot_id: String,
    pub pid: i32,
    pub pid_start_time: i64,
    pub uid: u32,
    pub phase: String,
    pub last_operation_id: String,
}

impl Execution {
    pub fn matches(&self, route: &str, bundle: &str, expected: &Expected) -> bool {
        self.route_id == route
            && self.bundle_digest == bundle
            && self.instance_id == expected.instance_id
            && Some(&self.incarnation_id) == expected.incarnation_id.as_ref()
            && self.execution_epoch == expected.execution_epoch
    }
}

fn execution_row(row: &Row<'_>) -> rusqlite::Result<Execution> {
    Ok(Execution {
        incarnation_id: row.get(0)?,
        route_id: row.get(1)?,
        instance_id: row.get(2)?,
        execution_epoch: row.get(3)?,
        bundle_digest: row.get(4)?,
        host_boot_id: row.get(5)?,
        pid: row.get(6)?,
        pid_start_time: row.get(7)?,
        uid: row.get(8)?,
        phase: row.get(9)?,
        last_operation_id: row.get(10)?,
    })
}

pub struct NewExecution<'a> {
    pub route: &'a str,
    pub bundle: &'a str,
    pub expected: &'a Expected,
    pub boot: &'a str,
    pub pid: i32,
    pub start: i64,
    pub uid: u32,
    pub permit_digest: &'a str,
    pub(crate) kernel_import: Option<&'a crate::managed_kernel_cow::Import>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct VolumeHead {
    pub volume_id: String,
    pub head_resource_id: String,
}

#[derive(Serialize)]
pub struct WriterSet {
    pub heads: Vec<VolumeHead>,
    pub state: String,
    pub revision: i64,
}

pub struct Catalog {
    pub(crate) db: Connection,
}

fn conflict(code: &'static str, message: &str) -> Fault {
    Fault::new(code, message)
}

fn not_found(what: &str) -> Fault {
    Fault::new("E_NOT_FOUND", format!("{what} does not exist"))
}

fn stale() -> Fault {
    conflict(
        "E_STALE_EXECUTION",
        "operation targets a different execution",
    )
}

fn identifier(value: &str) -> Result<&str> {
    if valid_id(value) {
        Ok(value)
    } else {
        Err(Fault::invalid("invalid resource or owner identifier"))
    }
}

fn op(db: &Connection, id: &str) -> Result<Option<Operation>> {
    Ok(db
        .query_row(
            &format!("SELECT {OP_COLUMNS} FROM operations WHERE operation_id=?"),
            [id],
            operation_row,
        )
        .optional()?)
}

fn exec(db: &Connection, id: &str) -> Result<Option<Execution>> {
    Ok(db
        .query_row(
            &format!("SELECT {EXEC_COLUMNS} FROM executions WHERE incarnation_id=?"),
            [id],
            execution_row,
        )
        .optional()?)
}

pub(crate) fn binding(
    db: &Connection,
    route: &str,
    instance: &str,
) -> Result<(i64, Option<String>, Option<String>)> {
    if crate::managed_retirement::is_retired(db, route, instance)? {
        return Err(stale());
    }
    Ok(db
        .query_row(
            "SELECT execution_epoch,incarnation_id,active_operation_id
        FROM instance_bindings WHERE route_id=? AND instance_id=?",
            [route, instance],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .unwrap_or((0, None, None)))
}

fn resource_available(db: &Connection, id: &str) -> Result<()> {
    let state: Option<String> = db
        .query_row(
            "SELECT state FROM resources WHERE resource_id=?",
            [identifier(id)?],
            |r| r.get(0),
        )
        .optional()?;
    if state.as_deref() != Some("available") {
        return Err(conflict(
            "E_RESOURCE_UNAVAILABLE",
            "resource is unavailable",
        ));
    }
    Ok(())
}

fn check_gc(db: &Connection, id: &str, revision: i64, state: &str) -> Result<()> {
    let eligible: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM resources r JOIN operations o ON o.operation_id=r.created_by_operation
              WHERE r.resource_id=?1 AND r.kind='descriptor' AND r.state=?2 AND r.revision=?3
                AND o.phase IN ('COMPLETED','ABORTED'))
         AND NOT EXISTS(SELECT 1 FROM root_refs WHERE resource_id=?1 AND state='active')
         AND NOT EXISTS(SELECT 1 FROM resource_edges WHERE child_resource_id=?1)
         AND NOT EXISTS(SELECT 1 FROM fd_leases WHERE resource_id=?1 AND state<>'released')
         AND NOT EXISTS(SELECT 1 FROM writer_reservations WHERE head_resource_id=?1)",
        params![identifier(id)?, state, revision], |r| r.get(0),
    )?;
    if !eligible {
        return Err(conflict(
            "E_RESOURCE_PINNED",
            "resource state, revision or references prevent collection",
        ));
    }
    Ok(())
}

pub(crate) fn bundle_executable(db: &Connection, digest: &str) -> Result<String> {
    db.query_row(
        "SELECT executable_sha256 FROM runtime_bundles WHERE bundle_digest=?",
        [digest],
        |row| row.get(0),
    )
    .optional()?
    .ok_or_else(|| conflict("E_BUNDLE_UNAVAILABLE", "bundle is not registered on this worker"))
}

impl Catalog {
    pub fn open(path: &Path, boot_id: &str, session_id: &str) -> Result<Self> {
        let mut db = Connection::open_with_flags(
            path,
            OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;",
        )?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        match version {
            0 => {
                tx.execute_batch(include_str!("schema.sql"))?;
                tx.execute(
                    "INSERT INTO worker_state VALUES(1,?,?,0)",
                    [boot_id, session_id],
                )?;
                tx.execute_batch(include_str!("schema_escrow.sql"))?;
                tx.execute_batch(include_str!("schema_blocks.sql"))?;
                crate::network_catalog::install(&tx)?;
                tx.execute_batch(include_str!("schema_writer_pivots.sql"))?;
                crate::network_lease_catalog::install(&tx)?;
                crate::activation_catalog::install(&tx)?;
                tx.execute_batch(include_str!("schema_native_operations.sql"))?;
                crate::network_lease_catalog::install_initial_activations(&tx)?;
                tx.execute_batch(include_str!("schema_statepoints.sql"))?;
                tx.execute_batch(include_str!("schema_managed_launch.sql"))?;
                tx.execute_batch(include_str!("schema_product_volumes.sql"))?;
                tx.execute_batch(include_str!("schema_network_dns.sql"))?;
                tx.execute_batch(include_str!("schema_managed_forks.sql"))?;
                tx.execute_batch(include_str!("schema_capture_network.sql"))?;
                tx.execute_batch(include_str!("schema_managed_state_restores.sql"))?;
                tx.execute_batch(include_str!("schema_lifecycle.sql"))?;
                tx.execute_batch(include_str!("schema_backup_closures.sql"))?;
                tx.execute_batch(include_str!("schema_packet_wake.sql"))?;
                tx.execute_batch(include_str!("schema_batch_admission.sql"))?;
                tx.execute_batch(include_str!("schema_packet_datagrams.sql"))?;
                tx.execute_batch(include_str!("schema_backup_imports.sql"))?;
                tx.execute_batch(include_str!("schema_managed_cpu_limits.sql"))?;
                tx.execute_batch(include_str!("schema_native_resize.sql"))?;
                tx.execute_batch(include_str!("schema_native_stop.sql"))?;
                tx.execute_batch(include_str!("schema_first_launch.sql"))?;
                tx.execute_batch(include_str!("schema_managed_retirements.sql"))?;
                tx.execute_batch(include_str!("schema_network_recovery.sql"))?;
                tx.execute_batch(include_str!("schema_product_machine_volumes.sql"))?;
                migrate_capture_journal(&tx)?;
            }
            1..=36 => {
                if version == 1 {
                    tx.execute_batch(include_str!("schema_escrow.sql"))?;
                }
                if version < 3 {
                    tx.execute_batch(include_str!("schema_blocks.sql"))?;
                }
                if version < 4 {
                    crate::network_catalog::install(&tx)?;
                }
                if version < 5 {
                    tx.execute_batch(include_str!("schema_writer_pivots.sql"))?;
                }
                if version < 6 {
                    crate::network_lease_catalog::install(&tx)?;
                }
                if version < 7 {
                    crate::activation_catalog::install(&tx)?;
                }
                if version < 8 {
                    tx.execute_batch(include_str!("schema_native_operations.sql"))?;
                }
                if version < 9 {
                    crate::network_lease_catalog::install_initial_activations(&tx)?;
                }
                if version < 10 {
                    tx.execute_batch(include_str!("schema_statepoints.sql"))?;
                }
                if version < 11 {
                    tx.execute_batch(include_str!("schema_managed_launch.sql"))?;
                }
                if version < 12 {
                    tx.execute_batch(include_str!("schema_product_volumes.sql"))?;
                }
                if version < 13 {
                    tx.execute_batch(include_str!("schema_network_dns.sql"))?;
                    tx.execute_batch("PRAGMA user_version=13")?;
                }
                if version < 14 {
                    tx.execute_batch(include_str!("schema_managed_forks.sql"))?;
                }
                if version < 15 {
                    tx.execute_batch(include_str!("schema_capture_network.sql"))?;
                }
                if version < 16 {
                    tx.execute_batch(include_str!("schema_managed_state_restores.sql"))?;
                    tx.execute_batch("PRAGMA user_version=16")?;
                }
                if version < 17 {
                    tx.execute_batch(include_str!("schema_lifecycle.sql"))?;
                }
                if version < 18 {
                    tx.execute_batch(include_str!("schema_backup_closures.sql"))?;
                }
                if version < 19 {
                    tx.execute_batch(include_str!("schema_packet_wake.sql"))?;
                }
                if version < 20 {
                    tx.execute_batch(include_str!("schema_batch_admission.sql"))?;
                }
                if version < 21 {
                    tx.execute_batch(include_str!("schema_packet_datagrams.sql"))?;
                }
                if version < 22 {
                    tx.execute_batch(include_str!("schema_backup_imports.sql"))?;
                }
                if version < 23 {
                    tx.execute_batch(include_str!("schema_managed_cpu_limits.sql"))?;
                    tx.execute_batch("PRAGMA user_version=23")?;
                }
                if version < 24 {
                    tx.execute_batch(include_str!("schema_native_resize.sql"))?;
                }
                if version < 25 {
                    tx.execute_batch(include_str!("schema_native_stop.sql"))?;
                }
                if version < 26 {
                    tx.execute_batch(include_str!("schema_first_launch.sql"))?;
                }
                if version < 27 {
                    tx.execute_batch(include_str!("schema_managed_retirements.sql"))?;
                }
                if version < 28 {
                    tx.execute_batch(include_str!("schema_network_recovery.sql"))?;
                }
                if version < 29 {
                    tx.execute_batch(include_str!("schema_product_machine_volumes.sql"))?;
                }
                if version < 32 {
                    migrate_capture_journal(&tx)?;
                }
                crate::packet_wake::recover(&tx)?;
                crate::lifecycle_controller::recover(&tx)?;
                crate::network_lease_catalog::recover(&tx)?;
                crate::activation_catalog::recover(&tx)?;
                let old_boot: String =
                    tx.query_row("SELECT host_boot_id FROM worker_state", [], |r| r.get(0))?;
                tx.execute(
                    "UPDATE worker_state SET host_boot_id=?,broker_session_id=?,recovering=1",
                    [boot_id, session_id],
                )?;
                tx.execute(
                    "UPDATE executions SET phase='unknown' WHERE phase='registered'",
                    [],
                )?;
                if old_boot != boot_id {
                    tx.execute(
                        "UPDATE resources SET state='lost',revision=revision+1
                        WHERE durability='volatile' AND state IN ('available','deleting')",
                        [],
                    )?;
                }
                crate::escrow_catalog::recover(&tx, old_boot != boot_id)?;
                tx.execute(
                    "UPDATE writer_grants SET state='unknown',revision=revision+1
                    WHERE state IN ('offered','attached')",
                    [],
                )?;
            }
            _ => {
                return Err(conflict(
                    "E_SCHEMA_UNSUPPORTED",
                    "unsupported worker catalog schema",
                ))
            }
        }
        tx.execute_batch(include_str!("schema_network_memberships.sql"))?;
        tx.execute_batch(include_str!("schema_network_transfers.sql"))?;
        tx.execute_batch(include_str!("schema_network_overlay.sql"))?;
        tx.execute_batch(include_str!("schema_saved_files.sql"))?;
        tx.execute_batch(include_str!("schema_bucket_bases.sql"))?;
        if version < 36 {
            tx.execute_batch(include_str!("schema_boot_environment.sql"))?;
        }
        tx.pragma_update(None, "user_version", 36)?;
        tx.commit()?;
        Ok(Self { db })
    }

    pub fn health(&self) -> Result<Value> {
        static EXECUTABLE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        let executable_sha256 = EXECUTABLE.get_or_init(|| {
            let mut file = std::fs::File::open("/proc/self/exe").ok()?;
            let mut hash = Sha256::new();
            std::io::copy(&mut file, &mut hash).ok()?;
            Some(format!("sha256:{:x}", hash.finalize()))
        });
        let slice = crate::worker_scope::configured_slice()
            .map_err(|error| Fault::invalid(error.to_string()))?;
        let (boot, session, recovering): (String, String, bool) = self.db.query_row(
            "SELECT host_boot_id,broker_session_id,recovering FROM worker_state",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        Ok(json!({"state":if recovering {"recovering"} else {"ready"},
            "host_boot_id":boot, "broker_session_id":session, "vm_slice":slice, "executable_sha256":executable_sha256,
            "writer_authority_supported":true, "writer_authority_mode":"managed_block_full_sync",
            "fd_transfer_supported":true, "fd_transfer_mode":"sealed_memfd"}))
    }

    pub fn ready(&self) -> Result<()> {
        let recovering: bool =
            self.db
                .query_row("SELECT recovering FROM worker_state", [], |r| r.get(0))?;
        if recovering {
            return Err(conflict(
                "E_RECOVERING",
                "worker catalog is reconciling previous activity",
            ));
        }
        Ok(())
    }

    pub(crate) fn can_complete_managed_recovery(&self) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS (SELECT 1 FROM executions e JOIN native_endpoints n USING(incarnation_id)
                            WHERE e.phase='registered' OR (e.phase='exited' AND e.host_boot_id<>(SELECT host_boot_id FROM worker_state)))
                 OR EXISTS (SELECT 1 FROM managed_launches m JOIN operations o USING(operation_id)
                            WHERE o.phase='NEW')
                 OR EXISTS (SELECT 1 FROM managed_fork_batches b JOIN operations o USING(operation_id)
                            JOIN executions e ON e.incarnation_id=b.source_incarnation
                            JOIN kernel_mm_anchors a ON a.operation_id=o.operation_id AND a.capture_id=b.capture_id
                            WHERE o.phase IN ('NEW','COMPLETED') AND b.selected_memory_fork_backend='kernel_cow'
                              AND b.source_released=1 AND b.stage IN ('children','complete') AND e.phase='exited'
                              AND o.route_id=e.route_id AND o.bundle_digest=e.bundle_digest AND o.instance_id=e.instance_id
                              AND o.expected_incarnation_id=e.incarnation_id AND o.expected_execution_epoch=e.execution_epoch
                              AND a.source_incarnation=e.incarnation_id AND a.source_epoch=e.execution_epoch
                              AND a.source_session=b.session AND a.host_boot_id=e.host_boot_id)",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn complete_recovery(&mut self, session: &str) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // The managed Fork actor and its reserved children replay from the
        // journal. Once the original VMM and its published RAM are accounted
        // for, waiting for those operations to finish here would deadlock
        // them on the same recovery barrier when they acquire resources.
        let outstanding: bool = tx.query_row(
            "WITH accounted_kernel_cuts AS (
                 SELECT a.capture_id,a.operation_id,a.source_incarnation,a.source_epoch,a.source_session,a.host_boot_id,ram.state
                 FROM kernel_mm_anchors a JOIN resources ram ON ram.resource_id=a.resource_id
                 WHERE a.resource_id=a.capture_id AND ram.created_by_operation=a.operation_id
                   AND ram.kind='descriptor' AND ram.durability='volatile'
                   AND json_extract(ram.descriptor_json,'$.schema')='KernelMmAnchor/1'
                   AND ((ram.state='available' AND a.failure IS NULL AND EXISTS (
                         SELECT 1 FROM root_refs p WHERE p.resource_id=ram.resource_id
                           AND p.owner_kind='fork_capture' AND p.owner_id=a.operation_id AND p.state='active'))
                        OR (ram.state='lost' AND a.failure IS NOT NULL))
             ), replayable_forks AS (
                 SELECT b.operation_id,b.serve_instance,o.route_id,o.bundle_digest FROM managed_fork_batches b
                 JOIN operations o USING(operation_id)
                 JOIN executions e ON e.incarnation_id=b.source_incarnation
                 LEFT JOIN native_endpoints n ON n.incarnation_id=e.incarnation_id
                 LEFT JOIN fd_transfers f ON f.resource_id=b.capture_id
                 LEFT JOIN resources r ON r.resource_id=f.resource_id
                 LEFT JOIN accounted_kernel_cuts k ON b.selected_memory_fork_backend='kernel_cow'
                   AND f.resource_id IS NULL AND k.capture_id=b.capture_id AND k.operation_id=o.operation_id
                   AND k.source_incarnation=e.incarnation_id AND k.source_epoch=e.execution_epoch
                   AND k.source_session=b.session AND k.host_boot_id=e.host_boot_id
                 WHERE o.kind IN ('independent_fork','fork_batch') AND o.phase='NEW'
                   AND o.route_id=e.route_id AND o.bundle_digest=e.bundle_digest AND o.instance_id=e.instance_id
                   AND o.expected_incarnation_id=e.incarnation_id AND o.expected_execution_epoch=e.execution_epoch
                   AND ((e.host_boot_id=(SELECT host_boot_id FROM worker_state) AND e.phase='registered' AND n.incarnation_id IS NOT NULL)
                        OR (k.operation_id IS NOT NULL AND e.phase='exited' AND b.source_released=1 AND b.stage='children'
                            AND (e.host_boot_id=(SELECT host_boot_id FROM worker_state) OR k.state='lost')))
                   AND ((b.checkpoint IS NULL AND f.resource_id IS NULL) OR
                        (b.selected_memory_fork_backend='native' AND f.state='committed'
                         AND r.state='available' AND f.incarnation_id=e.incarnation_id
                         AND f.operation_id=o.operation_id) OR k.operation_id IS NOT NULL)
             ), replayable_operations AS (
                 SELECT operation_id FROM replayable_forks
                 UNION ALL
                 SELECT ch.operation_id FROM managed_fork_children ch
                 JOIN replayable_forks f ON f.operation_id=ch.batch_id
                 JOIN managed_launches m ON m.operation_id=ch.operation_id
                 JOIN operations o ON o.operation_id=ch.operation_id
                 WHERE o.kind='restore_target' AND o.instance_id=ch.instance_id
                   AND o.route_id=f.route_id AND o.bundle_digest=f.bundle_digest
                   AND o.expected_execution_epoch=ch.prior_epoch AND o.expected_incarnation_id IS NULL
                   AND m.serve_instance=f.serve_instance AND m.machine_name=ch.name
                 UNION ALL
                 SELECT o.operation_id FROM managed_launches m JOIN operations o USING(operation_id)
                 JOIN instance_bindings b ON b.route_id=o.route_id AND b.instance_id=o.instance_id
                 WHERE (o.kind='launch' OR (o.kind='restore_target' AND EXISTS (
                            SELECT 1 FROM managed_state_restores s WHERE s.operation_id=o.operation_id)))
                   AND o.phase='NEW' AND o.expected_incarnation_id IS NULL
                   AND b.active_operation_id=o.operation_id AND b.incarnation_id IS NULL
                   AND b.execution_epoch=o.expected_execution_epoch
                   AND NOT EXISTS (SELECT 1 FROM executions e WHERE e.incarnation_id=m.incarnation_id)
             )
             SELECT EXISTS (SELECT 1 FROM executions WHERE phase='unknown')
                OR EXISTS (SELECT 1 FROM operations o WHERE o.phase='NEW'
                           AND o.kind!='disk_closure_import'
                           AND NOT EXISTS (SELECT 1 FROM replayable_operations p WHERE p.operation_id=o.operation_id))
                OR EXISTS (SELECT 1 FROM writer_reservations r LEFT JOIN writer_grants g USING(operation_id)
                    WHERE g.grant_id IS NULL OR g.state!='attached')
                OR EXISTS (SELECT 1 FROM fd_leases WHERE state='unknown')
                OR EXISTS (SELECT 1 FROM network_tap_leases WHERE state='unknown')
                OR EXISTS (SELECT 1 FROM target_activations WHERE phase='unknown')",
            [],
            |r| r.get(0),
        )?;
        if outstanding {
            return Err(conflict(
                "E_RECOVERING",
                "unresolved executions, operation intents or reservations",
            ));
        }
        if tx.execute(
            "UPDATE worker_state SET recovering=0 WHERE broker_session_id=?",
            [session],
        )? != 1
        {
            return Err(conflict("E_STALE_SESSION", "worker broker session changed"));
        }
        tx.commit()?;
        self.health()
    }

    pub fn bundle(&self, digest: &str) -> Result<String> {
        bundle_executable(&self.db, digest)
    }

    pub fn register_bundle(&self, digest: &str, binary: &str) -> Result<Value> {
        self.ready()?;
        self.db.execute(
            "INSERT OR IGNORE INTO runtime_bundles VALUES(?,?,1)",
            [digest, binary],
        )?;
        if self.bundle(digest)? != binary {
            return Err(conflict(
                "E_IDEMPOTENCY_CONFLICT",
                "bundle digest already has a different executable",
            ));
        }
        Ok(json!({"bundle_digest":digest, "executable_sha256":binary, "protocol_major":1}))
    }

    pub fn operation(&self, id: &str) -> Result<Operation> {
        let mut operation = op(&self.db, id)?.ok_or_else(|| not_found("operation"))?;
        operation.native = crate::native_operations::progress(&self.db, id)?;
        if operation.launches_execution() && operation.phase == "COMPLETED" {
            operation.execution = self.db.query_row(
                "SELECT e.instance_id,e.incarnation_id,e.execution_epoch FROM managed_launches m JOIN executions e USING(incarnation_id) WHERE m.operation_id=? AND e.last_operation_id=m.operation_id",
                [id], |row| Ok(Expected {instance_id:row.get(0)?, incarnation_id:row.get(1)?, execution_epoch:row.get(2)?})).optional()?;
        }
        if operation.kind == "launch" && operation.execution.is_some() {
            operation.boot_environment = crate::boot_environment::receipt(&self.db, &operation)?;
        }
        if matches!(operation.kind.as_str(), "independent_fork" | "fork_batch") {
            operation.fork = crate::managed_fork::receipt(self, &operation.operation_id)?;
        }
        if matches!(operation.kind.as_str(), "vm_snapshot" | "hibernate" | "vm_rollback") {
            operation.statepoint=crate::managed_statepoint::receipt(self,&operation)?;
            if operation.kind=="vm_rollback" && operation.phase=="COMPLETED" {
                operation.execution=self.db.query_row("SELECT e.instance_id,e.incarnation_id,e.execution_epoch FROM managed_fork_batches b
                    JOIN managed_launches m ON m.operation_id=b.target_operation_id JOIN executions e USING(incarnation_id)
                    WHERE b.operation_id=?", [&operation.operation_id],|r|Ok(Expected {instance_id:r.get(0)?,incarnation_id:r.get(1)?,execution_epoch:r.get(2)?})).optional()?;
            }
        }
        if operation.kind == "restore_target" {
            operation.statepoint = crate::managed_state_restore::receipt(self, &operation)?;
            if operation.phase == "COMPLETED" && operation.statepoint.is_none() {
                operation.fork = crate::product_volumes::fork_volume_receipt(self, &operation)?;
            }
        }
        if operation.kind == crate::resource_resize::KIND {
            operation.resize = crate::resource_resize::progress(&self.db, id)?;
        }
        Ok(operation)
    }

    pub fn begin(&mut self, r: &Request, kind: &str) -> Result<Operation> {
        self.begin_with(r, kind, |_| Ok(()))
    }

    pub(crate) fn begin_with(
        &mut self,
        r: &Request,
        kind: &str,
        record: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<()>,
    ) -> Result<Operation> {
        self.begin_with_handoff(r, kind, None, record)
    }

    pub(crate) fn begin_with_handoff(
        &mut self,
        r: &Request,
        kind: &str,
        predecessor: Option<&str>,
        record: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<()>,
    ) -> Result<Operation> {
        let (id, digest) = r.operation()?;
        let (route, bundle, expected) = r.scope()?;
        identifier(kind)?;
        if let Some(prior) = op(&self.db, id)? {
            if prior.kind == kind
                && prior.request_digest == digest
                && prior.route_id == route
                && prior.bundle_digest == bundle
                && prior.instance_id == expected.instance_id
                && prior.expected_execution_epoch == expected.execution_epoch
                && prior.expected_incarnation_id == expected.incarnation_id
            {
                return self.operation(id);
            }
            return Err(conflict(
                "E_IDEMPOTENCY_CONFLICT",
                "operation ID already has a different intent",
            ));
        }
        self.ready()?;
        self.bundle(bundle)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (epoch, incarnation, active) = binding(&tx, route, &expected.instance_id)?;
        if epoch != expected.execution_epoch || incarnation != expected.incarnation_id {
            return Err(stale());
        }
        if active.as_deref() != predecessor {
            return Err(conflict(
                "E_OPERATION_IN_PROGRESS",
                "this instance already has an active operation",
            ));
        }
        tx.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,'NEW','NONE',1)",
            params![
                id,
                kind,
                digest,
                route,
                expected.instance_id,
                bundle,
                epoch,
                incarnation
            ],
        )?;
        tx.execute("INSERT INTO instance_bindings(route_id,instance_id,execution_epoch,active_operation_id)
            VALUES(?,?,0,?) ON CONFLICT(route_id,instance_id) DO UPDATE SET active_operation_id=excluded.active_operation_id",
            params![route, expected.instance_id, id])?;
        record(&tx)?;
        tx.commit()?;
        self.operation(id)
    }

    pub fn matching_operation(&self, request: &Request) -> Result<Operation> {
        let (id, digest) = request.operation()?;
        let (route, bundle, expected) = request.scope()?;
        let operation = self.operation(id)?;
        if operation.request_digest != digest
            || operation.route_id != route
            || operation.bundle_digest != bundle
            || operation.instance_id != expected.instance_id
        {
            return Err(conflict(
                "E_IDEMPOTENCY_CONFLICT",
                "operation scope or digest changed",
            ));
        }
        Ok(operation)
    }

    pub fn active_operation(&self, request: &Request) -> Result<Operation> {
        let operation = self.matching_operation(request)?;
        if operation.phase != "NEW" {
            return Err(conflict("E_OPERATION_FINALIZED", "operation is final"));
        }
        let (route, _, expected) = request.scope()?;
        let (epoch, incarnation, active) = binding(&self.db, route, &expected.instance_id)?;
        if epoch != expected.execution_epoch
            || incarnation != expected.incarnation_id
            || active.as_deref() != Some(&operation.operation_id)
        {
            return Err(stale());
        }
        Ok(operation)
    }

    pub fn finish(&mut self, r: &Request, abort: bool, revision: i64) -> Result<Operation> {
        if crate::native_operations::progress(&self.db, r.operation()?.0)?.is_some() {
            return Err(conflict(
                "E_OPERATION_HAS_EFFECTS",
                "native execution outcome is owned by the Worker actor",
            ));
        }
        let mut operation = self.matching_operation(r)?;
        if operation.kind == crate::managed_retirement::KIND {
            return Err(conflict(
                "E_OPERATION_HAS_EFFECTS",
                "instance retirement requires Worker reconciliation",
            ));
        }
        if operation.kind == "managed_cpu_limit" {
            return Err(conflict(
                "E_OPERATION_HAS_EFFECTS",
                "the Worker owns the managed CPU limit outcome",
            ));
        }
        if matches!(operation.kind.as_str(), "independent_fork" | "fork_batch" | "vm_snapshot" | "hibernate" | "vm_rollback") {
            return Err(conflict(
                "E_OPERATION_HAS_EFFECTS",
                "a managed fork is owned by the capture actor",
            ));
        }
        let final_phase = if abort { "ABORTED" } else { "COMPLETED" };
        if operation.phase == final_phase
            && (operation.revision == revision
                || revision.checked_add(1) == Some(operation.revision))
        {
            return Ok(operation);
        }
        operation = self.active_operation(r)?;
        if operation.revision != revision {
            return Err(conflict("E_STALE_REVISION", "operation revision changed"));
        }
        let id = &operation.operation_id;
        if abort && crate::managed::live_claim(self, id)?.is_some() {
            return Err(conflict("E_OPERATION_IN_PROGRESS", "managed launch process still exists"));
        }
        let restored_products = if !abort && operation.kind == "restore_target" {
            crate::product_volumes::independent_restore_products(self, &operation)?
        } else {
            Vec::new()
        };
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !abort && operation.launches_execution() {
            let registered: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM executions WHERE last_operation_id=? AND phase='registered')",
                [id],
                |r| r.get(0),
            )?;
            if !registered {
                return Err(conflict(
                    "E_OPERATION_IN_PROGRESS",
                    "launch has no registered execution",
                ));
            }
        }
        if !abort && operation.kind == "launch" {
            crate::boot_environment::require_applied(&tx, id)?;
            let unpublished: bool = tx.query_row(
                "SELECT (
                    EXISTS(SELECT 1 FROM managed_launches WHERE operation_id=?1 AND json_extract(spec_json,'$.network') IS NOT NULL)
                    AND NOT EXISTS(SELECT 1 FROM network_attachments WHERE operation_id=?1 AND state='reserved')
                 ) OR EXISTS(SELECT 1 FROM network_attachments a
                 WHERE a.operation_id=?1 AND a.state<>'released' AND NOT EXISTS (
                    SELECT 1 FROM network_tap_leases l JOIN initial_network_activations i USING(lease_id)
                    WHERE l.attachment_id=a.attachment_id AND l.state='attached' AND i.phase='open'
                 ))",
                [id], |row| row.get(0),
            )?;
            if unpublished {
                return Err(conflict(
                    "E_FENCE_UNPROVEN",
                    "cold execution network is still quarantined",
                ));
            }
        }
        if operation.kind == "restore_target" {
            // A commit intent can outlive a target that never reached recorded publication.
            // Accept its failure only after the exact execution has been fenced.
            let finalized: bool = tx.query_row(
                "SELECT CASE WHEN ?1 THEN NOT EXISTS (
                    SELECT 1 FROM target_activations a WHERE a.operation_id=?2 AND a.decision='commit'
                      AND NOT (
                        a.phase='failed_held' AND EXISTS (
                          SELECT 1 FROM executions e JOIN instance_bindings b
                            ON b.route_id=e.route_id AND b.instance_id=e.instance_id AND b.execution_epoch=e.execution_epoch
                          WHERE e.incarnation_id=a.incarnation_id AND e.execution_epoch=a.execution_epoch
                            AND e.last_operation_id=a.operation_id AND e.instance_id=a.instance_id
                            AND e.bundle_digest=a.bundle_digest AND e.host_boot_id=a.host_boot_id
                            AND e.phase='exited' AND b.incarnation_id IS NULL AND b.active_operation_id=a.operation_id
                        ) AND NOT EXISTS (
                          SELECT 1 FROM network_tap_leases t LEFT JOIN network_kernel_receipts k USING(lease_id)
                          WHERE t.incarnation_id=a.incarnation_id AND t.execution_epoch=a.execution_epoch
                            AND (t.state<>'retired' OR k.lease_id IS NOT NULL)
                        )
                      )
                ) ELSE EXISTS (
                    SELECT 1 FROM target_activations WHERE operation_id=?2 AND phase='released' AND decision='commit'
                ) END",
                params![abort, id], |r| r.get(0),
            )?;
            if !finalized {
                return Err(conflict(
                    "E_FENCE_UNPROVEN",
                    "restore target activation has no compatible final decision",
                ));
            }
        }
        if let Some((incarnation, attached)) = tx
            .query_row(
                "SELECT incarnation_id,disks_attached FROM managed_launches WHERE operation_id=?",
                [id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
        {
            tx.execute("UPDATE managed_budget_holds SET state=?,incarnation_id=? WHERE operation_id=? AND instance_id=? AND state='reserved'", params![if abort {"released"} else {"running"},incarnation,id,operation.instance_id])?;
            if !abort {
                let bound = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM native_endpoints WHERE incarnation_id=?)",
                    [&incarnation],
                    |row| row.get::<_, bool>(0),
                )?;
                if !attached || !bound {
                    return Err(conflict(
                        "E_FENCE_UNPROVEN",
                        "managed VMM has no confirmed endpoint and disk set",
                    ));
                }
                tx.execute("INSERT OR IGNORE INTO root_refs(owner_kind,owner_id,resource_id,state,revision,created_by_operation)
                    SELECT 'managed_execution',?,resource_id,'active',1,? FROM root_refs WHERE owner_kind='operation' AND owner_id=? AND state='active'",
                    params![incarnation,id,id])?;
            }
            tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='operation' AND owner_id=? AND state='active'",[id])?;
        }
        let occupied: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM writer_reservations r LEFT JOIN writer_grants g USING(operation_id)
                WHERE r.operation_id=? AND (? OR g.grant_id IS NULL OR g.state!='attached'))
             OR (? AND EXISTS (SELECT 1 FROM executions WHERE last_operation_id=? AND (? OR phase<>'exited')))
             OR (? AND EXISTS (SELECT 1 FROM network_tap_leases l JOIN network_attachments a USING(attachment_id) WHERE a.operation_id=? AND l.state<>'retired'))
             OR EXISTS (SELECT 1 FROM root_refs WHERE owner_kind='operation' AND owner_id=? AND state='active')
             OR EXISTS (SELECT 1 FROM fd_transfers WHERE operation_id=? AND state='staging')
             OR EXISTS (SELECT 1 FROM fd_leases WHERE operation_id=? AND state='pending')
             OR EXISTS (SELECT 1 FROM managed_blocks WHERE operation_id=? AND backing_identity IS NULL)
             OR EXISTS (SELECT 1 FROM root_refs WHERE owner_kind='block_seal' AND owner_id=? AND state='active')
             OR EXISTS (SELECT 1 FROM writer_pivots WHERE operation_id=? AND state NOT IN ('complete','aborted'))",
            params![id, abort, abort, id, !matches!(operation.kind.as_str(), "launch" | "restore_target"), abort, id, id, id, id, id, id, id], |r| r.get(0))?;
        if occupied {
            return Err(conflict(
                "E_OPERATION_HAS_EFFECTS",
                "operation retains a reservation, root pin, or registered execution",
            ));
        }
        crate::product_volumes::publish_restore_products(&tx, &operation, restored_products)?;
        tx.execute(
            "UPDATE operations SET phase=?,decision=?,revision=revision+1 WHERE operation_id=?",
            params![final_phase, if abort { "ABORT" } else { "NONE" }, id],
        )?;
        tx.execute(
            "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
            [id],
        )?;
        tx.commit()?;
        self.operation(id)
    }

    pub fn verify_launch(&self, operation: &Operation, expected: &Expected) -> Result<()> {
        self.ready()?;
        let (epoch, incarnation, active) =
            binding(&self.db, &operation.route_id, &operation.instance_id)?;
        if incarnation.is_some()
            || active.as_deref() != Some(&operation.operation_id)
            || epoch.checked_add(1) != Some(expected.execution_epoch)
            || expected.incarnation_id.is_none()
            || operation.phase != "NEW"
        {
            return Err(stale());
        }
        let planned: Option<String> = self.db.query_row(
            "SELECT incarnation_id FROM managed_launches WHERE operation_id=?",
            [&operation.operation_id], |row| row.get(0),
        ).optional()?;
        if planned.is_some() && planned != expected.incarnation_id {
            return Err(stale());
        }
        Ok(())
    }

    pub fn register_execution(
        &mut self,
        operation: &Operation,
        new: NewExecution<'_>,
    ) -> Result<Execution> {
        self.verify_launch(operation, new.expected)?;
        let incarnation = new.expected.incarnation_id.as_ref().ok_or_else(stale)?;
        if exec(&self.db, incarnation)?.is_some() {
            return Err(conflict(
                "E_IDEMPOTENCY_CONFLICT",
                "incarnation ID already exists",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let process_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE host_boot_id=? AND pid=? AND pid_start_time=? AND phase!='exited')",
            params![new.boot,new.pid,new.start], |row| row.get(0))?;
        if process_exists {
            return Err(conflict(
                "E_IDEMPOTENCY_CONFLICT",
                "process already belongs to an execution",
            ));
        }
        tx.execute(
            "INSERT INTO executions(incarnation_id,route_id,instance_id,execution_epoch,bundle_digest,host_boot_id,
             pid,pid_start_time,uid,phase,last_operation_id,launch_permit_digest) VALUES(?,?,?,?,?,?,?,?,?,'registered',?,?)",
            params![
                incarnation,
                new.route,
                new.expected.instance_id,
                new.expected.execution_epoch,
                new.bundle,
                new.boot,
                new.pid,
                new.start,
                new.uid,
                operation.operation_id,
                new.permit_digest
            ],
        )?;
        tx.execute("UPDATE instance_bindings SET incarnation_id=?,execution_epoch=? WHERE route_id=? AND instance_id=?",
            params![incarnation, new.expected.execution_epoch, new.route, new.expected.instance_id])?;
        if let Some(import) = new.kernel_import {
            tx.execute(
                "INSERT INTO kernel_cow_imports(incarnation_id,capture_id,proof_digest) VALUES(?,?,?)",
                params![incarnation, import.capture_id, import.proof_digest],
            )?;
        }
        tx.commit()?;
        self.execution(incarnation)
    }

    pub fn query_binding(&self, r: &Request) -> Result<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Instance {
            instance_id: String,
        }
        let input: Instance = r.payload()?;
        let id = identifier(&input.instance_id)?;
        let route = r
            .route_id
            .as_deref()
            .ok_or_else(|| Fault::invalid("missing route"))?;
        let bundle = r
            .bundle_digest
            .as_deref()
            .ok_or_else(|| Fault::invalid("missing bundle"))?;
        self.bundle(bundle)?;
        let (epoch, incarnation, active) = binding(&self.db, route, id)?;
        // A shared resource catalog must not leak another bundle's instance.
        if let Some(incarnation) = &incarnation {
            if self.execution(incarnation)?.bundle_digest != bundle {
                return Err(not_found("execution"));
            }
        } else if epoch > 0 {
            let prior:String=self.db.query_row("SELECT bundle_digest FROM executions WHERE route_id=? AND instance_id=? AND execution_epoch=?",
                params![route,id,epoch], |row|row.get(0))?;
            if prior != bundle {
                return Err(not_found("execution"));
            }
        }
        if let Some(op_id) = &active {
            if self.operation(op_id)?.bundle_digest != bundle {
                return Err(not_found("execution"));
            }
        }
        Ok(
            json!({"instance_id":id,"execution_epoch":epoch,"incarnation_id":incarnation,"active_operation_id":active}),
        )
    }

    pub fn execution(&self, id: &str) -> Result<Execution> {
        exec(&self.db, id)?.ok_or_else(|| not_found("execution"))
    }

    pub fn execution_by_permit(&self, id: &str, permit_digest: &str) -> Result<Option<Execution>> {
        Ok(self
            .db
            .query_row(
                &format!(
                    "SELECT {EXEC_COLUMNS} FROM executions
            WHERE incarnation_id=? AND launch_permit_digest=?"
                ),
                [id, permit_digest],
                execution_row,
            )
            .optional()?)
    }

    pub fn reconcile_execution(&self, id: &str) -> Result<Execution> {
        self.db.execute(
            "UPDATE executions SET phase='registered' WHERE incarnation_id=? AND phase='unknown'",
            [id],
        )?;
        self.execution(id)
    }

    pub fn finalize_execution(&mut self, execution: &Execution) -> Result<Execution> {
        let id = &execution.incarnation_id;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM writer_reservations WHERE incarnation_id=?)",
            [id],
            |r| r.get(0),
        )?;
        if reserved {
            return Err(conflict(
                "E_FENCE_UNPROVEN",
                "execution still has a writer reservation",
            ));
        }
        tx.execute(
            "UPDATE executions SET phase='exited' WHERE incarnation_id=?",
            [id],
        )?;
        tx.execute(
            "UPDATE instance_bindings SET incarnation_id=NULL WHERE incarnation_id=?",
            [id],
        )?;
        crate::managed_fork::source_exited(&tx,id)?;
        crate::worker::abort_cpu_limits_for_exit(&tx, id)?;
        crate::resource_resize::execution_exited(&tx,id)?;
        tx.execute("UPDATE lifecycle_protections SET state='released',reason='execution fenced',revision=revision+1
            WHERE incarnation_id=? AND kind IN ('hold','lease') AND state IN ('suspect','active')",[id])?;
        tx.execute("UPDATE managed_budget_holds SET state='released' WHERE incarnation_id=? AND state='running'",[id])?;
        crate::escrow_catalog::release_execution(&tx, id)?;
        tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='managed_execution' AND owner_id=? AND state='active'",[id])?;
        crate::activation_catalog::record_exit(&tx, id)?;
        tx.commit()?;
        self.execution(id)
    }

    pub fn register_resource(
        &self,
        r: &Request,
        id: &str,
        durability: &str,
        mut descriptor: Value,
    ) -> Result<Value> {
        self.ready()?;
        let operation = self.active_operation(r)?;
        identifier(id)?;
        if !matches!(durability, "volatile" | "durable") || !descriptor.is_object() {
            return Err(Fault::invalid(
                "resource requires an object descriptor and valid durability",
            ));
        }
        descriptor.sort_all_objects();
        let bytes = descriptor.to_string();
        if bytes.len() > 16 * 1024 {
            return Err(Fault::invalid(
                "resource descriptor exceeds the catalog limit",
            ));
        }
        let digest = format!("sha256:{:x}", Sha256::digest(bytes.as_bytes()));
        self.db.execute(
            "INSERT OR IGNORE INTO resources VALUES
            (?,'descriptor','available',?,1,?,?,?,1)",
            params![id, durability, bytes, digest, operation.operation_id],
        )?;
        let result = self.resource(id)?;
        if result["created_by_operation"] != operation.operation_id
            || result["descriptor_digest"] != digest
            || result["durability"] != durability
            || result["kind"] != "descriptor"
        {
            return Err(conflict(
                "E_IDEMPOTENCY_CONFLICT",
                "resource ID already has a different definition",
            ));
        }
        Ok(result)
    }

    pub fn resource(&self, id: &str) -> Result<Value> {
        self.db.query_row("SELECT r.resource_id,
            CASE WHEN k.resource_id IS NOT NULL THEN 'kernel_mm_anchor' ELSE r.kind END,
            CASE WHEN f.state='missing' THEN 'missing' ELSE r.state END,
            r.durability,r.immutable,r.descriptor_json,r.descriptor_digest,r.created_by_operation,r.revision,f.state
            FROM resources r LEFT JOIN fd_transfers f ON f.resource_id=r.resource_id AND f.state!='staging'
            LEFT JOIN kernel_mm_anchors k ON k.resource_id=r.resource_id
            WHERE r.resource_id=?", [id], |r| {
            let descriptor: String = r.get(5)?;
            let parsed: Value = serde_json::from_str(&descriptor)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e)))?;
            let mut record = json!({"resource_id":r.get::<_,String>(0)?, "kind":r.get::<_,String>(1)?,
                "state":r.get::<_,String>(2)?, "durability":r.get::<_,String>(3)?, "immutable":r.get::<_,bool>(4)?,
                "descriptor":parsed, "descriptor_digest":r.get::<_,String>(6)?,
                "created_by_operation":r.get::<_,String>(7)?, "revision":r.get::<_,i64>(8)?});
            if let Some(state) = r.get::<_, Option<String>>(9)? {
                record["fd_state"] = json!(state);
            }
            Ok(record)
        }).optional()?.ok_or_else(|| not_found("resource"))
    }

    pub fn add_edge(&mut self, r: &Request, owner: &str, child: &str, role: &str) -> Result<Value> {
        self.ready()?;
        self.active_operation(r)?;
        identifier(role)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        resource_available(&tx, owner)?;
        resource_available(&tx, child)?;
        let creates_cycle: bool = tx.query_row(
            "WITH RECURSIVE closure(id) AS (SELECT ? UNION
             SELECT e.child_resource_id FROM resource_edges e JOIN closure c ON e.owner_resource_id=c.id)
             SELECT EXISTS(SELECT 1 FROM closure WHERE id=?)", [child, owner], |row| row.get(0))?;
        if creates_cycle {
            return Err(conflict(
                "E_RESOURCE_CYCLE",
                "edge would make the resource graph cyclic",
            ));
        }
        tx.execute(
            "INSERT OR IGNORE INTO resource_edges VALUES(?,?,?)",
            [owner, child, role],
        )?;
        tx.commit()?;
        Ok(json!({"owner_resource_id":owner,"child_resource_id":child,"role":role}))
    }

    pub fn set_ref(
        &mut self,
        r: &Request,
        kind: &str,
        owner: &str,
        resource: &str,
        revision: i64,
        add: bool,
    ) -> Result<Value> {
        if add {
            self.ready()?;
        }
        let op = self.active_operation(r)?;
        identifier(kind)?;
        if matches!(
            kind,
            "fd_lease"
                | "block_seal"
                | "statepoint_checkpoint"
                | "statepoint_hibernate"
                | "statepoint_rescue"
                | "backup"
                | "backup_import"
                | crate::disk_closure_import::KIND
                | "fork_capture"
                | "kernel_anchor_export"
                | "managed_execution"
                | "product_snapshot"
                | "product_attachment"
        ) {
            return Err(Fault::invalid(
                "this root kind is controlled by the resource protocol",
            ));
        }
        identifier(owner)?;
        identifier(resource)?;
        if kind == "operation" && owner != op.operation_id {
            return Err(Fault::invalid(
                "operation pin owner must match the active operation",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<(String, i64, String)> = tx.query_row(
            "SELECT state,revision,created_by_operation FROM root_refs WHERE owner_kind=? AND owner_id=? AND resource_id=?",
            [kind, owner, resource], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?;
        let old_revision = prior.as_ref().map_or(0, |(_, revision, _)| *revision);
        let state = if add { "active" } else { "dropped" };
        let new_revision = if prior.as_ref().is_some_and(|(old_state, _, operation)| {
            old_state == state
                && (revision == old_revision
                    || (operation == &op.operation_id
                        && revision.checked_add(1) == Some(old_revision)))
        }) {
            old_revision
        } else {
            if revision != old_revision {
                return Err(conflict(
                    "E_STALE_REVISION",
                    "root reference revision changed",
                ));
            }
            if add {
                resource_available(&tx, resource)?;
            }
            if !add && prior.is_none() {
                return Err(not_found("root reference"));
            }
            let new_revision = revision
                .checked_add(1)
                .ok_or_else(|| conflict("E_STALE_REVISION", "root revision exhausted"))?;
            tx.execute("INSERT INTO root_refs VALUES(?,?,?,?,?,?) ON CONFLICT(owner_kind,owner_id,resource_id)
                DO UPDATE SET state=excluded.state,revision=excluded.revision,created_by_operation=excluded.created_by_operation",
                params![kind,owner,resource,state,new_revision,op.operation_id])?;
            if !add && kind == "operation" {
                crate::escrow_catalog::lose_missing_without_provider(&tx)?;
            }
            new_revision
        };
        tx.commit()?;
        Ok(
            json!({"owner_kind":kind,"owner_id":owner,"resource_id":resource,"state":state,"revision":new_revision}),
        )
    }

    pub fn closure(&self, kind: &str, id: &str) -> Result<Value> {
        let mut statement = self.db.prepare(
            "WITH RECURSIVE closure(id) AS (
               SELECT resource_id FROM root_refs WHERE owner_kind=? AND owner_id=? AND state='active'
               UNION SELECT e.child_resource_id FROM resource_edges e JOIN closure c ON e.owner_resource_id=c.id)
             SELECT r.resource_id,CASE WHEN f.state='missing' THEN 'missing' ELSE r.state END
             FROM closure c JOIN resources r ON r.resource_id=c.id
             LEFT JOIN fd_transfers f ON f.resource_id=r.resource_id AND f.state!='staging'
             ORDER BY r.resource_id LIMIT 513")?;
        let rows = statement
            .query_map([identifier(kind)?, identifier(id)?], |r| {
                Ok(json!({"resource_id":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?}))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > 512 {
            return Err(conflict(
                "E_RESOURCE_LIMIT",
                "root closure exceeds the current query limit",
            ));
        }
        Ok(json!({"owner_kind":kind,"owner_id":id,"resources":rows}))
    }

    pub fn mark_gc(&mut self, id: &str, revision: i64) -> Result<Value> {
        self.ready()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_gc(&tx, id, revision, "available")?;
        tx.execute(
            "UPDATE resources SET state='deleting',revision=revision+1 WHERE resource_id=?",
            [id],
        )?;
        tx.commit()?;
        self.resource(id)
    }

    pub(crate) fn collect_gc(
        &mut self,
        id: &str,
        revision: i64,
        remove_backing: impl FnOnce(&Self) -> Result<()>,
    ) -> Result<Value> {
        self.ready()?;
        // Keep the deletion fence and ancestry intact until the storage owner
        // has finished. On failure the committed deleting row is retryable.
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let already_deleted: Option<i64> = tx.query_row(
            "SELECT revision FROM resources WHERE resource_id=? AND state='deleted'",
            [identifier(id)?], |row| row.get(0),
        ).optional()?;
        if already_deleted.is_some() && already_deleted == revision.checked_add(1) {
            // Older Workers could commit the receipt before unlinking a block.
            remove_backing(self)?;
            return self.resource(id);
        }
        check_gc(&tx, id, revision, "deleting")?;
        remove_backing(self)?;
        tx.execute(
            "UPDATE resources SET state='deleted',revision=revision+1 WHERE resource_id=?",
            [id],
        )?;
        tx.execute("DELETE FROM resource_edges WHERE owner_resource_id=?", [id])?;
        tx.execute("UPDATE fd_transfers SET state='collected' WHERE resource_id=? AND state='committed'", [id])?;
        tx.commit()?;
        self.resource(id)
    }

    pub(crate) fn pending_gc(&self, after_row: i64) -> Result<Vec<(i64, String, i64, bool)>> {
        let mut query = self.db.prepare(
            "SELECT r.rowid,r.resource_id,r.revision,r.state='available' FROM resources r
             WHERE r.rowid>? AND (r.state='deleting' OR (r.state='available'
                AND EXISTS(SELECT 1 FROM root_refs p WHERE p.resource_id=r.resource_id
                  AND p.owner_kind IN ('statepoint_checkpoint','statepoint_hibernate') AND p.state='dropped')
                AND NOT EXISTS(SELECT 1 FROM root_refs p WHERE p.resource_id=r.resource_id AND p.state='active')
                AND NOT EXISTS(SELECT 1 FROM resource_edges e WHERE e.child_resource_id=r.resource_id)
                AND NOT EXISTS(SELECT 1 FROM fd_leases l WHERE l.resource_id=r.resource_id AND l.state<>'released')
                AND NOT EXISTS(SELECT 1 FROM writer_reservations w WHERE w.head_resource_id=r.resource_id)))
             ORDER BY r.rowid LIMIT 16",
        )?;
        let rows = query.query_map([after_row], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub(crate) fn unused_fork_ram(&self) -> Result<Vec<(String, String, i64)>> {
        let mut query = self.db.prepare(
            "SELECT r.resource_id,r.state,r.revision FROM resources r
             JOIN managed_fork_batches b ON b.capture_id=r.resource_id
             JOIN operations o ON o.operation_id=b.operation_id AND o.operation_id=r.created_by_operation
             WHERE o.kind IN ('independent_fork','fork_batch') AND o.phase IN ('COMPLETED','ABORTED')
               AND r.kind='descriptor' AND r.durability='volatile' AND r.state IN ('available','deleting')
               AND NOT EXISTS(SELECT 1 FROM root_refs WHERE resource_id=r.resource_id AND state='active')
               AND NOT EXISTS(SELECT 1 FROM resource_edges WHERE child_resource_id=r.resource_id)
               AND NOT EXISTS(SELECT 1 FROM fd_leases WHERE resource_id=r.resource_id AND state<>'released')
               AND NOT EXISTS(SELECT 1 FROM writer_reservations WHERE head_resource_id=r.resource_id)
             ORDER BY r.rowid LIMIT 16",
        )?;
        let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn register_volume(
        &mut self,
        r: &Request,
        head: &VolumeHead,
        identity: &str,
    ) -> Result<Value> {
        self.ready()?;
        let op = self.active_operation(r)?;
        identifier(&head.volume_id)?;
        identifier(&head.head_resource_id)?;
        let descriptor = json!({"backing_identity":identity}).to_string();
        let digest = format!("sha256:{:x}", Sha256::digest(descriptor.as_bytes()));
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO resources VALUES
            (?,'block_head','available','durable',0,?,?,?,1)",
            params![head.head_resource_id, descriptor, digest, op.operation_id],
        )?;
        let valid: bool = tx.query_row(
            "SELECT kind='block_head' AND descriptor_digest=? AND state='available'
            FROM resources WHERE resource_id=?",
            params![digest, head.head_resource_id],
            |r| r.get(0),
        )?;
        if !valid {
            return Err(conflict(
                "E_IDEMPOTENCY_CONFLICT",
                "head resource already has a different definition",
            ));
        }
        tx.execute(
            "INSERT OR IGNORE INTO volume_heads VALUES(?,?,?)",
            params![head.volume_id, head.head_resource_id, identity],
        )?;
        let valid: bool = tx.query_row(
            "SELECT head_resource_id=? AND backing_identity=? FROM volume_heads WHERE volume_id=?",
            params![head.head_resource_id, identity, head.volume_id],
            |r| r.get(0),
        )?;
        if !valid {
            return Err(conflict(
                "E_STALE_REVISION",
                "volume already has a different head",
            ));
        }
        tx.commit()?;
        Ok(json!({"volume_id":head.volume_id,"head_resource_id":head.head_resource_id}))
    }

    pub fn volume_identity(&self, head: &VolumeHead) -> Result<String> {
        self.db.query_row("SELECT backing_identity FROM volume_heads WHERE volume_id=? AND head_resource_id=?",
            params![identifier(&head.volume_id)?, identifier(&head.head_resource_id)?], |r| r.get(0)).optional()?
            .ok_or_else(|| conflict("E_STALE_REVISION", "volume head changed or is not registered"))
    }

    pub fn writer_set(&self, operation_id: &str) -> Result<Option<WriterSet>> {
        Ok(self
            .db
            .query_row(
                "SELECT heads_json,state,revision FROM writer_sets WHERE operation_id=?",
                [operation_id],
                |r| {
                    let text: String = r.get(0)?;
                    let heads = serde_json::from_str(&text).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    Ok(WriterSet {
                        heads,
                        state: r.get(1)?,
                        revision: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn reserve_writers(
        &mut self,
        op: &Operation,
        execution: &Execution,
        heads: &[(VolumeHead, String)],
    ) -> Result<()> {
        self.ready()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let manifest = json!(heads.iter().map(|(head, _)| head).collect::<Vec<_>>()).to_string();
        tx.execute(
            "INSERT INTO writer_sets VALUES(?,?,'reserved',1)",
            params![op.operation_id, manifest],
        )?;
        for (head, identity) in heads {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO writer_reservations VALUES(?,?,?,?,?,?)",
                params![
                    head.volume_id,
                    head.head_resource_id,
                    identity,
                    op.operation_id,
                    execution.incarnation_id,
                    execution.execution_epoch
                ],
            )?;
            if inserted != 1 {
                return Err(conflict(
                    "E_VOLUME_WRITER_CONFLICT",
                    "a volume or its backing already has a reservation",
                ));
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn release_reservation(&mut self, id: &str, revision: i64) -> Result<()> {
        if self
            .grant_for_operation(id)?
            .is_some_and(|grant| grant.state != "released")
        {
            return Err(crate::grants::fence_unproven(
                "a writer set was issued to a VMM and requires an execution fence",
            ));
        }
        let existing = self
            .writer_set(id)?
            .ok_or_else(|| not_found("writer reservation"))?;
        if existing.state == "released"
            && (existing.revision == revision || revision.checked_add(1) == Some(existing.revision))
        {
            return Ok(());
        }
        if existing.state != "reserved" || existing.revision != revision {
            return Err(conflict(
                "E_STALE_REVISION",
                "writer reservation revision changed",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM writer_reservations WHERE operation_id=?", [id])?;
        tx.execute(
            "UPDATE writer_sets SET state='released', revision=revision+1 WHERE operation_id=?",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }
}
