use crate::catalog::{Catalog, Execution, Operation};
use crate::ipc::{Fault, Result};
use crate::network::{topology::KernelProof, NamespaceIdentity};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AttachmentDescriptor {
    pub schema: String,
    pub attachment_id: String,
    pub route_domain_id: String,
    pub private_ipv4: Ipv4Addr,
    pub guest_ipv4: Ipv4Addr,
    pub guest_prefix: u8,
    pub gateway_ipv4: Ipv4Addr,
    pub device_id: String,
    pub mac: [u8; 6],
    pub mode: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct TapLease {
    pub lease_id: String,
    pub operation_id: String,
    pub route_id: String,
    pub bundle_digest: String,
    pub instance_id: String,
    pub incarnation_id: Option<String>,
    pub execution_epoch: Option<i64>,
    pub host_boot_id: String,
    pub broker_session_id: String,
    pub state: String,
    pub gate: String,
    pub revision: i64,
    pub attachment: AttachmentDescriptor,
}

impl TapLease {
    pub fn attachment_digest(&self) -> Result<[u8; 32]> {
        let encoded = serde_json::to_vec(&(
            &self.lease_id,
            &self.operation_id,
            &self.route_id,
            &self.bundle_digest,
            &self.instance_id,
            &self.incarnation_id,
            &self.execution_epoch,
            &self.host_boot_id,
            &self.broker_session_id,
            &self.attachment,
        ))
        .map_err(|_| Fault::new("E_CATALOG", "cannot encode network lease binding"))?;
        Ok(Sha256::digest(encoded).into())
    }

    pub(crate) fn matches(&self, execution: &Execution) -> bool {
        self.route_id == execution.route_id
            && self.bundle_digest == execution.bundle_digest
            && self.instance_id == execution.instance_id
            && self.operation_id == execution.last_operation_id
            && self.host_boot_id == execution.host_boot_id
            && self.incarnation_id.as_deref() == Some(execution.incarnation_id.as_str())
            && self.execution_epoch == Some(execution.execution_epoch)
    }
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch(include_str!("schema_network_leases.sql"))?;
    Ok(())
}

pub(crate) fn install_initial_activations(db: &Connection) -> Result<()> {
    db.execute_batch(include_str!("schema_initial_network_activations.sql"))?;
    Ok(())
}

pub(crate) fn recover(db: &Connection) -> Result<()> {
    // Quarantined rows had never been sent, so this new broker can prepare a
    // replacement. Offers can remain with a live process after broker loss.
    db.execute(
        "UPDATE network_tap_leases SET state=CASE state WHEN 'quarantined' THEN 'retired' ELSE 'unknown' END,
            revision=revision+1 WHERE state IN ('quarantined','offered','attached')",
        [],
    )?;
    Ok(())
}

fn read(db: &Connection, id: &str) -> Result<Option<TapLease>> {
    Ok(db.query_row(
        "SELECT lease_id,operation_id,route_id,bundle_digest,instance_id,incarnation_id,execution_epoch,
                host_boot_id,broker_session_id,state,revision,descriptor_json,
                CASE
                  WHEN state='unknown' THEN 'unknown'
                  WHEN EXISTS (SELECT 1 FROM machine_migration_source_taps f
                    WHERE f.lease_id=network_tap_leases.lease_id AND f.phase<>'reopened') THEN 'closed'
                  WHEN state='attached' THEN COALESCE((
                    SELECT CASE a.phase WHEN 'policy_armed' THEN 'armed' WHEN 'released' THEN 'open' WHEN 'unknown' THEN 'unknown' ELSE 'closed' END
                    FROM target_activations a
                    WHERE a.operation_id=network_tap_leases.operation_id
                      AND a.incarnation_id=network_tap_leases.incarnation_id
                      AND a.execution_epoch=network_tap_leases.execution_epoch
                      AND json_extract(a.binding_json, '$.network.target.lease_id')=network_tap_leases.lease_id
                  ), (SELECT phase FROM initial_network_activations WHERE lease_id=network_tap_leases.lease_id), 'closed')
                  ELSE 'closed'
                END
         FROM network_tap_leases WHERE attachment_id=? AND state<>'retired'",
        [id],
        |row: &Row<'_>| {
            let descriptor: String = row.get(11)?;
            let state = row.get::<_, String>(9)?;
            let gate = row.get(12)?;
            let attachment = serde_json::from_str(&descriptor).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(error))
            })?;
            Ok(TapLease {
                lease_id: row.get(0)?, operation_id: row.get(1)?, route_id: row.get(2)?,
                bundle_digest: row.get(3)?, instance_id: row.get(4)?, incarnation_id: row.get(5)?,
                execution_epoch: row.get(6)?, host_boot_id: row.get(7)?, broker_session_id: row.get(8)?,
                state, gate, revision: row.get(10)?,
                attachment,
            })
        },
    ).optional()?)
}

fn owned(db: &Connection, attachment_id: &str) -> Result<TapLease> {
    read(db, attachment_id)?
        .ok_or_else(|| Fault::new("E_NOT_FOUND", "no prepared TAP for this attachment"))
}

impl Catalog {
    pub(crate) fn prior_tap_descriptor(
        &self,
        attachment_id: &str,
    ) -> Result<Option<AttachmentDescriptor>> {
        let json: Option<String> = self.db.query_row(
            "SELECT descriptor_json FROM network_tap_leases WHERE attachment_id=? ORDER BY rowid DESC LIMIT 1",
            [attachment_id], |row| row.get(0),
        ).optional()?;
        json.map(|value| {
            serde_json::from_str(&value)
                .map_err(|_| Fault::new("E_CATALOG", "cannot read previous TAP descriptor"))
        })
        .transpose()
    }

    pub(crate) fn tap_lease(&self, attachment_id: &str) -> Result<TapLease> {
        owned(&self.db, attachment_id)
    }

    pub(crate) fn tap_leases_for_execution(&self, execution: &Execution) -> Result<Vec<TapLease>> {
        let mut statement = self.db.prepare(
            "SELECT attachment_id FROM network_tap_leases
             WHERE incarnation_id=? AND execution_epoch=? AND state<>'retired'",
        )?;
        let mut leases = Vec::new();
        for attachment in statement.query_map(
            params![execution.incarnation_id, execution.execution_epoch],
            |row| row.get::<_, String>(0),
        )? {
            let lease = owned(&self.db, &attachment?)?;
            if !lease.matches(execution) {
                return Err(Fault::new(
                    "E_FENCE_UNPROVEN",
                    "recorded TAP belongs to another execution",
                ));
            }
            leases.push(lease);
        }
        Ok(leases)
    }

    pub(crate) fn record_network_kernel_proof(
        &self,
        lease: &TapLease,
        proof: &KernelProof,
    ) -> Result<()> {
        let evidence = serde_json::to_string(proof)
            .map_err(|_| Fault::new("E_CATALOG", "cannot encode kernel network receipt"))?;
        let recorded = self.db.execute(
            "INSERT INTO network_kernel_receipts (lease_id,published_revision,router_dev,router_ino,evidence_json)
                SELECT lease_id,revision,?3,?4,?5 FROM network_tap_leases
                WHERE lease_id=?1 AND revision=?2 AND state='attached'
             ON CONFLICT(lease_id) DO UPDATE SET evidence_json=excluded.evidence_json
                WHERE network_kernel_receipts.evidence_json=excluded.evidence_json
                  AND network_kernel_receipts.published_revision=excluded.published_revision",
            params![lease.lease_id, lease.revision, proof.router.device as i64, proof.router.inode as i64, evidence],
        )?;
        if recorded != 1 {
            return Err(network_recovery_unproven());
        }
        Ok(())
    }

    pub(crate) fn network_kernel_proof(&self, lease: &TapLease) -> Result<Option<KernelProof>> {
        let evidence: Option<String> = self
            .db
            .query_row(
                "SELECT evidence_json FROM network_kernel_receipts WHERE lease_id=?",
                [&lease.lease_id],
                |row| row.get(0),
            )
            .optional()?;
        evidence
            .map(|value| {
                serde_json::from_str(&value)
                    .map_err(|_| Fault::new("E_CATALOG", "cannot read kernel network receipt"))
            })
            .transpose()
    }

    pub(crate) fn recoverable_network_proof(
        &self,
        lease: &TapLease,
        execution: &Execution,
    ) -> Result<KernelProof> {
        if !lease.matches(execution) || !published_lease_can_recover(&self.db, lease)? {
            return Err(network_recovery_unproven());
        }
        self.network_kernel_proof(lease)?.ok_or_else(network_recovery_unproven)
    }

    pub(crate) fn has_migration_source_gate(&self, lease: &TapLease) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM machine_migration_source_taps f
             JOIN machine_migrations m USING(migration_id)
             WHERE f.lease_id=? AND f.phase<>'reopened' AND f.lease_revision<?
               AND m.side='source' AND m.instance_id=? AND m.state IN ('held','fenced','resuming'))",
            params![lease.lease_id, lease.revision, lease.instance_id], |row|row.get(0),
        )?)
    }

    pub(crate) fn adopt_published_tap(&mut self, lease: &TapLease) -> Result<()> {
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !published_lease_can_recover(&tx, lease)? {
            return Err(network_recovery_unproven());
        }
        // Preserve the offering session embedded in the live VMM's SGI2
        // attachment digest. Only broker ownership changes across recovery.
        tx.execute(
            "UPDATE network_kernel_receipts SET adopted_session_id=(SELECT broker_session_id FROM worker_state)
             WHERE lease_id=?",
            [&lease.lease_id],
        )?;
        tx.execute(
            "UPDATE network_tap_leases SET state='attached',revision=revision+1 WHERE lease_id=?",
            [&lease.lease_id],
        )?;
        // The transfer's signed source revision remains immutable in its scope.
        // This field follows the same exact lease through broker adoption.
        tx.execute(
            "UPDATE machine_migration_source_taps
             SET lease_revision=CASE phase WHEN 'reopened' THEN ?2 ELSE ?2+1 END
             WHERE lease_id=?1 AND lease_revision<?2",
            params![lease.lease_id, lease.revision],
        )?;
        // Carry authorization only for rules scoped to the same port and
        // execution at its last attached revision. Datagrams are never replayed.
        tx.execute(
            "UPDATE private_packet_wake_rules SET source_lease_revision=?1+1
             WHERE source_lease=?2 AND source_lease_revision=?1-1 AND source_attachment=?3
               AND source_incarnation=?4 AND source_epoch=?5",
            params![lease.revision, lease.lease_id, lease.attachment.attachment_id,
                    lease.incarnation_id, lease.execution_epoch],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn router_pin_in_use(&self, identity: NamespaceIdentity) -> rusqlite::Result<bool> {
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_kernel_receipts k
             JOIN network_tap_leases t USING(lease_id),worker_state w
             WHERE k.router_dev=?1 AND k.router_ino=?2 AND t.state<>'retired' AND t.host_boot_id=w.host_boot_id)",
            params![identity.device as i64, identity.inode as i64],
            |row| row.get(0),
        )
    }

    pub(crate) fn record_initial_network_activation(&self, lease: &TapLease) -> Result<()> {
        let inserted = self.db.execute(
            "INSERT INTO initial_network_activations
             SELECT tap.lease_id,'opening' FROM network_tap_leases tap
             JOIN operations op USING(operation_id)
             WHERE tap.lease_id=? AND tap.revision=? AND tap.state='attached' AND op.kind='launch'",
            params![lease.lease_id, lease.revision],
        )?;
        if inserted != 1 {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "initial network lease changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn finish_initial_network_activation(
        &self,
        lease: &TapLease,
        phase: &str,
    ) -> Result<()> {
        let changed = self.db.execute(
            "UPDATE initial_network_activations SET phase=?
             WHERE lease_id=? AND phase='opening'",
            params![phase, lease.lease_id],
        )?;
        if changed != 1 {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "initial network decision changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn record_quarantined_tap(
        &self,
        operation: &Operation,
        lease_id: &str,
        descriptor: &AttachmentDescriptor,
    ) -> Result<TapLease> {
        let content = serde_json::to_string(descriptor)
            .map_err(|_| Fault::new("E_CATALOG", "cannot encode network descriptor"))?;
        let inserted = self.db.execute(
            "INSERT INTO network_tap_leases
             SELECT ?1,?2,?3,?4,?5,?6,NULL,NULL,host_boot_id,broker_session_id,?7,'quarantined',1
             FROM worker_state WHERE EXISTS (
               SELECT 1 FROM network_attachments WHERE attachment_id=?2 AND operation_id=?3 AND state='reserved'
             )",
            params![lease_id, descriptor.attachment_id, operation.operation_id, operation.route_id,
                    operation.bundle_digest, operation.instance_id, content],
        )?;
        if inserted != 1 {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "network reservation changed",
            ));
        }
        owned(&self.db, &descriptor.attachment_id)
    }

    pub(crate) fn offer_tap(
        &mut self,
        execution: &Execution,
        attachment_id: &str,
    ) -> Result<TapLease> {
        self.ready()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = owned(&tx, attachment_id)?;
        if lease.state == "unknown" {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "network lease ownership must be reconciled",
            ));
        }
        if lease.state != "quarantined" {
            if !lease.matches(execution) {
                return Err(Fault::new(
                    "E_STALE_EXECUTION",
                    "network lease belongs to another execution",
                ));
            }
            return Ok(lease);
        }
        if execution.phase != "registered"
            || lease.route_id != execution.route_id
            || lease.bundle_digest != execution.bundle_digest
            || lease.instance_id != execution.instance_id
            || lease.operation_id != execution.last_operation_id
            || lease.host_boot_id != execution.host_boot_id
        {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "quarantined TAP is outside this launch",
            ));
        }
        tx.execute(
            "UPDATE network_tap_leases SET state='offered',incarnation_id=?,execution_epoch=?,revision=revision+1
             WHERE lease_id=? AND state='quarantined'",
            params![execution.incarnation_id, execution.execution_epoch, lease.lease_id],
        )?;
        let lease = owned(&tx, attachment_id)?;
        tx.commit()?;
        Ok(lease)
    }

    pub(crate) fn acknowledge_tap(
        &self,
        execution: &Execution,
        attachment_id: &str,
        lease_id: &str,
        revision: i64,
    ) -> Result<TapLease> {
        let lease = owned(&self.db, attachment_id)?;
        if lease.lease_id != lease_id || !lease.matches(execution) {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "network acknowledgement changed lease or execution",
            ));
        }
        if lease.state == "attached" && revision.checked_add(1) == Some(lease.revision) {
            return Ok(lease);
        }
        if lease.state != "offered" || lease.revision != revision {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "network offer is stale or requires reconciliation",
            ));
        }
        self.db.execute(
            "UPDATE network_tap_leases SET state='attached',revision=revision+1 WHERE lease_id=?",
            [lease_id],
        )?;
        owned(&self.db, attachment_id)
    }

    /// Only invoke after proving the router-side link has been removed.
    pub(crate) fn retire_fenced_tap(&self, lease: &TapLease) -> Result<()> {
        let rows = self.db.execute(
            "UPDATE network_tap_leases SET state='retired',revision=revision+1
             WHERE lease_id=? AND revision=? AND state<>'retired'",
            params![lease.lease_id, lease.revision],
        )?;
        if rows != 1 {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "network fence changed before retirement",
            ));
        }
        Ok(())
    }
}

fn network_recovery_unproven() -> Fault {
    Fault::new("E_FENCE_UNPROVEN", "TAP has no recoverable committed publication")
}

fn published_lease_can_recover(db: &Connection, lease: &TapLease) -> Result<bool> {
    let digest = hex::encode(lease.attachment_digest()?);
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_tap_leases t JOIN network_kernel_receipts k USING(lease_id)
           JOIN executions e USING(incarnation_id)
           JOIN instance_bindings b ON b.incarnation_id=e.incarnation_id AND b.execution_epoch=e.execution_epoch
             AND b.route_id=e.route_id AND b.instance_id=e.instance_id
           JOIN operations op ON op.operation_id=t.operation_id
           JOIN network_attachments a ON a.attachment_id=t.attachment_id AND a.operation_id=t.operation_id
             AND a.route_id=t.route_id AND a.instance_id=t.instance_id AND a.state='reserved',
           worker_state w
           WHERE t.lease_id=?1 AND t.revision=?2 AND t.state='unknown' AND w.recovering=1
             AND t.host_boot_id=w.host_boot_id AND t.host_boot_id=e.host_boot_id AND e.phase='registered'
             AND e.route_id=t.route_id AND e.bundle_digest=t.bundle_digest AND e.instance_id=t.instance_id
             AND e.execution_epoch=t.execution_epoch AND e.last_operation_id=t.operation_id
             AND NOT EXISTS (SELECT 1 FROM machine_migration_source_taps f
               JOIN machine_migrations m USING(migration_id) WHERE f.lease_id=t.lease_id
                 AND f.phase<>'reopened' AND (m.side<>'source' OR m.instance_id<>t.instance_id
                   OR m.state NOT IN ('held','fenced','resuming') OR f.lease_revision>=t.revision))
             AND op.phase='COMPLETED' AND op.decision='NONE'
             AND ((op.kind='launch' AND EXISTS (SELECT 1 FROM initial_network_activations i
                  WHERE i.lease_id=t.lease_id AND i.phase='open'))
              OR (op.kind='restore_target' AND EXISTS (SELECT 1 FROM target_activations v
                  WHERE v.operation_id=t.operation_id AND v.incarnation_id=t.incarnation_id
                    AND v.execution_epoch=t.execution_epoch AND v.bundle_digest=t.bundle_digest
                    AND v.instance_id=t.instance_id AND v.host_boot_id=t.host_boot_id
                    AND v.phase='released' AND v.decision='commit'
                    AND json_extract(v.binding_json,'$.network.target.lease_id')=t.lease_id
                    AND json_extract(v.binding_json,'$.network.target.lease_revision')=k.published_revision
                    AND json_extract(v.binding_json,'$.network.target.attachment_digest')=?3))))",
        params![lease.lease_id, lease.revision, digest],
        |row| row.get(0),
    )?)
}
