use crate::catalog::{Catalog, Execution, Operation};
use crate::ipc::{Fault, Result};
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
                host_boot_id,broker_session_id,state,revision,descriptor_json
         FROM network_tap_leases WHERE attachment_id=? AND state<>'retired'",
        [id],
        |row: &Row<'_>| {
            let descriptor: String = row.get(11)?;
            let state = row.get::<_, String>(9)?;
            let gate = if state == "unknown" { "unknown" } else { "closed" }.to_owned();
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
    pub(crate) fn tap_lease(&self, attachment_id: &str) -> Result<TapLease> {
        owned(&self.db, attachment_id)
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
