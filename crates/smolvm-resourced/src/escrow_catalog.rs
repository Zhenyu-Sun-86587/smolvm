use crate::catalog::Catalog;
use crate::ipc::{Fault, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

pub struct TransferRecord {
    pub resource_id: String,
    pub operation_id: String,
    pub incarnation_id: String,
    pub descriptor_digest: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct LeaseRecord {
    pub lease_id: String,
    pub resource_id: String,
    pub incarnation_id: String,
    pub operation_id: String,
    pub state: String,
    pub delivered: usize,
    pub revision: i64,
}

pub type BackingIdentities = BTreeMap<String, (u64, u64, u64)>;

fn absent(what: &str) -> Fault {
    Fault::new("E_NOT_FOUND", format!("{what} does not exist"))
}

pub fn recover(db: &Connection, rebooted: bool) -> Result<()> {
    if rebooted {
        db.execute(
            "UPDATE root_refs SET state='dropped',revision=revision+1
            WHERE owner_kind='fd_lease' AND state='active'",
            [],
        )?;
        db.execute(
            "UPDATE fd_leases SET state='released',revision=revision+1
            WHERE state IN ('pending','attached','unknown')",
            [],
        )?;
    } else {
        db.execute(
            "UPDATE fd_leases SET state='unknown',revision=revision+1
            WHERE state IN ('pending','attached')",
            [],
        )?;
    }
    db.execute("UPDATE resources SET state='lost',revision=revision+1 WHERE state IN ('available','deleting')
        AND resource_id IN (SELECT resource_id FROM fd_transfers WHERE state='committed')", [])?;
    db.execute("UPDATE fd_transfers SET state=CASE WHEN state='committed' AND EXISTS
        (SELECT 1 FROM fd_leases l WHERE l.resource_id=fd_transfers.resource_id AND l.state='unknown')
        THEN 'missing' ELSE 'lost' END WHERE state IN ('staging','committed')", [])?;
    db.execute("UPDATE fd_transfers SET state='lost' WHERE state='missing' AND NOT EXISTS
        (SELECT 1 FROM fd_leases l WHERE l.resource_id=fd_transfers.resource_id AND l.state='unknown')", [])?;
    Ok(())
}

pub fn release_execution(db: &Connection, incarnation_id: &str) -> Result<()> {
    db.execute(
        "UPDATE fd_transfers SET state='aborted' WHERE incarnation_id=? AND state='staging'",
        [incarnation_id],
    )?;
    db.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='fd_lease' AND state='active'
        AND owner_id IN (SELECT lease_id FROM fd_leases WHERE incarnation_id=?)", [incarnation_id])?;
    db.execute(
        "UPDATE fd_leases SET state='released',revision=revision+1
        WHERE incarnation_id=? AND state!='released'",
        [incarnation_id],
    )?;
    db.execute("UPDATE fd_transfers SET state='lost' WHERE state='missing' AND NOT EXISTS
        (SELECT 1 FROM fd_leases l WHERE l.resource_id=fd_transfers.resource_id AND l.state='unknown')", [])?;
    Ok(())
}

impl Catalog {
    pub fn transfer(&self, id: &str) -> Result<Option<TransferRecord>> {
        Ok(self
            .db
            .query_row(
                "SELECT resource_id,operation_id,incarnation_id,descriptor_digest,state
            FROM fd_transfers WHERE transfer_id=?",
                [id],
                |row| {
                    Ok(TransferRecord {
                        resource_id: row.get(0)?,
                        operation_id: row.get(1)?,
                        incarnation_id: row.get(2)?,
                        descriptor_digest: row.get(3)?,
                        state: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn begin_transfer(
        &self,
        id: &str,
        record: &TransferRecord,
        descriptor: &Value,
    ) -> Result<()> {
        let inserted = self.db.execute(
            "INSERT OR IGNORE INTO fd_transfers VALUES(?,?,?,?,?,?,'staging')",
            params![
                id,
                record.resource_id,
                record.operation_id,
                record.incarnation_id,
                descriptor.to_string(),
                record.descriptor_digest
            ],
        )?;
        if inserted != 1 {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "generation resource or transfer identifier already exists",
            ));
        }
        Ok(())
    }

    pub fn batch(&self, id: &str, index: usize) -> Result<Option<String>> {
        Ok(self.db.query_row("SELECT identities_json FROM fd_transfer_batches WHERE transfer_id=? AND batch_index=?",
            params![id, index as i64], |row| row.get(0)).optional()?)
    }

    pub fn add_batch(&self, id: &str, index: usize, identities: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO fd_transfer_batches VALUES(?,?,?)",
            params![id, index as i64, identities],
        )?;
        Ok(())
    }

    pub fn commit_transfer(&mut self, id: &str) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inserted = tx.execute("INSERT OR IGNORE INTO resources
            SELECT resource_id,'descriptor','available','volatile',1,descriptor_json,descriptor_digest,operation_id,1
            FROM fd_transfers WHERE transfer_id=? AND state='staging'", [id])?;
        if inserted != 1 {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "generation resource ID already exists",
            ));
        }
        tx.execute("INSERT INTO root_refs
            SELECT 'operation',operation_id,resource_id,'active',1,operation_id FROM fd_transfers WHERE transfer_id=?", [id])?;
        tx.execute(
            "UPDATE fd_transfers SET state='committed' WHERE transfer_id=?",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn abort_transfer(&self, id: &str) -> Result<()> {
        self.db.execute(
            "UPDATE fd_transfers SET state='aborted' WHERE transfer_id=? AND state='staging'",
            [id],
        )?;
        Ok(())
    }

    pub fn lease(&self, id: &str) -> Result<LeaseRecord> {
        self.db.query_row(
            "SELECT lease_id,resource_id,incarnation_id,operation_id,state,delivered,revision FROM fd_leases WHERE lease_id=?",
            [id], |row| Ok(LeaseRecord {
                lease_id:row.get(0)?, resource_id:row.get(1)?, incarnation_id:row.get(2)?, operation_id:row.get(3)?,
                state:row.get(4)?, delivered:row.get::<_, i64>(5)? as usize, revision:row.get(6)?,
            })).optional()?.ok_or_else(|| absent("descriptor lease"))
    }

    pub fn acquire_lease(&mut self, requested: &LeaseRecord) -> Result<LeaseRecord> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let available: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM resources WHERE resource_id=? AND state='available')",
            [&requested.resource_id],
            |row| row.get(0),
        )?;
        if !available {
            return Err(Fault::new(
                "E_RESOURCE_UNAVAILABLE",
                "generation is unavailable",
            ));
        }
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO fd_leases VALUES(?,?,?,?,'pending',0,1)",
            params![
                requested.lease_id,
                requested.resource_id,
                requested.incarnation_id,
                requested.operation_id
            ],
        )?;
        if inserted == 1 {
            tx.execute(
                "INSERT INTO root_refs VALUES('fd_lease',?,?,'active',1,?)",
                params![
                    requested.lease_id,
                    requested.resource_id,
                    requested.operation_id
                ],
            )?;
        }
        tx.commit()?;
        let prior = self.lease(&requested.lease_id)?;
        if prior.resource_id != requested.resource_id
            || prior.incarnation_id != requested.incarnation_id
            || prior.operation_id != requested.operation_id
        {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "lease ID already has a different scope",
            ));
        }
        if prior.state != "pending" {
            return Err(Fault::new(
                "E_RESOURCE_UNAVAILABLE",
                "descriptor lease is no longer pending",
            ));
        }
        Ok(prior)
    }

    pub fn delivered(&self, id: &str, count: usize) -> Result<()> {
        self.db.execute(
            "UPDATE fd_leases SET delivered=max(delivered,?) WHERE lease_id=? AND state='pending'",
            params![count as i64, id],
        )?;
        Ok(())
    }

    pub fn backing_identities(&self, resource: &str) -> Result<BackingIdentities> {
        let mut statement = self.db.prepare(
            "SELECT b.identities_json FROM fd_transfer_batches b
            JOIN fd_transfers t USING (transfer_id)
            WHERE t.resource_id=? AND t.state IN ('missing','committed')",
        )?;
        let rows = statement.query_map([resource], |row| row.get::<_, String>(0))?;
        let mut identities = BTreeMap::new();
        for row in rows {
            let batch: Vec<(String, u64, u64, u64)> = serde_json::from_str(&row?)
                .map_err(|_| Fault::new("E_CATALOG", "invalid stored RAM backing identities"))?;
            for (id, device, inode, length) in batch {
                if identities.insert(id, (device, inode, length)).is_some() {
                    return Err(Fault::new(
                        "E_CATALOG",
                        "duplicate stored RAM backing identity",
                    ));
                }
            }
        }
        Ok(identities)
    }

    pub fn commit_reexport(
        &mut self,
        lease: &LeaseRecord,
        delivered: usize,
    ) -> Result<LeaseRecord> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let restored = tx.execute(
            "UPDATE fd_transfers SET state='committed' WHERE resource_id=? AND state='missing'",
            [&lease.resource_id],
        )?;
        if restored != 0 {
            let changed = tx.execute(
                "UPDATE resources SET state='available',revision=revision+1
                WHERE resource_id=? AND state='lost'",
                [&lease.resource_id],
            )?;
            if changed != 1 {
                return Err(Fault::new(
                    "E_CATALOG",
                    "generation resource changed during recovery",
                ));
            }
        }
        let attached = tx.execute(
            "UPDATE fd_leases SET state='attached',revision=revision+1,delivered=?
            WHERE lease_id=? AND state='unknown' AND revision=?",
            params![delivered as i64, lease.lease_id, lease.revision],
        )?;
        if attached != 1 {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "descriptor lease changed during recovery",
            ));
        }
        tx.commit()?;
        self.lease(&lease.lease_id)
    }

    pub fn update_lease(
        &mut self,
        existing: &LeaseRecord,
        revision: i64,
        finish: bool,
    ) -> Result<LeaseRecord> {
        let wanted = if finish { "released" } else { "attached" };
        if existing.state == wanted
            && (revision == existing.revision || revision.checked_add(1) == Some(existing.revision))
        {
            return self.lease(&existing.lease_id);
        }
        if revision != existing.revision
            || (!finish && existing.state != "pending")
            || existing.state == "released"
        {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "descriptor lease state or revision changed",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE fd_leases SET state=?,revision=revision+1 WHERE lease_id=?",
            params![wanted, existing.lease_id],
        )?;
        if finish {
            tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='fd_lease' AND owner_id=?",
                [&existing.lease_id])?;
            tx.execute("UPDATE fd_transfers SET state='lost' WHERE resource_id=? AND state='missing' AND NOT EXISTS
                (SELECT 1 FROM fd_leases l WHERE l.resource_id=fd_transfers.resource_id AND l.state='unknown')",
                [&existing.resource_id])?;
        }
        tx.commit()?;
        self.lease(&existing.lease_id)
    }
}
