//! Journal of writable OFD sets sent to a particular authorized VMM.

use crate::catalog::{Catalog, Execution};
use crate::ipc::{valid_id, Fault, Result};
use rusqlite::{params, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub grant_id: String,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WriterGrant {
    pub grant_id: String,
    pub operation_id: String,
    pub incarnation_id: String,
    pub execution_epoch: i64,
    pub state: String,
    pub revision: i64,
}

impl WriterGrant {
    pub fn belongs_to(&self, operation_id: &str, execution: &Execution) -> bool {
        self.operation_id == operation_id
            && self.incarnation_id == execution.incarnation_id
            && self.execution_epoch == execution.execution_epoch
    }
}

fn from_row(row: &Row<'_>) -> rusqlite::Result<WriterGrant> {
    Ok(WriterGrant {
        grant_id: row.get(0)?,
        operation_id: row.get(1)?,
        incarnation_id: row.get(2)?,
        execution_epoch: row.get(3)?,
        state: row.get(4)?,
        revision: row.get(5)?,
    })
}

pub fn fence_unproven(message: &str) -> Fault {
    Fault::new("E_FENCE_UNPROVEN", message)
}

fn ofd_conflict(file: &File) -> io::Result<Option<i16>> {
    let mut lock = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_GETLK, &mut lock) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((lock.l_type != libc::F_UNLCK as i16).then_some(lock.l_type))
}

pub fn prove_live_ofd(expected: &File, held: &File) -> Result<()> {
    let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & (libc::O_PATH | libc::O_APPEND | libc::O_DIRECT) != 0
        || crate::blocks::backing_identity(expected).ok()
            != crate::blocks::backing_identity(held).ok()
        || !matches!(ofd_conflict(expected), Ok(Some(kind)) if kind == libc::F_WRLCK as i16)
        || !matches!(ofd_conflict(held), Ok(None))
    {
        return Err(fence_unproven(
            "writer FD does not own the recorded inode's exclusive OFD lock",
        ));
    }
    Ok(())
}

impl Catalog {
    pub fn writer_grant(&self, id: &str) -> Result<Option<WriterGrant>> {
        Ok(self.db.query_row(
            "SELECT grant_id,operation_id,incarnation_id,execution_epoch,state,revision FROM writer_grants WHERE grant_id=?",
            [id], from_row,
        ).optional()?)
    }

    pub fn grant_for_operation(&self, operation: &str) -> Result<Option<WriterGrant>> {
        Ok(self.db.query_row(
            "SELECT grant_id,operation_id,incarnation_id,execution_epoch,state,revision FROM writer_grants WHERE operation_id=?",
            [operation], from_row,
        ).optional()?)
    }

    pub fn grants_for_execution(&self, execution: &Execution) -> Result<Vec<WriterGrant>> {
        let mut query = self.db.prepare(
            "SELECT grant_id,operation_id,incarnation_id,execution_epoch,state,revision FROM writer_grants
            WHERE incarnation_id=? AND execution_epoch=? AND state!='released' ORDER BY operation_id",
        )?;
        let mut grants = Vec::new();
        for row in query.query_map(
            params![execution.incarnation_id, execution.execution_epoch],
            from_row,
        )? {
            grants.push(row?);
        }
        Ok(grants)
    }

    pub fn offer_writer_grant(
        &mut self,
        operation_id: &str,
        request: &GrantRequest,
        execution: &Execution,
    ) -> Result<WriterGrant> {
        if !valid_id(&request.grant_id) {
            return Err(Fault::invalid("invalid writer grant ID"));
        }
        self.ready()?;
        if let Some(prior) = self.grant_for_operation(operation_id)? {
            if prior.grant_id != request.grant_id || !prior.belongs_to(operation_id, execution) {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "writer grant intent changed",
                ));
            }
            if prior.state != "offered" {
                return Err(fence_unproven(
                    "writer descriptors may already have an acknowledged or unknown holder",
                ));
            }
            return Ok(prior);
        }
        let set = self
            .writer_set(operation_id)?
            .ok_or_else(|| Fault::new("E_NOT_FOUND", "writer reservation does not exist"))?;
        if set.state != "reserved" || set.revision != request.expected_revision {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "writer reservation revision changed",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM writer_reservations
            WHERE operation_id=? AND incarnation_id=? AND execution_epoch=?",
            params![
                operation_id,
                execution.incarnation_id,
                execution.execution_epoch
            ],
            |row| row.get(0),
        )?;
        if count != set.heads.len() as i64 {
            return Err(fence_unproven(
                "writer reservation does not contain the requested execution's complete set",
            ));
        }
        if tx.execute(
            "INSERT OR IGNORE INTO writer_grants VALUES(?,?,?,?,'offered',1)",
            params![
                request.grant_id,
                operation_id,
                execution.incarnation_id,
                execution.execution_epoch
            ],
        )? != 1
        {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "writer grant ID already exists",
            ));
        }
        tx.commit()?;
        self.writer_grant(&request.grant_id)?
            .ok_or_else(|| Fault::new("E_CATALOG", "writer grant disappeared"))
    }

    pub fn attach_writer_grant(
        &self,
        grant: &WriterGrant,
        expected_revision: i64,
        reconcile: bool,
    ) -> Result<WriterGrant> {
        if grant.state == "attached"
            && (expected_revision == grant.revision
                || expected_revision.checked_add(1) == Some(grant.revision))
        {
            return Ok(grant.clone());
        }
        let prior = if reconcile { "unknown" } else { "offered" };
        if grant.state != prior || expected_revision != grant.revision {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "writer grant revision changed",
            ));
        }
        self.db.execute(
            "UPDATE writer_grants SET state='attached',revision=revision+1 WHERE grant_id=?",
            [&grant.grant_id],
        )?;
        self.writer_grant(&grant.grant_id)?
            .ok_or_else(|| Fault::new("E_CATALOG", "writer grant disappeared"))
    }

    pub fn forget_offered_writer(&self, grant: &WriterGrant) -> Result<()> {
        self.db.execute(
            "UPDATE writer_grants SET state='unknown',revision=revision+1 WHERE grant_id=? AND state='offered'",
            [&grant.grant_id],
        )?;
        Ok(())
    }

    pub fn release_confirmed_grant(&mut self, grant: &WriterGrant) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM writer_reservations WHERE operation_id=?",
            [&grant.operation_id],
        )?;
        tx.execute(
            "UPDATE writer_sets SET state='released',revision=revision+1 WHERE operation_id=?",
            [&grant.operation_id],
        )?;
        tx.execute(
            "UPDATE writer_grants SET state='released',revision=revision+1 WHERE grant_id=?",
            [&grant.grant_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}
