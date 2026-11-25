//! Journal of writable OFD sets sent to a particular authorized VMM.

use crate::catalog::{Catalog, Execution};
use crate::ipc::{valid_id, Fault, Request, Result, MAX_FDS};
use crate::pivots::ForkOrigin;
use rusqlite::{params, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreHead {
    source_volume_id: String,
    volume_id: String,
    head_resource_id: String,
    generation_id: String,
    layers: Vec<(u64, u64)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreProof {
    origin: ForkOrigin,
    grant_id: String,
    expected_revision: i64,
    heads: Vec<RestoreHead>,
}

pub fn verify_restore_writer(
    catalog: &Catalog,
    root: &File,
    request: &Request,
    execution: &Execution,
    descriptors: Vec<OwnedFd>,
) -> Result<Value> {
    catalog.ready()?;
    let operation = catalog.matching_operation(request)?;
    let wanted: RestoreProof = request.payload()?;
    if !valid_id(&wanted.origin.pivot_id)
        || !valid_id(&wanted.grant_id)
        || wanted.heads.is_empty()
        || wanted.heads.len() > MAX_FDS
        || wanted.heads.len() != descriptors.len()
        || wanted.heads.len() != request.fd_table.len()
    {
        return Err(Fault::invalid("restore WriterSet proof is incomplete"));
    }
    let grant = catalog
        .writer_grant(&wanted.grant_id)?
        .ok_or_else(|| fence_unproven("restore writer grant is missing"))?;
    if !grant.belongs_to(&operation.operation_id, execution)
        || grant.state != "attached"
        || grant.revision != wanted.expected_revision
    {
        return Err(fence_unproven(
            "restore has no current attached writer grant",
        ));
    }
    let set = catalog
        .writer_set(&grant.operation_id)?
        .ok_or_else(|| fence_unproven("restore writer reservation is missing"))?;
    if set.heads.len() != wanted.heads.len() {
        return Err(fence_unproven(
            "restore must name every original writer descriptor",
        ));
    }
    let mut sources = HashMap::new();
    let mut volumes = HashSet::new();
    for (((head, record), entry), descriptor) in wanted
        .heads
        .iter()
        .zip(set.heads)
        .zip(&request.fd_table)
        .zip(descriptors)
    {
        if head.volume_id != record.volume_id
            || head.head_resource_id != record.head_resource_id
            || entry.role != "block_writer"
            || entry.resource_id != head.head_resource_id
        {
            return Err(fence_unproven(
                "restore writer descriptor belongs to a different head or volume",
            ));
        }
        let closure = catalog.block_closure(&head.head_resource_id)?;
        if closure[0].spec.volume_id.as_ref() != Some(&head.volume_id)
            || closure.get(1).is_none_or(|layer| {
                layer.spec.mutable() || layer.spec.resource_id != head.generation_id
            })
            || sources
                .insert(head.source_volume_id.clone(), head.generation_id.clone())
                .is_some()
            || !volumes.insert(head.volume_id.clone())
        {
            return Err(fence_unproven(
                "restore head does not start at its exact immutable source generation",
            ));
        }
        let expected = crate::blocks::open_object(root, &closure[0], true)?;
        prove_live_ofd(&expected, &File::from(descriptor))?;
        if closure.len() != head.layers.len()
            || closure
                .iter()
                .zip(&head.layers)
                .any(|(object, (dev, ino))| object.backing_identity != format!("inode:{dev}:{ino}"))
        {
            return Err(fence_unproven(
                "restore disk uses different opened ancestor files",
            ));
        }
    }
    crate::pivots::validate_fork_origin(catalog, &wanted.origin, execution, &sources, &volumes)?;
    Ok(json!({"origin":wanted.origin,"grant":grant,"heads":wanted.heads}))
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
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM writer_pivots WHERE next_grant_id=?)",
            [&request.grant_id],
            |row| row.get(0),
        )?;
        if reserved {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "writer grant ID is reserved by a pivot",
            ));
        }
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
