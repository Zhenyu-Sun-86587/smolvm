//! Journal of writable OFD sets sent to a particular authorized VMM.

use crate::catalog::{Catalog, Execution};
use crate::ipc::{Fault, MAX_FDS, Request, Result, valid_id};
use crate::pivots::ForkOrigin;
use rusqlite::{OptionalExtension, Row, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
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
    #[serde(default)]
    statepoint_lease_id: Option<String>,
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
    let lease_scope = if let Some(lease) = &wanted.statepoint_lease_id {
        let policy: (String, String) = catalog
            .db
            .query_row(
                "SELECT l.volume_policy,p.capture_id FROM statepoint_restore_leases l
            JOIN fd_leases f USING(lease_id) JOIN statepoints p USING(capture_id)
            WHERE l.lease_id=? AND f.operation_id=? AND f.incarnation_id=? AND f.state='attached'
                AND p.operation_id=? AND p.representation_id=f.resource_id",
                params![
                    lease,
                    operation.operation_id,
                    execution.incarnation_id,
                    wanted.origin.pivot_id
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                fence_unproven("StatePoint writer policy is outside this restore lease")
            })?;
        Some(policy)
    } else {
        None
    };
    let set = catalog
        .writer_set(&grant.operation_id)?
        .ok_or_else(|| fence_unproven("restore writer reservation is missing"))?;
    if set.heads.len() != wanted.heads.len() {
        return Err(fence_unproven(
            "restore must name every original writer descriptor",
        ));
    }
    let mut sources = HashMap::new();
    let mut volumes = HashMap::new();
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
            || volumes
                .insert(head.volume_id.clone(), head.head_resource_id.clone())
                .is_some()
        {
            return Err(fence_unproven(
                "restore head does not start at its exact immutable source generation",
            ));
        }
        let expected = crate::blocks::open_object(root, &closure[0], true)?;
        prove_live_ofd(&expected, &File::from(descriptor))?;
        if closure.len() != head.layers.len() {
            return Err(fence_unproven(
                "restore disk uses a different number of ancestor files",
            ));
        }
        for (layer, &(dev, ino)) in closure.iter().skip(1).zip(head.layers.iter().skip(1)) {
            let file = crate::blocks::open_object(root, layer, false)?;
            require_live_identity(&file, dev, ino)?;
        }
        let (dev, ino) = head.layers[0];
        require_live_identity(&expected, dev, ino)?;
    }
    if let Some((policy, capture)) = &lease_scope {
        if crate::backup_import::imported(catalog, capture)? {
            if policy != "clone_conflicts" {
                return Err(fence_unproven(
                    "backup restores require independent writable volumes",
                ));
            }
            crate::pivots::validate_archived_origin(
                catalog,
                capture,
                &wanted.origin,
                execution,
                &sources,
                &volumes,
            )?;
            return Ok(json!({"origin":wanted.origin,"grant":grant,"heads":wanted.heads}));
        }
    }
    let exact = lease_scope
        .as_ref()
        .is_some_and(|(policy, _)| policy == "exact");
    crate::pivots::validate_fork_origin(
        catalog,
        &wanted.origin,
        execution,
        &sources,
        &volumes,
        exact.then_some(operation.operation_id.as_str()),
    )?;
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

pub(crate) fn require_live_identity(file: &File, dev: u64, ino: u64) -> Result<()> {
    if crate::backing_identity::live(file).is_ok_and(|actual| actual == (dev, ino)) {
        Ok(())
    } else {
        Err(fence_unproven("managed block proof uses a different opened file"))
    }
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
    let expected_identity = crate::backing_identity::live(expected).ok();
    let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDWR
        || flags & (libc::O_PATH | libc::O_APPEND | libc::O_DIRECT) != 0
        || expected_identity.is_none()
        || expected_identity != crate::backing_identity::live(held).ok()
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
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "UPDATE writer_grants SET state='attached',revision=revision+1 WHERE grant_id=?",
            [&grant.grant_id],
        )?;
        if reconcile {
            // ReconcileWriterSet proved the exact live OFD of every head before
            // calling us. Preserve that proof only for a capture which admitted
            // this writer before the broker restart and has yet to start its pivot.
            tx.execute(
                "UPDATE managed_fork_batches AS b
                 SET pivot_json=json_set(pivot_json,'$.reconciled_writer',
                     json_object('id',?1,'revision',?2+1))
                 WHERE source_incarnation=?3 AND source_released=0 AND pivot_json IS NOT NULL
                   AND coalesce(json_extract(pivot_json,'$.admitted_grant_id'),?1)=?1
                   AND coalesce(json_extract(pivot_json,'$.reconciled_writer.id'),?1)=?1
                   AND coalesce(json_extract(pivot_json,'$.reconciled_writer.revision'),
                                json_extract(pivot_json,'$.previous_grant_revision'))=?2-1
                   AND EXISTS (SELECT 1 FROM operations o WHERE o.operation_id=b.operation_id
                               AND o.phase='NEW' AND o.expected_incarnation_id=?3 AND o.expected_execution_epoch=?4)
                   AND NOT EXISTS (SELECT 1 FROM writer_pivots p WHERE p.operation_id=b.operation_id)
                   AND NOT EXISTS (SELECT key FROM json_each(pivot_json,'$.destinations') EXCEPT
                                   SELECT h.value->>'volume_id' FROM writer_sets s,json_each(s.heads_json) h WHERE s.operation_id=?5)
                   AND NOT EXISTS (SELECT h.value->>'volume_id' FROM writer_sets s,json_each(s.heads_json) h WHERE s.operation_id=?5
                                   EXCEPT SELECT key FROM json_each(pivot_json,'$.destinations'))",
                params![grant.grant_id, grant.revision, grant.incarnation_id, grant.execution_epoch, grant.operation_id],
            )?;
        }
        tx.commit()?;
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
