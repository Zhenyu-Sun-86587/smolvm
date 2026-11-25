//! Recoverable handoff of complete writable block sets while an execution is held.

use crate::blocks::{self, BlockObject, BlockSpec};
use crate::catalog::{Catalog, Execution, VolumeHead};
use crate::grants::{fence_unproven, prove_live_ofd};
use crate::ipc::{valid_id, Fault, FdEntry, Request, Result, MAX_FDS};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::fd::OwnedFd;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Heads {
    volume_id: String,
    head_resource_id: String,
    next_resource_id: String,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plan {
    previous_grant_id: String,
    previous_grant_revision: i64,
    next_grant_id: String,
    hold_token: String,
    heads: Vec<Heads>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    expected_revision: i64,
    hold_token: String,
}

struct Pivot {
    operation_id: String,
    incarnation_id: String,
    epoch: i64,
    plan: Plan,
    state: String,
    revision: i64,
}

impl Pivot {
    fn receipt(&self) -> Value {
        json!({
            "operation_id":self.operation_id,"previous_grant_id":self.plan.previous_grant_id,
            "next_grant_id":self.plan.next_grant_id,"incarnation_id":self.incarnation_id,
            "execution_epoch":self.epoch,"state":self.state,"revision":self.revision,
            "heads":self.plan.heads,
        })
    }

    fn check_scope(&self, execution: &Execution) -> Result<()> {
        if execution.incarnation_id != self.incarnation_id
            || execution.execution_epoch != self.epoch
        {
            return Err(Fault::new(
                "E_PERMISSION_DENIED",
                "writer pivot belongs to another execution",
            ));
        }
        Ok(())
    }

    fn update(&self, input: &Update, state: &str) -> Result<()> {
        if self.plan.hold_token != input.hold_token
            || self.revision != input.expected_revision
            || self.state != state
        {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "writer pivot hold, state or revision changed",
            ));
        }
        Ok(())
    }

    fn replay(&self, input: &Update, state: &str) -> bool {
        self.plan.hold_token == input.hold_token
            && self.state == state
            && input.expected_revision.checked_add(1) == Some(self.revision)
    }
}

pub struct PivotPacket {
    pub result: Value,
    pub table: Vec<FdEntry>,
    pub descriptors: Vec<OwnedFd>,
}

fn io_fault(error: std::io::Error) -> Fault {
    Fault::new("E_HOST_IO", error.to_string())
}

fn missing() -> Fault {
    Fault::new("E_NOT_FOUND", "held writer pivot is absent")
}

fn verify_plan(plan: &mut Plan) -> Result<()> {
    if !valid_id(&plan.previous_grant_id)
        || !valid_id(&plan.next_grant_id)
        || plan.previous_grant_id == plan.next_grant_id
        || plan.hold_token.len() != 32
        || !plan.hold_token.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !u128::from_str_radix(&plan.hold_token, 16).is_ok_and(|value| value != 0)
        || plan.heads.is_empty()
        || plan.heads.len() > MAX_FDS
    {
        return Err(Fault::invalid(
            "invalid writer pivot grant, hold token or head count",
        ));
    }
    plan.heads.sort_unstable();
    let mut identities = HashSet::new();
    let mut volumes = HashSet::new();
    for head in &plan.heads {
        if !valid_id(&head.volume_id)
            || !valid_id(&head.head_resource_id)
            || !valid_id(&head.next_resource_id)
            || !volumes.insert(&head.volume_id)
            || !identities.insert(&head.next_resource_id)
            || !identities.insert(&head.head_resource_id)
        {
            return Err(Fault::invalid("a writer pivot repeats a volume or head"));
        }
    }
    Ok(())
}

fn old_closures(catalog: &Catalog, plan: &Plan) -> Result<Vec<Vec<BlockObject>>> {
    let mut closures = Vec::new();
    for head in &plan.heads {
        let closure = catalog.block_closure(&head.head_resource_id)?;
        let object = &closure[0];
        let registered = VolumeHead {
            volume_id: head.volume_id.clone(),
            head_resource_id: head.head_resource_id.clone(),
        };
        if !object.spec.mutable()
            || catalog.volume_identity(&registered)? != object.backing_identity
        {
            return Err(fence_unproven(
                "writer pivot source does not match the current managed head",
            ));
        }
        if closure.len() + 1 > MAX_FDS {
            return Err(Fault::new(
                "E_RESOURCE_LIMIT",
                "writer pivot exceeds the backing depth",
            ));
        }
        closures.push(closure);
    }
    Ok(closures)
}

fn candidate(catalog: &Catalog, root: &File, op: &str, id: &str) -> Result<BlockObject> {
    let (owner, spec, identity) = catalog.block_intent(id)?.ok_or_else(missing)?;
    if owner != op {
        return Err(fence_unproven(
            "writer pivot candidate belongs to another operation",
        ));
    }
    let object = blocks::read_published(root, &spec)?.ok_or_else(missing)?;
    if identity.as_deref() != Some(&object.backing_identity) {
        return Err(fence_unproven("writer pivot candidate identity changed"));
    }
    Ok(object)
}

pub fn prepare(
    catalog: &mut Catalog,
    root: &File,
    parked: &mut HashMap<String, Vec<File>>,
    request: &Request,
    execution: &Execution,
) -> Result<PivotPacket> {
    let operation = catalog.active_operation(request)?;
    if operation.kind != "writer_pivot" {
        return Err(Fault::invalid(
            "held pivot requires a writer_pivot operation",
        ));
    }
    let id = &operation.operation_id;
    let mut plan: Plan = request.payload()?;
    verify_plan(&mut plan)?;
    let sources = old_closures(catalog, &plan)?;
    let ancestor_count = sources
        .iter()
        .flatten()
        .map(|object| &object.spec.resource_id)
        .collect::<HashSet<_>>()
        .len();
    if ancestor_count + plan.heads.len() > MAX_FDS {
        return Err(Fault::new(
            "E_RESOURCE_LIMIT",
            "writer pivot closure exceeds one descriptor packet",
        ));
    }
    let pivot = if let Some(existing) = catalog.writer_pivot(id)? {
        existing.check_scope(execution)?;
        if existing.plan != plan {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "writer pivot plan changed",
            ));
        }
        existing
    } else {
        catalog.ready()?;
        for head in &plan.heads {
            match crate::worker::openat(
                root,
                &head.next_resource_id,
                libc::O_RDONLY | libc::O_DIRECTORY,
            ) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    return Err(Fault::new(
                        "E_IDEMPOTENCY_CONFLICT",
                        "replacement block object path already exists",
                    ))
                }
            }
        }
        catalog.start_writer_pivot(id, execution, &plan, &sources)?
    };

    if pivot.state == "preparing" {
        let mut files = Vec::new();
        let mut objects = Vec::new();
        for (head, source) in plan.heads.iter().zip(&sources) {
            let (_, spec, _) = catalog
                .block_intent(&head.next_resource_id)?
                .ok_or_else(missing)?;
            let object = blocks::materialize(root, id, spec, None, Some(&source[0]))?;
            let file = blocks::open_object(root, &object, true)?;
            crate::worker::ofd_lock(&file)?;
            objects.push(object);
            files.push(file);
        }
        catalog.offer_writer_pivot(id, &objects)?;
        parked.insert(id.clone(), files);
    } else if pivot.state != "offered" {
        return Err(Fault::new(
            "E_STALE_REVISION",
            "writer pivot is no longer preparing or offered",
        ));
    }
    let capabilities = parked.get(id).ok_or_else(|| {
        fence_unproven(
            "writer pivot offer may survive in the VMM; reconcile or abort the same operation",
        )
    })?;
    if capabilities.len() != plan.heads.len() {
        return Err(fence_unproven(
            "broker holds an incomplete replacement writer set",
        ));
    }
    let mut descriptors = Vec::new();
    let mut table = Vec::new();
    let mut ids = HashSet::new();
    let mut layouts = Vec::new();
    for ((head, mut layers), fd) in plan.heads.iter().zip(sources).zip(capabilities) {
        let next = candidate(catalog, root, id, &head.next_resource_id)?;
        if blocks::backing_identity(fd).map_err(io_fault)? != next.backing_identity {
            return Err(fence_unproven("offered writer pivot FD identity changed"));
        }
        layers.insert(0, next);
        for (index, object) in layers.iter().enumerate() {
            if !ids.insert(object.spec.resource_id.clone()) {
                continue;
            }
            if descriptors.len() == MAX_FDS {
                return Err(Fault::new(
                    "E_RESOURCE_LIMIT",
                    "writer pivot closure exceeds one descriptor packet",
                ));
            }
            let file = match index {
                0 => fd.try_clone().map_err(io_fault)?,
                // Only the authenticated old writer receives this prepared
                // alias. It may install it only with the entire device set held.
                1 => blocks::open_final(root, object, false).map_err(io_fault)?,
                _ => blocks::open_object(root, object, false)?,
            };
            table.push(FdEntry {
                index: descriptors.len(),
                resource_id: object.spec.resource_id.clone(),
                role: if index == 0 {
                    "block_writer"
                } else {
                    "block_ancestor"
                }
                .into(),
            });
            descriptors.push(OwnedFd::from(file));
        }
        let target = VolumeHead {
            volume_id: head.volume_id.clone(),
            head_resource_id: head.next_resource_id.clone(),
        };
        layouts.push(json!({"head":target,"layers":layers}));
    }
    let pivot = catalog.writer_pivot(id)?.ok_or_else(missing)?;
    Ok(PivotPacket {
        result: json!({"pivot":pivot.receipt(),"block_sets":layouts}),
        table,
        descriptors,
    })
}

fn verify_candidate_descriptions(
    catalog: &Catalog,
    root: &File,
    pivot: &Pivot,
    table: &[FdEntry],
    descriptors: Vec<OwnedFd>,
) -> Result<Vec<BlockObject>> {
    if descriptors.len() != pivot.plan.heads.len() || descriptors.len() != table.len() {
        return Err(fence_unproven(
            "writer pivot proof requires every candidate head FD",
        ));
    }
    let mut objects = Vec::new();
    for ((head, entry), descriptor) in pivot.plan.heads.iter().zip(table).zip(descriptors) {
        if entry.role != "block_writer" || entry.resource_id != head.next_resource_id {
            return Err(fence_unproven("writer pivot candidate table changed"));
        }
        let object = candidate(catalog, root, &pivot.operation_id, &head.next_resource_id)?;
        let expected = blocks::open_object(root, &object, true)?;
        prove_live_ofd(&expected, &File::from(descriptor))?;
        objects.push(object);
    }
    Ok(objects)
}

pub fn update(
    catalog: &mut Catalog,
    root: &File,
    parked: &mut HashMap<String, Vec<File>>,
    request: &Request,
    execution: &Execution,
    descriptors: Vec<OwnedFd>,
) -> Result<Value> {
    let operation = catalog.matching_operation(request)?;
    let id = &operation.operation_id;
    let input: Update = request.payload()?;
    let pivot = catalog.writer_pivot(id)?.ok_or_else(missing)?;
    pivot.check_scope(execution)?;
    match request.method.as_str() {
        "CommitWriterPivot" => {
            if pivot.replay(&input, "commit") {
                return Ok(pivot.receipt());
            }
            pivot.update(&input, "offered")?;
            verify_candidate_descriptions(catalog, root, &pivot, &request.fd_table, descriptors)?;
            catalog.set_pivot_state(id, "commit")?;
            parked.remove(id);
        }
        "FinalizeWriterPivot" => {
            if pivot.replay(&input, "complete") {
                return Ok(pivot.receipt());
            }
            pivot.update(&input, "commit")?;
            let objects = verify_candidate_descriptions(
                catalog,
                root,
                &pivot,
                &request.fd_table,
                descriptors,
            )?;
            finish(catalog, root, &pivot, &objects, true)?;
        }
        "AbortWriterPivot" => {
            if pivot.replay(&input, "aborted") {
                return Ok(pivot.receipt());
            }
            if !matches!(pivot.state.as_str(), "preparing" | "offered") {
                return Err(fence_unproven(
                    "writer pivot has passed its durable commit decision",
                ));
            }
            pivot.update(&input, &pivot.state)?;
            abort(catalog, root, parked, &pivot)?;
        }
        _ => return Err(Fault::invalid("unknown writer pivot transition")),
    }
    Ok(catalog.writer_pivot(id)?.ok_or_else(missing)?.receipt())
}

fn abort(
    catalog: &mut Catalog,
    root: &File,
    parked: &mut HashMap<String, Vec<File>>,
    pivot: &Pivot,
) -> Result<()> {
    let id = &pivot.operation_id;
    parked.remove(id);
    let mut objects = Vec::new();
    let mut proof = Vec::new();
    for head in &pivot.plan.heads {
        let (_, spec, _) = catalog
            .block_intent(&head.next_resource_id)?
            .ok_or_else(missing)?;
        if let Some(object) = blocks::read_published(root, &spec)? {
            let file = blocks::open_object(root, &object, true)?;
            crate::worker::ofd_lock(&file)
                .map_err(|_| fence_unproven("a replacement writer FD is still open"))?;
            proof.push(file);
        }
        objects.push(spec);
    }
    for object in &objects {
        blocks::discard_staged(root, id, object)?;
    }
    catalog.abort_writer_pivot(pivot)
}

fn finish(
    catalog: &mut Catalog,
    root: &File,
    pivot: &Pivot,
    candidates: &[BlockObject],
    live: bool,
) -> Result<()> {
    let mut old_heads = Vec::new();
    let mut fences = Vec::new();
    let mut closed_candidates = Vec::new();
    for (old, new) in old_closures(catalog, &pivot.plan)?
        .into_iter()
        .zip(candidates)
    {
        let old_head = old.into_iter().next().expect("checked block closure");
        fences.push(blocks::fence_head_for_seal(root, &old_head, true)?);
        old_heads.push(old_head);
        if !live {
            let file = blocks::open_object(root, new, true)?;
            crate::worker::ofd_lock(&file)
                .map_err(|_| fence_unproven("a replacement writer FD survives the execution"))?;
            file.sync_all().map_err(io_fault)?;
            closed_candidates.push(file);
        }
    }
    for ((directory, file), object) in fences.iter().zip(&mut old_heads) {
        blocks::seal_fenced_head(directory, file, object)?;
    }
    catalog.publish_writer_pivot(pivot, &old_heads, candidates, live)
}

pub fn reconcile_dead(
    catalog: &mut Catalog,
    root: &File,
    parked: &mut HashMap<String, Vec<File>>,
    execution: &Execution,
) -> Result<()> {
    let id: Option<String> = catalog
        .db
        .query_row(
            "SELECT p.operation_id FROM writer_pivots p JOIN operations o USING(operation_id)
        WHERE p.incarnation_id=? AND o.phase='NEW'",
            [&execution.incarnation_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(id) = id else { return Ok(()) };
    let pivot = catalog.writer_pivot(&id)?.ok_or_else(missing)?;
    pivot.check_scope(execution)?;
    match pivot.state.as_str() {
        "commit" => {
            let mut objects = Vec::new();
            for head in &pivot.plan.heads {
                objects.push(candidate(catalog, root, &id, &head.next_resource_id)?);
            }
            finish(catalog, root, &pivot, &objects, false)?;
        }
        "complete" | "aborted" => {}
        _ => abort(catalog, root, parked, &pivot)?,
    }
    catalog.finish_dead_pivot(&id, matches!(pivot.state.as_str(), "commit" | "complete"))
}

pub fn query(catalog: &Catalog, request: &Request) -> Result<Value> {
    let operation = catalog.matching_operation(request)?;
    Ok(catalog
        .writer_pivot(&operation.operation_id)?
        .ok_or_else(missing)?
        .receipt())
}

pub fn query_execution(
    catalog: &Catalog,
    request: &Request,
    execution: &Execution,
) -> Result<Value> {
    let operation = catalog.matching_operation(request)?;
    let pivot = catalog
        .writer_pivot(&operation.operation_id)?
        .ok_or_else(missing)?;
    pivot.check_scope(execution)?;
    Ok(pivot.receipt())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForkOrigin {
    pub pivot_id: String,
    hold_token: String,
    grant_id: String,
    execution_epoch: i64,
}

pub fn validate_fork_origin(
    catalog: &Catalog,
    origin: &ForkOrigin,
    target: &Execution,
    source_heads: &HashMap<String, String>,
    target_volumes: &HashSet<String>,
) -> Result<()> {
    let point = catalog
        .writer_pivot(&origin.pivot_id)?
        .ok_or_else(missing)?;
    let source = catalog.operation(&origin.pivot_id)?;
    if point.state != "complete"
        || point.plan.hold_token != origin.hold_token
        || point.plan.previous_grant_id != origin.grant_id
        || point.epoch != origin.execution_epoch
        || source.bundle_digest != target.bundle_digest
        || source.route_id != target.route_id
        || point.incarnation_id == target.incarnation_id
        || point.plan.heads.len() != source_heads.len()
        || point.plan.heads.iter().any(|head| {
            source_heads.get(&head.volume_id) != Some(&head.head_resource_id)
                || target_volumes.contains(&head.volume_id)
        })
    {
        return Err(fence_unproven(
            "restore does not name the complete sealed source pivot and independent volumes",
        ));
    }
    Ok(())
}

impl Catalog {
    fn finish_dead_pivot(&mut self, id: &str, committed: bool) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if committed {
            tx.execute(
                "UPDATE root_refs SET owner_kind='pivot_recovery',revision=revision+1
                WHERE owner_kind='operation' AND owner_id=? AND state='active'",
                [id],
            )?;
        }
        tx.execute("UPDATE operations SET phase=?,decision=?,revision=revision+1 WHERE operation_id=? AND phase='NEW'",
            params![if committed {"COMPLETED"} else {"ABORTED"},if committed {"NONE"} else {"ABORT"},id])?;
        tx.execute(
            "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn writer_pivot(&self, id: &str) -> Result<Option<Pivot>> {
        let row: Option<(String, i64, String, String, i64)> = self.db.query_row(
            "SELECT incarnation_id,execution_epoch,plan_json,state,revision FROM writer_pivots WHERE operation_id=?",
            [id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional()?;
        row.map(|(incarnation_id, epoch, plan, state, revision)| {
            Ok(Pivot {
                operation_id: id.into(),
                incarnation_id,
                epoch,
                plan: serde_json::from_str(&plan)
                    .map_err(|_| Fault::new("E_CATALOG", "invalid stored writer pivot plan"))?,
                state,
                revision,
            })
        })
        .transpose()
    }

    fn start_writer_pivot(
        &mut self,
        id: &str,
        execution: &Execution,
        plan: &Plan,
        sources: &[Vec<BlockObject>],
    ) -> Result<Pivot> {
        let grant = self
            .writer_grant(&plan.previous_grant_id)?
            .ok_or_else(missing)?;
        if !grant.belongs_to(&grant.operation_id, execution)
            || grant.state != "attached"
            || grant.revision != plan.previous_grant_revision
        {
            return Err(fence_unproven(
                "writer pivot does not hold the exact current writer grant",
            ));
        }
        let held = self.writer_set(&grant.operation_id)?.ok_or_else(missing)?;
        if held.heads.len() != plan.heads.len()
            || held.heads.iter().zip(&plan.heads).any(|(old, selected)| {
                old.volume_id != selected.volume_id
                    || old.head_resource_id != selected.head_resource_id
            })
        {
            return Err(fence_unproven(
                "writer pivot must contain the complete current writer set",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let created = tx.execute(
            "INSERT OR IGNORE INTO writer_pivots VALUES(?,?,?,?,?,?,?,'preparing',1)",
            params![
                id,
                execution.incarnation_id,
                execution.execution_epoch,
                plan.previous_grant_id,
                plan.next_grant_id,
                plan.hold_token,
                json!(plan).to_string()
            ],
        )?;
        if created != 1 {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "writer pivot operation or next grant ID already exists",
            ));
        }
        let grant_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM writer_grants WHERE grant_id=?)",
            [&plan.next_grant_id],
            |row| row.get(0),
        )?;
        if grant_exists {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "replacement writer grant ID has been used",
            ));
        }
        for (head, source) in plan.heads.iter().zip(sources) {
            let spec = BlockSpec {
                resource_id: head.next_resource_id.clone(),
                capacity_bytes: source[0].spec.capacity_bytes,
                volume_id: Some(head.volume_id.clone()),
                backing_id: Some(head.head_resource_id.clone()),
                content_sha256: None,
                sealed: false,
            };
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO managed_blocks SELECT ?,?,?,NULL
                WHERE NOT EXISTS(SELECT 1 FROM resources WHERE resource_id=?)",
                params![
                    spec.resource_id,
                    id,
                    json!(spec).to_string(),
                    spec.resource_id
                ],
            )?;
            if inserted != 1 {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "writer pivot candidate resource ID already exists",
                ));
            }
        }
        tx.commit()?;
        self.writer_pivot(id)?.ok_or_else(missing)
    }

    fn offer_writer_pivot(&mut self, id: &str, objects: &[BlockObject]) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for object in objects {
            tx.execute("UPDATE managed_blocks SET backing_identity=? WHERE resource_id=? AND operation_id=?",
                params![object.backing_identity,object.spec.resource_id,id])?;
        }
        tx.execute(
            "UPDATE writer_pivots SET state='offered',revision=revision+1 WHERE operation_id=?",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn set_pivot_state(&self, id: &str, state: &str) -> Result<()> {
        self.db.execute(
            "UPDATE writer_pivots SET state=?,revision=revision+1 WHERE operation_id=?",
            [state, id],
        )?;
        Ok(())
    }

    fn abort_writer_pivot(&mut self, pivot: &Pivot) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for head in &pivot.plan.heads {
            tx.execute(
                "DELETE FROM managed_blocks WHERE resource_id=? AND operation_id=?",
                params![head.next_resource_id, pivot.operation_id],
            )?;
        }
        tx.execute(
            "UPDATE writer_pivots SET state='aborted',revision=revision+1 WHERE operation_id=?",
            [&pivot.operation_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn publish_writer_pivot(
        &mut self,
        pivot: &Pivot,
        old: &[BlockObject],
        new: &[BlockObject],
        live: bool,
    ) -> Result<()> {
        let previous = self
            .writer_grant(&pivot.plan.previous_grant_id)?
            .ok_or_else(missing)?;
        let id = &pivot.operation_id;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM writer_reservations WHERE operation_id=?",
            [&previous.operation_id],
        )?;
        tx.execute(
            "UPDATE writer_sets SET state='released',revision=revision+1 WHERE operation_id=?",
            [&previous.operation_id],
        )?;
        tx.execute(
            "UPDATE writer_grants SET state='released',revision=revision+1 WHERE grant_id=?",
            [&previous.grant_id],
        )?;
        let mut updated = Vec::new();
        for ((head, old), new) in pivot.plan.heads.iter().zip(old).zip(new) {
            blocks::publish_seal_record(&tx, id, old)?;
            blocks::publish_block_record(&tx, id, new)?;
            let changed = tx.execute(
                "UPDATE volume_heads SET head_resource_id=?,backing_identity=? WHERE volume_id=? AND head_resource_id=?",
                params![head.next_resource_id,new.backing_identity,head.volume_id,head.head_resource_id],
            )?;
            if changed != 1 {
                return Err(fence_unproven(
                    "old volume head changed during held pivot publication",
                ));
            }
            updated.push(VolumeHead {
                volume_id: head.volume_id.clone(),
                head_resource_id: head.next_resource_id.clone(),
            });
        }
        tx.execute(
            "INSERT INTO writer_sets VALUES(?,?,?,1)",
            params![
                id,
                json!(updated).to_string(),
                if live { "reserved" } else { "released" }
            ],
        )?;
        tx.execute(
            "INSERT INTO writer_grants VALUES(?,?,?,?,?,1)",
            params![
                pivot.plan.next_grant_id,
                id,
                pivot.incarnation_id,
                pivot.epoch,
                if live { "attached" } else { "released" }
            ],
        )?;
        if live {
            for (head, object) in updated.iter().zip(new) {
                tx.execute(
                    "INSERT INTO writer_reservations VALUES(?,?,?,?,?,?)",
                    params![
                        head.volume_id,
                        head.head_resource_id,
                        object.backing_identity,
                        id,
                        pivot.incarnation_id,
                        pivot.epoch
                    ],
                )?;
            }
        }
        tx.execute(
            "UPDATE writer_pivots SET state='complete',revision=revision+1 WHERE operation_id=?",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }
}
