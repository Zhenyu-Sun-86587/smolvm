//! Worker-owned product volumes and offline attachment declarations.

use crate::blocks::{self, BlockObject, BlockSpec};
use crate::catalog::{Catalog, Execution, Operation, VolumeHead};
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::managed::{Device, Disk};
use imago::{file::File as ImageFile, qcow2::Qcow2, raw::Raw, DynStorage, FormatAccess};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lookup {
    volume_id: String,
    owner_id: String,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Action {
    Create {
        capacity_bytes: u64,
        lifecycle: String,
        source_snapshot_id: Option<String>,
    },
    Snapshot {
        snapshot_id: String,
    },
    DropSnapshot {
        snapshot_id: String,
    },
    Grow {
        capacity_bytes: u64,
    },
    Delete,
    Attach {
        attachment_id: String,
        instance_id: String,
        execution_epoch: i64,
        device_key: String,
        mode: String,
        snapshot_id: Option<String>,
        fork_policy: String,
        #[serde(default = "include")]
        capture_policy: String,
    },
    Detach {
        attachment_id: String,
        instance_id: String,
        execution_epoch: i64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    volume_id: String,
    owner_id: String,
    expected_revision: i64,
    command: Action,
}

fn include() -> String {
    "include".into()
}

fn missing() -> Fault {
    Fault::new("E_NOT_FOUND", "product volume does not exist in this scope")
}

fn busy(message: &str) -> Fault {
    Fault::new("E_VOLUME_BUSY", message)
}

fn mismatch(message: &str) -> Fault {
    Fault::new("E_STALE_REVISION", message)
}

fn host(error: std::io::Error) -> Fault {
    Fault::new("E_HOST_IO", error.to_string())
}

fn head(catalog: &Catalog, volume_id: &str) -> Result<Option<BlockObject>> {
    let id: Option<String> = catalog
        .db
        .query_row(
            "SELECT head_resource_id FROM volume_heads WHERE volume_id=?",
            [volume_id],
            |r| r.get(0),
        )
        .optional()?;
    id.map(|id| {
        catalog
            .block_closure(&id)
            .map(|layers| layers.into_iter().next().unwrap())
    })
    .transpose()
}

fn metadata(
    catalog: &Catalog,
    route: &str,
    bundle: &str,
    volume: &Lookup,
) -> Result<(String, i64, String)> {
    catalog
        .db
        .query_row(
            "SELECT lifecycle,revision,state FROM product_volumes
        WHERE volume_id=? AND route_id=? AND bundle_digest=? AND owner_id=?",
            params![volume.volume_id, route, bundle, volume.owner_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or_else(missing)
}

pub(crate) fn query(catalog: &Catalog, request: &Request) -> Result<Value> {
    let (route, bundle, _) = request.scope()?;
    let input: Lookup = request.payload()?;
    describe(catalog, route, bundle, &input)
}

fn describe(catalog: &Catalog, route: &str, bundle: &str, input: &Lookup) -> Result<Value> {
    let (lifecycle, revision, mut state) = metadata(catalog, route, bundle, input)?;
    let object = if state == "deleted" {
        None
    } else {
        head(catalog, &input.volume_id)?
    };
    let pending: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM product_volume_operations
        WHERE volume_id=? AND result_json IS NULL)",
        [&input.volume_id],
        |row| row.get(0),
    )?;
    if pending && state != "deleted" {
        state = "changing".into();
    }
    let mut snapshots = catalog.db.prepare(
        "SELECT snapshot_id,generation_id,source_revision,capacity_bytes
        FROM product_volume_snapshots WHERE volume_id=? AND state='available' ORDER BY snapshot_id",
    )?;
    let snapshots = snapshots
        .query_map([&input.volume_id], |row| {
            Ok(json!({
                "snapshot_id":row.get::<_,String>(0)?,"generation_id":row.get::<_,String>(1)?,
                "source_revision":row.get::<_,i64>(2)?,"capacity_bytes":row.get::<_,i64>(3)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut attachments = catalog.db.prepare("SELECT a.attachment_id,a.instance_id,a.device_key,a.mode,a.generation_id,
        a.fork_policy,a.capture_policy,a.revision,CASE WHEN g.state='attached' OR (a.mode='ro'
          AND e.phase='registered' AND m.disks_attached=1 AND EXISTS (
              SELECT 1 FROM json_each(m.devices_json) d
              WHERE json_extract(d.value,'$.device_id')=a.device_key
                AND json_extract(d.value,'$.volume_id')=a.volume_id
                AND json_extract(d.value,'$.generation_id')=a.generation_id
                AND json_extract(d.value,'$.read_only')=1
          )) THEN 'attached'
        WHEN g.state IS NOT NULL OR (b.incarnation_id IS NOT NULL AND e.phase='unknown') THEN 'unknown'
        ELSE 'reserved' END
        FROM product_volume_attachments a LEFT JOIN instance_bindings b
            ON b.route_id=? AND b.instance_id=a.instance_id
        LEFT JOIN executions e ON e.incarnation_id=b.incarnation_id
        LEFT JOIN managed_launches m ON m.incarnation_id=b.incarnation_id
        LEFT JOIN writer_reservations wr ON wr.volume_id=a.volume_id AND a.mode='rw' AND wr.incarnation_id=b.incarnation_id
        LEFT JOIN writer_grants g ON g.operation_id=wr.operation_id
        WHERE a.volume_id=? AND a.state='reserved' ORDER BY a.attachment_id")?;
    let attachments = attachments.query_map(params![route,input.volume_id], |row| Ok(json!({
        "attachment_id":row.get::<_,String>(0)?,"instance_id":row.get::<_,String>(1)?,
        "device_key":row.get::<_,String>(2)?,"mode":row.get::<_,String>(3)?,
        "generation_id":row.get::<_,Option<String>>(4)?,"fork_policy":row.get::<_,String>(5)?,
        "capture_policy":row.get::<_,String>(6)?,"revision":row.get::<_,i64>(7)?,"state":row.get::<_,String>(8)?,
    })))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(
        json!({"schema":"Volume/1","volume_id":input.volume_id,"owner_id":input.owner_id,
        "bundle_digest":bundle,"route_id":route,"lifecycle":lifecycle,"revision":revision,"state":state,
        "head_resource_id":object.as_ref().map(|object| &object.spec.resource_id),
        "generation_id":object.as_ref().and_then(|object| object.spec.backing_id.as_ref()),
        "capacity_bytes":object.as_ref().map(|object| object.spec.capacity_bytes),
        "snapshots":snapshots,"attachments":attachments}),
    )
}

pub(crate) struct RestoredProduct {
    volume: String,
    owner: String,
    lifecycle: String,
    attachment: String,
    device: String,
    generation: Option<String>,
    fork: String,
    capture: String,
}

/// Preserve the captured disk's wire attachment ID for the parked reader. The
/// independent machine gets a distinct, durable product attachment ID.
pub(crate) fn independent_restore_products(
    catalog: &Catalog,
    op: &Operation,
) -> Result<Vec<RestoredProduct>> {
    let restore: Option<(String, String)> = catalog.db.query_row(
        "SELECT r.capture_id,m.devices_json FROM managed_state_restores r
         JOIN managed_launches m USING(operation_id) WHERE r.operation_id=?",
        [&op.operation_id], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let Some((capture, devices)) = restore else { return Ok(Vec::new()) };
    let point = catalog.require_statepoint(&capture)?;
    let source = catalog.execution(&point.point.incarnation_id)?;
    if source.instance_id == op.instance_id {
        return Ok(Vec::new());
    }
    let restored: Vec<crate::managed::Device> = serde_json::from_str(&devices)
        .map_err(|err| Fault::new("E_CATALOG", err.to_string()))?;
    let captured: Vec<_> = point.point.devices.iter().filter_map(|device| device.block()).collect();
    if captured.len() != restored.len() {
        return Err(Fault::new("E_CATALOG", "restore volume plan differs from its captured disk set"));
    }
    let mut products = Vec::new();
    for (index, (old, new)) in captured.into_iter().zip(restored).enumerate() {
        let generation = new.disk.read_only.then_some(&old.generation_id);
        let row: Option<(String, String, String, String)> = catalog.db.query_row(
            "SELECT v.owner_id,v.lifecycle,a.fork_policy,a.capture_policy FROM product_volumes v
             JOIN product_volume_attachments a USING(volume_id)
             WHERE v.volume_id=?1 AND v.route_id=?2 AND v.bundle_digest=?3
               AND a.instance_id=?4 AND a.device_key=?5
               AND ( (?6 IS NULL AND a.mode='rw')
                 OR (?6 IS NOT NULL AND a.mode='ro' AND a.generation_id=?6 AND v.state='available') )
             ORDER BY a.attachment_id=?7 DESC, a.state='reserved' DESC, a.attachment_id LIMIT 1",
            params![old.volume_id, op.route_id, op.bundle_digest, source.instance_id, old.device_id, generation, old.attachment_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        if let Some((owner, lifecycle, fork, capture)) = row {
            if old.device_id != new.disk.device_id
                || old.attachment_id != new.disk.attachment_id
                || new.disk.read_only != (old.volume_id == new.volume_id)
            {
                return Err(Fault::new("E_CATALOG", "restore product volume has inconsistent disk provenance"));
            }
            products.push(RestoredProduct {
                volume: new.volume_id,
                owner,
                lifecycle,
                attachment: crate::managed::key(&op.operation_id, "product-attachment", index),
                device: new.disk.device_id,
                generation: generation.cloned(),
                fork,
                capture,
            });
        }
    }
    Ok(products)
}

pub(crate) fn publish_restore_products(
    tx: &Transaction<'_>,
    op: &Operation,
    products: Vec<RestoredProduct>,
) -> Result<()> {
    for item in products {
        let mode = if item.generation.is_some() { "ro" } else { "rw" };
        if mode == "rw" {
            tx.execute("INSERT INTO product_volumes VALUES(?,?,?,?,?,1,'available')",
                       params![item.volume, op.route_id, op.bundle_digest, item.owner, item.lifecycle])?;
        }
        tx.execute("INSERT INTO product_volume_attachments VALUES(?,?,?,?,?,?,?,?,?,'reserved',1)",
            params![item.attachment, item.volume, op.instance_id, item.device, mode,
                item.generation, item.fork, item.capture, op.expected_execution_epoch],
        )?;
        if let Some(generation) = item.generation {
            insert_pin(tx, "product_attachment", &item.attachment, &generation, &op.operation_id)?;
            tx.execute("UPDATE product_volumes SET revision=revision+1 WHERE volume_id=?", [&item.volume])?;
        }
    }
    Ok(())
}

pub(crate) fn restore_attachment_receipt(
    catalog: &Catalog,
    op: &Operation,
) -> Result<std::collections::BTreeMap<String, String>> {
    let devices: u32 = catalog.db.query_row(
        "SELECT json_array_length(devices_json) FROM managed_launches WHERE operation_id=?",
        [&op.operation_id], |row| row.get(0),
    )?;
    let mut attachments = std::collections::BTreeMap::new();
    let mut query = catalog.db.prepare(
        "SELECT volume_id FROM product_volume_attachments WHERE instance_id=? AND attachment_id=?",
    )?;
    for index in 0..devices {
        let id = crate::managed::key(&op.operation_id, "product-attachment", index as usize);
        if let Some(volume) = query.query_row(params![op.instance_id, id], |row| row.get(0)).optional()? {
            attachments.insert(volume, id);
        }
    }
    Ok(attachments)
}

fn snapshot(
    catalog: &Catalog,
    route: &str,
    bundle: &str,
    owner: &str,
    id: &str,
) -> Result<(String, String, u64)> {
    catalog
        .db
        .query_row(
            "SELECT s.volume_id,s.generation_id,s.capacity_bytes FROM product_volume_snapshots s
        JOIN product_volumes v USING(volume_id) WHERE s.snapshot_id=? AND s.state='available'
            AND v.route_id=? AND v.bundle_digest=? AND v.owner_id=?",
            params![id, route, bundle, owner],
            |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? as u64)),
        )
        .optional()?
        .ok_or_else(missing)
}

fn exclusive(catalog: &Catalog, id: &str, route: &str, deleting: bool) -> Result<()> {
    let in_use: bool = catalog.db.query_row("SELECT EXISTS(SELECT 1 FROM writer_reservations WHERE volume_id=?1)
        OR EXISTS(SELECT 1 FROM product_volume_attachments a
        LEFT JOIN instance_bindings b ON b.instance_id=a.instance_id AND b.route_id=?2
        WHERE a.volume_id=?1 AND a.state='reserved'
          AND (?3 OR (a.mode='rw' AND (b.incarnation_id IS NOT NULL OR b.active_operation_id IS NOT NULL OR EXISTS
             (SELECT 1 FROM statepoints p JOIN executions e ON e.incarnation_id=p.source_incarnation_id
              WHERE e.instance_id=a.instance_id AND e.route_id=?2 AND e.execution_epoch=b.execution_epoch
              AND p.phase='hibernated' AND json_extract(p.export_json,'$.purpose')='hibernate')))))",
        params![id,route,deleting], |row| row.get(0))?;
    if in_use {
        return Err(busy(
            "volume has an attached, hibernated or unconfirmed writer",
        ));
    }
    Ok(())
}

fn stopped(catalog: &Catalog, route: &str, instance: &str, epoch: i64) -> Result<()> {
    if !valid_id(instance) || epoch < 0 {
        return Err(Fault::invalid("invalid attachment execution scope"));
    }
    let binding: Option<(i64, Option<String>, Option<String>)> = catalog.db.query_row(
        "SELECT execution_epoch,incarnation_id,active_operation_id FROM instance_bindings WHERE route_id=? AND instance_id=?",
        params![route,instance], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional()?;
    if binding.unwrap_or_default() != (epoch, None, None) {
        return Err(busy(
            "attachment changes require the exact stopped execution",
        ));
    }
    let hibernated: bool = catalog.db.query_row("SELECT EXISTS(SELECT 1 FROM statepoints p
        JOIN executions e ON e.incarnation_id=p.source_incarnation_id WHERE e.route_id=? AND e.instance_id=?
        AND e.execution_epoch=? AND p.phase='hibernated' AND json_extract(p.export_json,'$.purpose')='hibernate')",
        params![route,instance,epoch], |row| row.get(0))?;
    if hibernated {
        return Err(busy("hibernated volume topology is immutable"));
    }
    Ok(())
}

fn check_capacity(capacity: u64) -> Result<()> {
    if capacity == 0 || capacity > i64::MAX as u64 || capacity % 512 != 0 {
        return Err(Fault::invalid(
            "volume capacity must be a positive whole number of sectors",
        ));
    }
    Ok(())
}

fn with_payload(request: &Request, payload: Value) -> Request {
    Request {
        protocol: request.protocol.clone(),
        method: request.method.clone(),
        request_id: request.request_id.clone(),
        operation_id: request.operation_id.clone(),
        request_digest: request.request_digest.clone(),
        route_id: request.route_id.clone(),
        bundle_digest: request.bundle_digest.clone(),
        expected: request.expected.clone(),
        fd_table: vec![],
        payload,
    }
}

fn replacement(volume: &str, op: &str, capacity: u64, backing: Option<String>) -> BlockSpec {
    BlockSpec {
        resource_id: format!("{op}-head"),
        capacity_bytes: capacity,
        volume_id: Some(volume.into()),
        backing_id: backing,
        content_sha256: None,
        sealed: false,
    }
}

fn insert_pin(
    tx: &Transaction<'_>,
    kind: &str,
    owner: &str,
    resource: &str,
    operation: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO root_refs VALUES(?,?,?,'active',1,?)",
        params![kind, owner, resource, operation],
    )?;
    Ok(())
}

fn drop_pin(tx: &Transaction<'_>, kind: &str, owner: &str, resource: &str) -> Result<()> {
    if tx.execute(
        "UPDATE root_refs SET state='dropped',revision=revision+1
        WHERE owner_kind=? AND owner_id=? AND resource_id=? AND state='active'",
        params![kind, owner, resource],
    )? != 1
    {
        return Err(Fault::new(
            "E_FENCE_UNPROVEN",
            "volume generation has no matching root to release",
        ));
    }
    Ok(())
}

fn grow_image(
    catalog: &Catalog,
    objects: &File,
    generation: &str,
    target: &File,
    capacity: u64,
) -> Result<()> {
    type Storage = Box<dyn DynStorage>;
    let closure = catalog.block_closure(generation)?;
    let old = closure[0].spec.capacity_bytes;
    let mut prior: Option<(String, String, Arc<FormatAccess<Storage>>)> = None;
    for object in closure.iter().rev() {
        let file = blocks::open_object(objects, object, false)?;
        let storage: Storage = Box::new(ImageFile::try_from(file).map_err(host)?);
        let access = if object.format == "raw" && prior.is_none() {
            FormatAccess::new(Raw::open_image_sync(storage, false).map_err(host)?)
        } else if object.format == "qcow2" {
            let mut image = Qcow2::open_image_sync(storage, false).map_err(host)?;
            let (id, format, backing) = prior
                .take()
                .ok_or_else(|| Fault::invalid("missing volume backing"))?;
            if image.requires_external_data_file()
                || image.implicit_external_data_file().is_some()
                || image.implicit_backing_file().map(String::as_str) != Some(id.as_str())
                || image.implicit_backing_format().map(String::as_str) != Some(format.as_str())
            {
                return Err(Fault::invalid(
                    "volume image header differs from its Worker backing closure",
                ));
            }
            image.set_backing(Some(backing));
            FormatAccess::new(image)
        } else {
            return Err(Fault::invalid("unrecognized managed volume image format"));
        };
        prior = Some((
            object.spec.resource_id.clone(),
            object.format.clone(),
            Arc::new(access),
        ));
    }
    let (_, _, read) = prior.unwrap();
    target.set_len(capacity).map_err(host)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(host)?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < old {
        let count = (old - offset).min(buffer.len() as u64) as usize;
        let bytes = &mut buffer[..count];
        runtime
            .block_on(read.read(&mut *bytes, offset))
            .map_err(host)?;
        if bytes.iter().any(|&byte| byte != 0) {
            target.write_all_at(bytes, offset).map_err(host)?;
        }
        offset += count as u64;
    }
    target.sync_all().map_err(host)
}

fn grow(
    catalog: &mut Catalog,
    objects: &File,
    op: &str,
    volume: &str,
    old: &str,
    capacity: u64,
) -> Result<()> {
    let spec = replacement(volume, op, capacity, None);
    match catalog.block_intent(&spec.resource_id)? {
        Some((owner, previous, committed)) => {
            if owner != op || previous != spec {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "volume growth intent changed",
                ));
            }
            if committed.is_some() {
                return Ok(());
            }
        }
        None => catalog.begin_block(op, &spec)?,
    }
    let object = blocks::materialize_with(objects, op, spec, |_, file| {
        grow_image(catalog, objects, old, file, capacity)
    })?;
    catalog.commit_block(op, &object)?;
    Ok(())
}

pub(crate) fn mutate(catalog: &mut Catalog, objects: &File, request: &Request) -> Result<Value> {
    let input: Mutation = request.payload()?;
    let (route, bundle, expected) = request.scope()?;
    let (op, _) = request.operation()?;
    if !valid_id(&input.volume_id)
        || !valid_id(&input.owner_id)
        || input.volume_id != expected.instance_id
        || expected.execution_epoch != 0
        || expected.incarnation_id.is_some()
        || op.len() > 120
    {
        return Err(Fault::invalid("invalid product volume operation scope"));
    }
    let wanted = request.payload.to_string();
    let prior: Option<(String, Option<String>, Option<u64>, Option<String>)> = catalog.db.query_row(
        "SELECT command_json,prior_head,prior_capacity,result_json FROM product_volume_operations WHERE operation_id=?",
        [op], |row| Ok((row.get(0)?,row.get(1)?,row.get::<_,Option<i64>>(2)?.map(|size| size as u64),row.get(3)?)),
    ).optional()?;
    let lookup = Lookup {
        volume_id: input.volume_id.clone(),
        owner_id: input.owner_id.clone(),
    };
    let (old, prior_capacity) = if let Some((command, old, capacity, result)) = prior {
        let operation = catalog.matching_operation(request)?;
        if command != wanted {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "volume operation parameters changed",
            ));
        }
        if let Some(result) = result {
            if operation.phase == "NEW" {
                catalog.finish(request, false, operation.revision)?;
            }
            return serde_json::from_str(&result)
                .map_err(|_| Fault::new("E_CATALOG", "invalid stored volume receipt"));
        }
        catalog.active_operation(request)?;
        (old, capacity)
    } else {
        let current = if matches!(input.command, Action::Create { .. }) {
            if input.expected_revision != 0
                || catalog.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM product_volumes WHERE volume_id=?)",
                    [&input.volume_id],
                    |row| row.get::<_, bool>(0),
                )?
            {
                return Err(mismatch("duplicate volume or nonzero initial revision"));
            }
            None
        } else {
            let (_, revision, state) = metadata(catalog, route, bundle, &lookup)?;
            if input.expected_revision != revision
                || (state != "available" && !matches!(input.command, Action::DropSnapshot { .. }))
            {
                return Err(mismatch("volume has a different current revision"));
            }
            if matches!(input.command, Action::DropSnapshot { .. }) {
                None
            } else {
                Some(
                    head(catalog, &input.volume_id)?
                        .ok_or_else(|| busy("volume head is changing"))?,
                )
            }
        };
        preflight(catalog, route, bundle, &input, current.as_ref())?;
        let old = current
            .as_ref()
            .map(|object| object.spec.resource_id.clone());
        let capacity = current.as_ref().map(|object| object.spec.capacity_bytes);
        if catalog.operation(op).is_ok() {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "operation is owned by another handler",
            ));
        }
        catalog.begin_with(request, "catalog", |transaction| {
            transaction.execute(
                "INSERT INTO product_volume_operations VALUES(?,?,?,?,?,NULL)",
                params![
                    op,
                    input.volume_id,
                    wanted,
                    old,
                    capacity.map(|size| size as i64)
                ],
            )?;
            Ok(())
        })?;
        (old, capacity)
    };

    let seal = |catalog: &mut Catalog, old: &str| -> Result<()> {
        blocks::seal_heads(
            catalog,
            objects,
            request,
            vec![VolumeHead {
                volume_id: input.volume_id.clone(),
                head_resource_id: old.to_owned(),
            }],
        )?;
        Ok(())
    };
    match &input.command {
        Action::Create {
            capacity_bytes,
            source_snapshot_id,
            ..
        } => {
            let parent = source_snapshot_id
                .as_deref()
                .map(|id| snapshot(catalog, route, bundle, &input.owner_id, id))
                .transpose()?
                .map(|(_, generation, _)| generation);
            let spec = replacement(&input.volume_id, op, *capacity_bytes, parent);
            blocks::create(
                catalog,
                objects,
                &with_payload(request, json!(spec)),
                None,
                false,
            )?;
        }
        Action::Snapshot { .. } => {
            let old = old.as_deref().unwrap();
            seal(catalog, old)?;
            let spec = replacement(
                &input.volume_id,
                op,
                prior_capacity.unwrap(),
                Some(old.into()),
            );
            blocks::create(
                catalog,
                objects,
                &with_payload(request, json!(spec)),
                None,
                false,
            )?;
        }
        Action::Grow { capacity_bytes } => {
            let old = old.as_deref().unwrap();
            seal(catalog, old)?;
            grow(catalog, objects, op, &input.volume_id, old, *capacity_bytes)?;
        }
        Action::Delete => seal(catalog, old.as_deref().unwrap())?,
        _ => (),
    }

    let tx = catalog.db.unchecked_transaction()?;
    apply_metadata(
        &tx,
        &input,
        route,
        bundle,
        op,
        old.as_deref(),
        prior_capacity,
    )?;
    // The heads and lease changes are already durable. Store a stable receipt
    // with their metadata before releasing the serialized catalog operation.
    tx.execute(
        "UPDATE product_volume_operations SET result_json='null' WHERE operation_id=?",
        [op],
    )?;
    let receipt = json!({"schema":"VolumeOperation/1","operation_id":op,"volume":describe(catalog,route,bundle,&lookup)?,
        "block_capacity_applied":matches!(input.command,Action::Grow { .. }),
        "filesystem_resize_status":if matches!(input.command,Action::Grow { .. }) { "not_requested" } else { "not_applicable" }});
    tx.execute(
        "UPDATE product_volume_operations SET result_json=? WHERE operation_id=?",
        params![receipt.to_string(), op],
    )?;
    tx.commit()?;
    let operation = catalog.active_operation(request)?;
    catalog.finish(request, false, operation.revision)?;
    Ok(receipt)
}

fn preflight(
    catalog: &Catalog,
    route: &str,
    bundle: &str,
    input: &Mutation,
    current: Option<&BlockObject>,
) -> Result<()> {
    match &input.command {
        Action::Create {
            capacity_bytes,
            lifecycle,
            source_snapshot_id,
        } => {
            check_capacity(*capacity_bytes)?;
            if !matches!(lifecycle.as_str(), "persistent" | "ephemeral") {
                return Err(Fault::invalid("invalid volume lifecycle"));
            }
            if let Some(id) = source_snapshot_id.as_deref() {
                let (_, _, bytes) = snapshot(catalog, route, bundle, &input.owner_id, id)?;
                if *capacity_bytes != bytes {
                    return Err(Fault::invalid(
                        "clone capacity differs from its immutable snapshot",
                    ));
                }
            }
        }
        Action::Snapshot { snapshot_id } => {
            if !valid_id(snapshot_id)
                || catalog.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM product_volume_snapshots WHERE snapshot_id=?)",
                    [snapshot_id],
                    |r| r.get::<_, bool>(0),
                )?
            {
                return Err(Fault::invalid("invalid or duplicate volume snapshot"));
            }
            exclusive(catalog, &input.volume_id, route, false)?;
        }
        Action::Grow { capacity_bytes } => {
            check_capacity(*capacity_bytes)?;
            if *capacity_bytes <= current.unwrap().spec.capacity_bytes {
                return Err(Fault::invalid("volume capacity can only increase"));
            }
            exclusive(catalog, &input.volume_id, route, false)?;
        }
        Action::Delete => exclusive(catalog, &input.volume_id, route, true)?,
        Action::Attach {
            attachment_id,
            instance_id,
            execution_epoch,
            device_key,
            mode,
            snapshot_id,
            fork_policy,
            capture_policy,
        } => {
            stopped(catalog, route, instance_id, *execution_epoch)?;
            if !valid_id(attachment_id)
                || !valid_id(device_key)
                || !matches!(capture_policy.as_str(), "include" | "external")
                || !matches!(
                    (mode.as_str(), snapshot_id, fork_policy.as_str()),
                    ("rw", None, "clone" | "reject")
                        | ("ro", Some(_), "share_immutable" | "reject")
                )
            {
                return Err(Fault::invalid(
                    "unsupported volume attachment configuration",
                ));
            }
            if let Some(id) = snapshot_id {
                let (volume, _, _) = snapshot(catalog, route, bundle, &input.owner_id, id)?;
                if volume != input.volume_id {
                    return Err(missing());
                }
            }
            let in_use: bool = catalog.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM product_volume_attachments WHERE
                attachment_id=?1 OR (state='reserved' AND ((instance_id=?2 AND device_key=?3)
                OR (volume_id=?4 AND mode='rw' AND ?5='rw'))))",
                params![
                    attachment_id,
                    instance_id,
                    device_key,
                    input.volume_id,
                    mode
                ],
                |row| row.get(0),
            )?;
            if in_use {
                return Err(busy("device slot or writable volume already reserved"));
            }
        }
        Action::Detach {
            attachment_id,
            instance_id,
            execution_epoch,
        } => {
            stopped(catalog, route, instance_id, *execution_epoch)?;
            let exists: bool = catalog.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM product_volume_attachments
                WHERE attachment_id=? AND instance_id=? AND volume_id=? AND state='reserved')",
                params![attachment_id, instance_id, input.volume_id],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(missing());
            }
        }
        Action::DropSnapshot { snapshot_id } => {
            let (volume, _, _) = snapshot(catalog, route, bundle, &input.owner_id, snapshot_id)?;
            if volume != input.volume_id {
                return Err(missing());
            }
        }
    }
    Ok(())
}

fn apply_metadata(
    tx: &Transaction<'_>,
    input: &Mutation,
    route: &str,
    bundle: &str,
    op: &str,
    prior: Option<&str>,
    capacity: Option<u64>,
) -> Result<()> {
    let id = &input.volume_id;
    match &input.command {
        Action::Create { lifecycle, .. } => {
            tx.execute(
                "INSERT INTO product_volumes VALUES(?,?,?,?,?,1,'available')",
                params![id, route, bundle, input.owner_id, lifecycle],
            )?;
            return Ok(());
        }
        Action::Snapshot { snapshot_id } => {
            let prior = prior.unwrap();
            tx.execute(
                "INSERT INTO product_volume_snapshots VALUES(?,?,?,?,?,'available')",
                params![
                    snapshot_id,
                    id,
                    prior,
                    input.expected_revision,
                    capacity.unwrap() as i64
                ],
            )?;
            insert_pin(tx, "product_snapshot", snapshot_id, prior, op)?;
            drop_pin(tx, "operation", op, prior)?;
        }
        Action::Grow { .. } | Action::Delete => {
            drop_pin(tx, "operation", op, prior.unwrap())?;
            if matches!(input.command, Action::Delete) {
                tx.execute(
                    "UPDATE product_volumes SET state='deleted' WHERE volume_id=?",
                    [id],
                )?;
            }
        }
        Action::DropSnapshot { snapshot_id } => {
            let generation: String = tx.query_row(
                "SELECT generation_id FROM product_volume_snapshots WHERE snapshot_id=?",
                [snapshot_id],
                |row| row.get(0),
            )?;
            drop_pin(tx, "product_snapshot", snapshot_id, &generation)?;
            tx.execute(
                "UPDATE product_volume_snapshots SET state='deleted' WHERE snapshot_id=?",
                [snapshot_id],
            )?;
        }
        Action::Attach {
            attachment_id,
            instance_id,
            device_key,
            mode,
            snapshot_id,
            fork_policy,
            capture_policy,
            execution_epoch,
            ..
        } => {
            let generation: Option<String> = snapshot_id.as_ref().map(|snapshot| tx.query_row(
                "SELECT generation_id FROM product_volume_snapshots WHERE snapshot_id=? AND state='available'", [snapshot], |row| row.get(0),
            )).transpose()?;
            tx.execute(
                "INSERT INTO product_volume_attachments VALUES(?,?,?,?,?,?,?,?,?,'reserved',1)",
                params![
                    attachment_id,
                    id,
                    instance_id,
                    device_key,
                    mode,
                    generation,
                    fork_policy,
                    capture_policy,
                    execution_epoch
                ],
            )?;
            if let Some(generation) = generation {
                insert_pin(tx, "product_attachment", attachment_id, &generation, op)?;
            }
        }
        Action::Detach { attachment_id, .. } => {
            let generation: Option<String> = tx.query_row(
                "SELECT generation_id FROM product_volume_attachments WHERE attachment_id=?",
                [attachment_id],
                |row| row.get(0),
            )?;
            if let Some(generation) = generation {
                drop_pin(tx, "product_attachment", attachment_id, &generation)?;
            }
            tx.execute("UPDATE product_volume_attachments SET state='detached',revision=revision+1 WHERE attachment_id=?", [attachment_id])?;
        }
    }
    tx.execute(
        "UPDATE product_volumes SET revision=revision+1 WHERE volume_id=? AND revision=?",
        params![id, input.expected_revision],
    )?;
    Ok(())
}

pub(crate) fn require_writer(catalog: &Catalog, volume: &str, execution: &Execution) -> Result<()> {
    let product: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM product_volumes WHERE volume_id=?)",
        [volume],
        |row| row.get(0),
    )?;
    if !product {
        return Ok(());
    }
    let attached: bool = catalog.db.query_row("SELECT EXISTS(SELECT 1 FROM product_volume_attachments a
        JOIN product_volumes v USING(volume_id) WHERE a.volume_id=? AND a.instance_id=? AND a.mode='rw'
        AND a.state='reserved' AND v.state='available' AND a.declared_epoch<? AND v.route_id=? AND v.bundle_digest=?
        AND NOT EXISTS(SELECT 1 FROM product_volume_operations p WHERE p.volume_id=a.volume_id AND p.result_json IS NULL))",
        params![volume,execution.instance_id,execution.execution_epoch,execution.route_id,execution.bundle_digest], |row| row.get(0))?;
    if attached {
        Ok(())
    } else {
        Err(busy(
            "execution has no authorized product volume attachment",
        ))
    }
}

pub(crate) fn require_launch_set(
    catalog: &Catalog,
    route: &str,
    instance: &str,
    count: usize,
) -> Result<()> {
    let reserved: i64 = catalog.db.query_row(
        "SELECT count(*) FROM product_volume_attachments a JOIN product_volumes v USING(volume_id)
        WHERE a.instance_id=? AND v.route_id=? AND a.state='reserved'",
        params![instance, route],
        |row| row.get(0),
    )?;
    if usize::try_from(reserved).ok() != Some(count) {
        return Err(busy(
            "managed launch must include every reserved attachment",
        ));
    }
    Ok(())
}

pub(crate) fn launch_device(
    catalog: &Catalog,
    route: &str,
    bundle: &str,
    instance: &str,
    epoch: i64,
    disk: &Disk,
    volume: &str,
) -> Result<(Device, Vec<BlockObject>)> {
    let reservation: Option<Option<String>> = catalog.db.query_row(
        "SELECT a.generation_id FROM product_volume_attachments a JOIN product_volumes v USING(volume_id)
        WHERE a.attachment_id=? AND a.volume_id=? AND a.instance_id=? AND a.device_key=? AND a.declared_epoch<?
        AND a.mode=? AND a.state='reserved' AND v.state='available' AND v.route_id=? AND v.bundle_digest=?
        AND NOT EXISTS (SELECT 1 FROM product_volume_operations p WHERE p.volume_id=v.volume_id AND p.result_json IS NULL)",
        params![disk.attachment_id, volume, instance, disk.device_id, epoch,
            if disk.read_only { "ro" } else { "rw" }, route, bundle],
        |row| row.get(0),
    ).optional()?;
    let generation = reservation.ok_or_else(|| {
        busy("link does not match the reserved volume consumer, slot, mode or epoch")
    })?;
    let (top, head_id) = if disk.read_only {
        (
            generation.ok_or_else(|| Fault::invalid("immutable attachment has no generation"))?,
            None,
        )
    } else {
        let object = head(catalog, volume)?.ok_or_else(|| busy("volume has no allocated head"))?;
        let id = object.spec.resource_id;
        catalog.volume_identity(&VolumeHead {
            volume_id: volume.into(),
            head_resource_id: id.clone(),
        })?;
        catalog.require_unsealed_head(&id)?;
        (id.clone(), Some(id))
    };
    let closure = catalog.block_closure(&top)?;
    let object = &closure[0].spec;
    if object.mutable() == disk.read_only
        || (!disk.read_only && object.volume_id.as_deref() != Some(volume))
    {
        return Err(busy("allocated volume does not match the reserved access"));
    }
    let mut resolved = disk.clone();
    resolved.volume_id = None;
    resolved.generation_id = object.backing_id.as_ref().unwrap_or(&top).clone();
    if disk.read_only {
        resolved.generation_id = top;
    }
    let device = Device {
        disk: resolved,
        volume_id: volume.into(),
        head_id,
        capacity_bytes: object.capacity_bytes,
        reattach: !disk.read_only,
    };
    Ok((device, closure))
}

pub(crate) fn require_capture_policy(
    catalog: &Catalog,
    execution: &Execution,
    fork: bool,
) -> Result<()> {
    let blocked: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM product_volume_attachments a JOIN product_volumes v USING(volume_id)
        WHERE a.instance_id=? AND a.state='reserved' AND a.declared_epoch<? AND v.route_id=? AND v.bundle_digest=?
        AND (a.capture_policy='external' OR (? AND a.fork_policy='reject')))",
        params![execution.instance_id, execution.execution_epoch,
            execution.route_id, execution.bundle_digest, fork],
        |row| row.get(0),
    )?;
    if blocked {
        return Err(Fault::new(
            "E_CAPABILITY_UNSUPPORTED",
            "an attached volume policy excludes this capture",
        ));
    }
    Ok(())
}
