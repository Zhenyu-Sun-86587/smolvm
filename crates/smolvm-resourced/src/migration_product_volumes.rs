//! Preserve exclusive persistent product volume identities during migration.

use crate::catalog::Catalog;
use crate::ipc::{Fault, Request, Result, valid_id};
use crate::managed::Device;
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Volume {
    volume_id: String,
    owner_id: String,
    revision: i64,
    attachment_id: String,
    attachment_revision: i64,
    device_key: String,
    fork_policy: String,
    capacity_bytes: u64,
}

fn unsupported(message: &str) -> Fault {
    Fault::new("E_CAPABILITY_UNSUPPORTED", message)
}

fn invalid(message: &str) -> Fault {
    Fault::new("E_FENCE_UNPROVEN", message)
}

fn check_device(volume: &Volume, devices: &[Device]) -> Result<()> {
    let valid = valid_id(&volume.volume_id)
        && valid_id(&volume.owner_id)
        && valid_id(&volume.attachment_id)
        && valid_id(&volume.device_key)
        && matches!(volume.fork_policy.as_str(), "clone" | "reject")
        && volume.revision > 0
        && volume.attachment_revision > 0
        && volume.capacity_bytes > 0
        && devices.iter().any(|device| {
            device.volume_id == volume.volume_id
                && device.disk.attachment_id == volume.attachment_id
                && device.disk.device_id == volume.device_key
                && !device.disk.read_only
                && device.capacity_bytes == volume.capacity_bytes
        });
    if valid {
        Ok(())
    } else {
        Err(invalid(
            "migrating product volume does not match the exact writable disk slot",
        ))
    }
}

pub(crate) fn source(
    catalog: &Catalog,
    bundle: &str,
    instance: &str,
    devices: &[Device],
) -> Result<Vec<Volume>> {
    let mut query = catalog.db.prepare(
        "SELECT v.volume_id,v.owner_id,v.revision,a.attachment_id,a.revision,a.device_key,a.fork_policy,
                v.lifecycle,v.state,m.instance_id IS NOT NULL,a.mode,a.capture_policy,
                EXISTS(SELECT 1 FROM product_volume_attachments peer
                       WHERE peer.volume_id=v.volume_id AND peer.state='reserved'
                         AND peer.attachment_id<>a.attachment_id),
                EXISTS(SELECT 1 FROM product_volume_snapshots point
                       WHERE point.volume_id=v.volume_id AND point.state='available'),
                EXISTS(SELECT 1 FROM product_volume_operations op
                       WHERE op.volume_id=v.volume_id AND op.result_json IS NULL)
         FROM product_volume_attachments a JOIN product_volumes v USING(volume_id)
         LEFT JOIN product_machine_volumes m USING(volume_id)
         WHERE a.instance_id=? AND a.state='reserved' AND v.route_id='deep' AND v.bundle_digest=?
         ORDER BY v.volume_id",
    )?;
    let mut rows = query.query(params![instance, bundle])?;
    let mut volumes = Vec::new();
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(7)? != "persistent"
            || row.get::<_, String>(8)? != "available"
            || row.get::<_, bool>(9)?
            || row.get::<_, String>(10)? != "rw"
            || row.get::<_, String>(11)? != "include"
            || row.get::<_, bool>(12)?
            || row.get::<_, bool>(13)?
            || row.get::<_, bool>(14)?
        {
            return Err(unsupported(
                "migration requires exclusive persistent writable volumes with included data, no active volume snapshots and no unfinished volume changes",
            ));
        }
        let volume_id: String = row.get(0)?;
        let capacity_bytes = devices
            .iter()
            .find(|device| device.volume_id == volume_id)
            .ok_or_else(|| {
                invalid("reserved product volume is missing from the measured disk set")
            })?
            .capacity_bytes;
        let volume = Volume {
            volume_id,
            owner_id: row.get(1)?,
            revision: row.get(2)?,
            attachment_id: row.get(3)?,
            attachment_revision: row.get(4)?,
            device_key: row.get(5)?,
            fork_policy: row.get(6)?,
            capacity_bytes,
        };
        check_device(&volume, devices)?;
        volumes.push(volume);
    }
    for device in devices {
        let product: bool = catalog.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM product_volumes WHERE volume_id=?)",
            [&device.volume_id],
            |row| row.get(0),
        )?;
        if product
            && !volumes
                .iter()
                .any(|volume| volume.volume_id == device.volume_id)
        {
            return Err(unsupported(
                "a measured product volume has no exclusive migrating attachment",
            ));
        }
    }
    Ok(volumes)
}

fn read(tx: &rusqlite::Connection, migration: &str) -> Result<Vec<Volume>> {
    let mut statement = tx.prepare(
        "SELECT metadata_json FROM migration_product_volumes WHERE migration_id=? ORDER BY volume_id",
    )?;
    let values = statement
        .query_map([migration], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    values
        .into_iter()
        .map(|raw| {
            serde_json::from_str(&raw)
                .map_err(|_| invalid("stored product volume migration metadata is invalid"))
        })
        .collect()
}

fn insert(tx: &Transaction<'_>, migration: &str, volume: &Volume) -> Result<()> {
    let metadata = serde_json::to_string(volume)
        .map_err(|_| invalid("cannot encode product volume migration metadata"))?;
    tx.execute(
        "INSERT INTO migration_product_volumes(migration_id,volume_id,metadata_json) VALUES(?,?,?)",
        params![migration, volume.volume_id, metadata],
    )?;
    Ok(())
}

pub(crate) fn reserve_source(catalog: &Catalog, migration: &str, volumes: &[Volume]) -> Result<()> {
    let tx = catalog.db.unchecked_transaction()?;
    let existing = read(&tx, migration)?;
    if !existing.is_empty() && existing != volumes {
        return Err(invalid(
            "source product volume selection changed after reservation",
        ));
    }
    if existing.is_empty() {
        for volume in volumes {
            insert(&tx, migration, volume)?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn check_held(catalog: &Catalog, migration: &str, volumes: &[Volume]) -> Result<()> {
    let reserved = read(&catalog.db, migration)?;
    if reserved.len() != volumes.len() {
        return Err(invalid(
            "held product volume selection differs from the source reservation",
        ));
    }
    for (before, after) in reserved.iter().zip(volumes) {
        if before.volume_id != after.volume_id
            || before.owner_id != after.owner_id
            || before.attachment_id != after.attachment_id
            || before.device_key != after.device_key
            || before.fork_policy != after.fork_policy
            || before.capacity_bytes != after.capacity_bytes
            || before.attachment_revision != after.attachment_revision
            || before.revision > after.revision
        {
            return Err(invalid(
                "held product volume metadata changed outside the capture",
            ));
        }
    }
    Ok(())
}

pub(crate) fn install_target(
    catalog: &Catalog,
    request: &Request,
    migration: &str,
    volumes: &[Volume],
    devices: &[Device],
) -> Result<()> {
    let (route, bundle, expected) = request.scope()?;
    let mut ids = BTreeSet::new();
    for volume in volumes {
        check_device(volume, devices)?;
        if !ids.insert(&volume.volume_id) {
            return Err(invalid("duplicate logical product volume in migration"));
        }
    }
    let tx = catalog.db.unchecked_transaction()?;
    let existing = read(&tx, migration)?;
    if !existing.is_empty() {
        if existing != volumes {
            return Err(invalid(
                "target already reserved different product volumes for this migration",
            ));
        }
        return Ok(());
    }
    for volume in volumes {
        let occupied: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM product_volumes WHERE volume_id=?1)
                OR EXISTS(SELECT 1 FROM volume_heads WHERE volume_id=?1)
                OR EXISTS(SELECT 1 FROM product_volume_attachments WHERE attachment_id=?2)",
            params![volume.volume_id, volume.attachment_id],
            |row| row.get(0),
        )?;
        if occupied {
            return Err(invalid(
                "target already has the migrated product volume or attachment ID",
            ));
        }
        let revision = volume
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("product volume revision is exhausted"))?;
        let attachment_revision = volume
            .attachment_revision
            .checked_add(1)
            .ok_or_else(|| invalid("product volume attachment revision is exhausted"))?;
        tx.execute(
            "INSERT INTO product_volumes(volume_id,route_id,bundle_digest,owner_id,lifecycle,revision,state)
             VALUES(?,?,?,?,'persistent',?,'available')",
            params![volume.volume_id, route, bundle, volume.owner_id, revision],
        )?;
        tx.execute(
            "INSERT INTO product_volume_attachments(attachment_id,volume_id,instance_id,device_key,
               mode,generation_id,fork_policy,capture_policy,declared_epoch,state,revision)
             VALUES(?,?,?,?,'rw',NULL,?,'include',?,'reserved',?)",
            params![
                volume.attachment_id,
                volume.volume_id,
                expected.instance_id,
                volume.device_key,
                volume.fork_policy,
                expected.execution_epoch,
                attachment_revision
            ],
        )?;
        insert(&tx, migration, volume)?;
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn remove_aborted_target(catalog: &Catalog, migration: &str) -> Result<()> {
    let tx = catalog.db.unchecked_transaction()?;
    for volume in read(&tx, migration)? {
        let active: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM writer_reservations r JOIN writer_grants g USING(operation_id)
                           WHERE r.volume_id=?1 AND g.state<>'released')
                 OR EXISTS(SELECT 1 FROM volume_heads WHERE volume_id=?1)",
            [&volume.volume_id], |row| row.get(0),
        )?;
        if active {
            return Err(invalid(
                "aborting product volume still has a target writer or published head",
            ));
        }
        tx.execute(
            "DELETE FROM product_volume_attachments WHERE attachment_id=? AND volume_id=?",
            params![volume.attachment_id, volume.volume_id],
        )?;
        tx.execute(
            "DELETE FROM product_volumes WHERE volume_id=?",
            [&volume.volume_id],
        )?;
    }
    tx.execute(
        "DELETE FROM migration_product_volumes WHERE migration_id=?",
        [migration],
    )?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn observations(
    catalog: &Catalog,
    request: &Request,
    migration: &str,
) -> Result<Vec<Value>> {
    read(&catalog.db, migration)?
        .iter()
        .map(|volume| {
            crate::product_volumes::query(
                catalog,
                &request.derived(
                    "QueryProductVolume",
                    json!({"volume_id":volume.volume_id,"owner_id":volume.owner_id}),
                ),
            )
        })
        .collect()
}

pub(crate) fn guard_mutation(catalog: &Catalog, volume: &str) -> Result<()> {
    let blocked: Option<String> = catalog.db.query_row(
        "SELECT m.migration_id FROM migration_product_volumes v JOIN machine_migrations m USING(migration_id)
         WHERE v.volume_id=?
           AND (m.side='source' AND m.state NOT IN ('aborted','resumed')
             OR m.side='target' AND m.state NOT IN ('aborted','complete'))
         LIMIT 1",
        [volume], |row| row.get(0),
    ).optional()?;
    if blocked.is_some() {
        return Err(Fault::new(
            "E_VOLUME_BUSY",
            "product volume authority is reserved by migration",
        ));
    }
    Ok(())
}
