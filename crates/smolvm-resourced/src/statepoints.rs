//! Native durable state publication and restore preparation on the Worker.

use crate::catalog::{Catalog, Execution, Operation};
use crate::escrow_catalog::LeaseRecord;
use crate::ipc::{Fault, FdEntry, Request, Result, valid_id};
use crate::managed_state_restore::{self, RestoreMode as VolumePolicy};
use crate::native_control::Endpoint;
use crate::statepoint_capture::{self, Export, Purpose, host_io};
use crate::statepoint_catalog::Record;
use crate::statepoint_store::{self, Manifest, Point};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lookup {
    pub capture_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acquire {
    capture_id: String,
    lease_id: String,
    #[serde(default)]
    volume_restore_policy: VolumePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    capture_id: String,
    #[serde(default)]
    volume_restore_policy: VolumePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stop {
    pub capture_id: String,
    pub expected_revision: i64,
    pub restore_capture_id: Option<String>,
}

pub(crate) struct Prepared {
    pub table: Vec<FdEntry>,
    pub descriptors: Vec<OwnedFd>,
    pub result: Value,
    pub delivered: (String, usize),
}

type Materialized = (String, File, File);

pub(crate) struct StatePoints {
    directory: PathBuf,
    exports: HashMap<String, JoinHandle<io::Result<Manifest>>>,
    restores: HashMap<String, JoinHandle<io::Result<Materialized>>>,
    prepared: Option<(String, Materialized)>,
}

fn conflict(detail: &str) -> Fault {
    Fault::new("E_IDEMPOTENCY_CONFLICT", detail)
}

fn limits() -> Fault {
    Fault::new(
        "E_RESOURCE_LIMIT",
        "Worker already has an in-progress StatePoint job",
    )
}

fn integrity(error: io::Error) -> Fault {
    Fault::new("E_STATEPOINT_CORRUPT", error.to_string())
}

impl StatePoints {
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            exports: HashMap::new(),
            restores: HashMap::new(),
            prepared: None,
        }
    }

    pub fn begin(
        &mut self,
        catalog: &mut Catalog,
        objects: &File,
        boot: &str,
        request: &Request,
        source: &Execution,
    ) -> Result<Record> {
        let export: Export = request.payload()?;
        export.validate()?;
        let operation = catalog.matching_operation(request)?;
        let prior = catalog.statepoint(&export.capture_id)?;
        if let Some(prior) = prior.as_ref() {
            if prior.export != export || prior.operation_id != operation.operation_id {
                return Err(conflict("StatePoint export scope changed"));
            }
            let status = self.query(catalog, objects, request, &export.capture_id)?;
            if status.phase != "exporting" || self.exports.contains_key(&export.capture_id) {
                return Ok(status);
            }
        }
        catalog.ready()?;
        if prior.is_none() || operation.kind != "vm_snapshot" {
            catalog.active_operation(request)?;
        }
        if !self.exports.is_empty() {
            return Err(limits());
        }
        if !matches!(
            operation.kind.as_str(),
            "statepoint" | "writer_pivot" | "vm_snapshot" | "hibernate" | "vm_rollback"
        ) {
            return Err(Fault::invalid(
                "StatePoint requires its own capture operation",
            ));
        }
        crate::product_volumes::require_capture_policy(catalog, source, false)?;
        let endpoint = Endpoint::load(&catalog.db, &source.incarnation_id, boot)?;
        if export.purpose != Purpose::Checkpoint {
            let query = format!("CAPTURE_QUERY {} {}", export.session, export.hold_token);
            let state: Value = serde_json::from_str(&endpoint.command(&query)?)
                .map_err(|_| Fault::invalid("invalid native capture state"))?;
            if state["phase"] != "prepared" || state["source_disposition"] != "HELD" {
                return Err(Fault::new(
                    "E_CAPTURE_NOT_HELD",
                    "stop capture requires a held source",
                ));
            }
        }
        let capture = statepoint_capture::acquire(&endpoint, &export)?;
        let disks =
            statepoint_capture::disk_roots(catalog, &operation, source, &export, &capture.devices)?;
        let opened = statepoint_capture::open_disks(catalog, objects, &disks)?;
        let point = Point::new(source, &export, &capture, disks);
        let record = match prior {
            Some(prior) if prior.point == point => {
                catalog.require_statepoint(&export.capture_id)?
            }
            Some(_) => return Err(conflict("held capture bytes changed on export replay")),
            None => catalog.start_statepoint(&operation, &export, &point)?,
        };
        crate::activation_catalog::pin_statepoint_tap(
            catalog,
            &record,
            source,
            record
                .point
                .devices
                .iter()
                .any(|device| device.is_network()),
        )?;
        let directory = self.directory.clone();
        let bundle = operation.bundle_digest;
        let commit_id = operation.operation_id;
        let job = thread::Builder::new()
            .name("statepoint-export".into())
            .spawn(move || {
                statepoint_store::write(&directory, point, bundle, commit_id, capture, opened)
            })
            .map_err(host_io)?;
        self.exports.insert(export.capture_id, job);
        Ok(record)
    }

    pub fn query(
        &mut self,
        catalog: &mut Catalog,
        objects: &File,
        request: &Request,
        capture_id: &str,
    ) -> Result<Record> {
        let operation = catalog.matching_operation(request)?;
        let record = catalog.require_statepoint(capture_id)?;
        if operation.operation_id != record.operation_id {
            return Err(Fault::new(
                "E_NOT_FOUND",
                "StatePoint belongs to another capture operation",
            ));
        }
        self.complete_export(catalog, objects, record, &operation)
    }

    fn complete_export(
        &mut self,
        catalog: &mut Catalog,
        objects: &File,
        record: Record,
        operation: &Operation,
    ) -> Result<Record> {
        if record.phase != "exporting" {
            return Ok(record);
        }
        let capture_id = &record.export.capture_id;
        let manifest = if let Some(job) = self.exports.get(capture_id) {
            if !job.is_finished() {
                return Ok(record);
            }
            match self.exports.remove(capture_id).unwrap().join() {
                Ok(Ok(manifest)) => manifest,
                Ok(Err(error)) => {
                    return catalog.statepoint_export_failure(&record, &error.to_string());
                }
                Err(_) => {
                    return catalog
                        .statepoint_export_failure(&record, "durable export worker exited");
                }
            }
        } else {
            // A completed rename could precede the previous Worker's SQL commit.
            match statepoint_store::read(
                &self.directory,
                &record.point,
                &operation.bundle_digest,
                &record.operation_id,
            ) {
                Ok(manifest) => {
                    let disks = statepoint_capture::open_disks(
                        catalog,
                        objects,
                        &record.point.disk_generations,
                    )?;
                    statepoint_store::verify_replay(&self.directory, &manifest, disks)
                        .map_err(integrity)?;
                    manifest
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(record),
                Err(error) => return Err(integrity(error)),
            }
        };
        let digest = manifest.digest().map_err(host_io)?;
        catalog.publish_statepoint(&record, &manifest, &digest)
    }

    pub fn complete_exports(
        &mut self,
        catalog: &mut Catalog,
        objects: &File,
    ) -> Result<Vec<Record>> {
        let finished: Vec<_> = self
            .exports
            .iter()
            .filter(|(_, job)| job.is_finished())
            .map(|(capture, _)| capture.clone())
            .collect();
        finished
            .into_iter()
            .map(|capture| {
                let record = catalog.require_statepoint(&capture)?;
                let operation = catalog.operation(&record.operation_id)?;
                self.complete_export(catalog, objects, record, &operation)
            })
            .collect()
    }

    pub fn export_in_progress(&self, capture_id: &str) -> bool {
        self.exports.contains_key(capture_id)
    }

    fn valid_restore(
        &self,
        catalog: &Catalog,
        request: &Request,
        capture_id: &str,
    ) -> Result<(Record, Operation)> {
        let (route, bundle, _) = request.scope()?;
        managed_state_restore::source(catalog, route, bundle, capture_id)
    }

    pub fn prepare_restore(
        &mut self,
        catalog: &Catalog,
        objects: &File,
        request: &Request,
    ) -> Result<Value> {
        let input: Prepare = request.payload()?;
        let (record, source) = self.valid_restore(catalog, request, &input.capture_id)?;
        let exact_heads = if input.volume_restore_policy == VolumePolicy::Exact {
            managed_state_restore::exact_heads(
                catalog,
                &record,
                &source,
                &request.scope()?.2.instance_id,
                request.operation_id.as_deref(),
            )?
        } else {
            Vec::new()
        };
        let ready = json!({"phase":"prepared", "capture_id":input.capture_id, "manifest_digest":record.manifest_digest,
            "volume_restore_policy":input.volume_restore_policy.as_str(),"exact_heads":exact_heads});
        if let Some(job) = self.restores.get(&input.capture_id) {
            if !job.is_finished() {
                return Ok(json!({"phase":"preparing", "capture_id":input.capture_id}));
            }
            let materialized = self
                .restores
                .remove(&input.capture_id)
                .unwrap()
                .join()
                .map_err(|_| Fault::new("E_HOST_IO", "StatePoint materialization worker exited"))?
                .map_err(integrity)?;
            self.prepared = Some((input.capture_id, materialized));
            return Ok(ready);
        }
        if self.prepared.as_ref().is_some_and(|(id, artifact)| {
            id == &input.capture_id && record.manifest_digest.as_ref() == Some(&artifact.0)
        }) {
            return Ok(ready);
        }
        if !self.restores.is_empty() {
            return Err(limits());
        }
        let directory = self.directory.clone();
        let disks =
            statepoint_capture::open_disks(catalog, objects, &record.point.disk_generations)?;
        let job = thread::Builder::new()
            .name("statepoint-restore".into())
            .spawn(move || {
                let manifest = statepoint_store::read(
                    &directory,
                    &record.point,
                    &source.bundle_digest,
                    &source.operation_id,
                )?;
                let digest = manifest.digest()?;
                if record.manifest_digest.as_ref() != Some(&digest) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "StatePoint manifest differs from the committed catalog digest",
                    ));
                }
                let (checkpoint, ram) =
                    statepoint_store::materialize(&directory, &manifest, disks)?;
                Ok((digest, checkpoint, ram))
            })
            .map_err(host_io)?;
        self.restores.insert(input.capture_id.clone(), job);
        Ok(json!({"phase":"preparing", "capture_id":input.capture_id}))
    }

    pub fn acquire_restore(
        &self,
        catalog: &mut Catalog,
        request: &Request,
        target: &Execution,
    ) -> Result<Prepared> {
        let input: Acquire = request.payload()?;
        let (point, source) = self.valid_restore(catalog, request, &input.capture_id)?;
        let operation = catalog.active_operation(request)?;
        let imported = crate::backup_import::imported(catalog, &input.capture_id)?;
        if !valid_id(&input.lease_id)
            || operation.kind != "restore_target"
            || target.incarnation_id == point.point.incarnation_id
            || (!imported
                && point.export.purpose != Purpose::Checkpoint
                && source.instance_id != target.instance_id)
            || (imported
                && (source.instance_id == target.instance_id
                    || target.execution_epoch != 1
                    || input.volume_restore_policy != VolumePolicy::CloneConflicts))
        {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "StatePoint restore requires an authorized replacement execution",
            ));
        }
        if let Some(restore) = managed_state_restore::plan(catalog, &operation)? {
            if restore.capture_id != input.capture_id
                || restore
                    .durable
                    .is_none_or(|durable| durable.mode != input.volume_restore_policy)
                || input.lease_id
                    != crate::managed::key(&operation.operation_id, "statepoint-lease", 0)
            {
                return Err(conflict(
                    "managed restore capture, volume policy or lease changed",
                ));
            }
        }
        if input.volume_restore_policy == VolumePolicy::Exact {
            managed_state_restore::exact_heads(
                catalog,
                &point,
                &source,
                &target.instance_id,
                Some(&operation.operation_id),
            )?;
        }
        if source.instance_id == target.instance_id && point.export.purpose == Purpose::Checkpoint {
            let rescued: bool = catalog.db.query_row("SELECT EXISTS(SELECT 1 FROM statepoints p
                JOIN executions e ON e.incarnation_id=p.source_incarnation_id
                WHERE p.restore_capture_id=? AND p.phase='hibernated' AND e.phase='exited'
                AND e.instance_id=? AND e.route_id=? AND e.execution_epoch=? AND e.bundle_digest=?)",
                rusqlite::params![input.capture_id, target.instance_id, target.route_id, target.execution_epoch - 1, target.bundle_digest],
                |row| row.get(0))?;
            if !rescued {
                return Err(Fault::new(
                    "E_FENCE_UNPROVEN",
                    "same-instance checkpoint restore requires a stopped rescue StatePoint",
                ));
            }
        }
        let (_, (digest, checkpoint, ram)) = self
            .prepared
            .as_ref()
            .filter(|(id, _)| *id == input.capture_id)
            .ok_or_else(|| {
                Fault::new(
                    "E_RESOURCE_UNAVAILABLE",
                    "verified StatePoint restore preparation is missing",
                )
            })?;
        if point.manifest_digest.as_ref() != Some(digest) {
            return Err(Fault::new(
                "E_STATEPOINT_CORRUPT",
                "prepared StatePoint no longer matches the catalog",
            ));
        }
        let resource = &point.point.representation_id;
        let mut disk_identities = HashMap::new();
        for root in &point.point.disk_generations {
            for layer in catalog.block_closure(root)? {
                disk_identities.insert(layer.spec.resource_id, layer.backing_identity);
            }
        }
        let lease = catalog.acquire_lease(&LeaseRecord {
            lease_id: input.lease_id,
            resource_id: resource.clone(),
            incarnation_id: target.incarnation_id.clone(),
            operation_id: operation.operation_id,
            state: "pending".into(),
            delivered: 0,
            revision: 1,
        })?;
        if lease.state != "pending" {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "StatePoint lease was already attached or fenced",
            ));
        }
        if catalog.db.execute(
            "INSERT INTO statepoint_restore_leases VALUES(?,?,?)
            ON CONFLICT(lease_id) DO UPDATE SET capture_id=excluded.capture_id
            WHERE capture_id=excluded.capture_id AND volume_policy=excluded.volume_policy",
            rusqlite::params![
                lease.lease_id,
                point.export.capture_id,
                input.volume_restore_policy.as_str()
            ],
        )? != 1
        {
            return Err(conflict(
                "StatePoint restore lease or volume policy changed",
            ));
        }
        let open = |file: &File| {
            File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(host_io)
        };
        let descriptors = vec![open(checkpoint)?.into(), open(ram)?.into()];
        Ok(Prepared {
            table: ["statepoint_checkpoint", "statepoint_ram"]
                .into_iter()
                .enumerate()
                .map(|(index, role)| FdEntry {
                    index,
                    role: role.into(),
                    resource_id: resource.clone(),
                })
                .collect(),
            descriptors,
            result: json!({"lease":lease,"capture_id":point.export.capture_id,"source_operation_id":source.operation_id,
                "checkpoint_digest":point.point.checkpoint_digest,"checkpoint_bytes":point.point.checkpoint_bytes,
                "regions":point.point.regions,"manifest_digest":digest,"volume_restore_policy":input.volume_restore_policy.as_str(),
                "disk_identities":disk_identities}),
            delivered: (lease.lease_id, 2),
        })
    }

    pub fn finish_restore(&mut self, catalog: &Catalog, lease: &LeaseRecord) -> Result<()> {
        let unused: Option<String> = catalog
            .db
            .query_row(
                "SELECT s.capture_id FROM statepoint_restore_leases s
            JOIN fd_leases f USING(lease_id) WHERE s.lease_id=? AND NOT EXISTS
            (SELECT 1 FROM fd_leases p WHERE p.resource_id=f.resource_id AND p.state='pending')",
                [&lease.lease_id],
                |row| row.get(0),
            )
            .optional()?;
        if self
            .prepared
            .as_ref()
            .is_some_and(|(id, _)| Some(id) == unused.as_ref())
        {
            self.prepared = None;
        }
        Ok(())
    }

    pub fn require_rollback_target(
        &self,
        catalog: &Catalog,
        request: &Request,
        source: &Operation,
        target: &str,
    ) -> Result<()> {
        let (record, operation) = self.valid_restore(catalog, request, target)?;
        if operation.instance_id != source.instance_id
            || record.export.purpose != Purpose::Checkpoint
        {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "rollback target is not a checkpoint of this instance",
            ));
        }
        if self.prepared.as_ref().is_none_or(|(id, (digest, _, _))| {
            id != target || record.manifest_digest.as_ref() != Some(digest)
        }) {
            return Err(Fault::new(
                "E_RESOURCE_UNAVAILABLE",
                "rollback target has not passed durable preflight",
            ));
        }
        Ok(())
    }
}
