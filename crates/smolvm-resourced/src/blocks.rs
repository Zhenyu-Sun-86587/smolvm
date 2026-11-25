//! Managed raw bases and qcow2 heads addressed by their resource IDs.

use crate::catalog::{Catalog, Execution, VolumeHead};
use crate::escrow::{Acquire, Escrow, LeasePacket};
use crate::escrow_catalog::LeaseRecord;
use crate::ipc::{valid_digest, valid_id, Fault, FdEntry, Request, Result};
use imago::file::File as ImageFile;
use imago::qcow2::Qcow2;
use imago::{DynStorage, FormatAccess, FormatCreateBuilder};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

const SECTOR_BYTES: u64 = 512;
const MAX_CLOSURE_DEPTH: usize = 64;

#[derive(Clone, Deserialize, Serialize, Debug, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BlockSpec {
    pub resource_id: String,
    pub capacity_bytes: u64,
    pub volume_id: Option<String>,
    pub backing_id: Option<String>,
    pub content_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sealed: bool,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct BlockObject {
    #[serde(flatten)]
    pub spec: BlockSpec,
    pub format: String,
    pub backing_identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockId {
    resource_id: String,
}

fn io_fault(error: io::Error) -> Fault {
    Fault::new("E_HOST_IO", error.to_string())
}

fn conflict(message: &str) -> Fault {
    Fault::new("E_IDEMPOTENCY_CONFLICT", message)
}

impl BlockSpec {
    fn verify(&self, import: bool) -> Result<()> {
        if self.sealed
            || !valid_id(&self.resource_id)
            || self.capacity_bytes == 0
            || self.capacity_bytes > i64::MAX as u64
            || !self.capacity_bytes.is_multiple_of(SECTOR_BYTES)
            || self.volume_id.as_ref().is_some_and(|id| !valid_id(id))
            || self
                .backing_id
                .as_ref()
                .is_some_and(|id| !valid_id(id) || *id == self.resource_id)
        {
            return Err(Fault::invalid("invalid managed block ID or capacity"));
        }
        if import {
            if self.volume_id.is_some()
                || self.backing_id.is_some()
                || !self.content_sha256.as_deref().is_some_and(valid_digest)
            {
                return Err(Fault::invalid(
                    "import requires a raw immutable digest and no writable head",
                ));
            }
        } else if self.volume_id.is_none() || self.content_sha256.is_some() {
            return Err(Fault::invalid("creating a head requires a volume ID"));
        }
        Ok(())
    }

    fn format(&self) -> &'static str {
        if self.backing_id.is_some() {
            "qcow2"
        } else {
            "raw"
        }
    }

    pub fn mutable(&self) -> bool {
        self.volume_id.is_some() && !self.sealed
    }
}

fn fd_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn staging_name(operation_id: &str, resource_id: &str) -> String {
    format!(
        ".block-{:x}",
        Sha256::digest(format!("{operation_id}:{resource_id}").as_bytes()),
    )
}

pub fn backing_identity(file: &File) -> io::Result<String> {
    let info = file.metadata()?;
    if !info.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "block storage is not a regular file",
        ));
    }
    Ok(format!("inode:{}:{}", info.dev(), info.ino()))
}

fn publish_directory(root: &File, from: &str, to: &str) -> io::Result<()> {
    let from = CString::new(from)?;
    let to = CString::new(to)?;
    let status = unsafe {
        libc::renameat2(
            root.as_raw_fd(),
            from.as_ptr(),
            root.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    root.sync_all()
}

fn open_final(root: &File, object: &BlockObject, writable: bool) -> io::Result<File> {
    let directory = crate::worker::openat(
        root,
        &object.spec.resource_id,
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    let access = if writable {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    let file = crate::worker::openat(&directory, "data", access | libc::O_NONBLOCK)?;
    let meta = file.metadata()?;
    let mode = if object.spec.mutable() { 0o600 } else { 0o400 };
    if meta.mode() & 0o777 != mode
        || meta.nlink() != 1
        || backing_identity(&file)? != object.backing_identity
        || (object.format == "raw" && meta.len() != object.spec.capacity_bytes)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed block backing identity changed",
        ));
    }
    Ok(file)
}

pub fn open_object(root: &File, object: &BlockObject, writable: bool) -> Result<File> {
    if writable != object.spec.mutable() {
        return Err(Fault::new("E_VOLUME_WRITER_CONFLICT", "mutable heads require a writer grant and immutable generations require read-only access"));
    }
    open_final(root, object, writable).map_err(io_fault)
}

fn import_bytes(source: File, target: &File, spec: &BlockSpec) -> Result<()> {
    let metadata = source.metadata().map_err(io_fault)?;
    let flags = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GETFL) };
    if !metadata.is_file()
        || metadata.len() != spec.capacity_bytes
        || flags < 0
        || flags & libc::O_ACCMODE != libc::O_RDONLY
        || flags & libc::O_PATH != 0
    {
        return Err(Fault::invalid(
            "block import requires a correctly sized read-only regular file",
        ));
    }
    target.set_len(spec.capacity_bytes).map_err(io_fault)?;
    let mut buffer = [0u8; 128 * 1024];
    let mut offset = 0;
    let mut hash = Sha256::new();
    while offset < spec.capacity_bytes {
        let length = (spec.capacity_bytes - offset).min(buffer.len() as u64) as usize;
        let bytes = &mut buffer[..length];
        source.read_exact_at(bytes, offset).map_err(io_fault)?;
        hash.update(&*bytes);
        if bytes.iter().any(|byte| *byte != 0) {
            target.write_all_at(bytes, offset).map_err(io_fault)?;
        }
        offset += length as u64;
    }
    let actual = format!("sha256:{:x}", hash.finalize());
    if spec.content_sha256.as_deref() != Some(actual.as_str()) {
        return Err(Fault::new(
            "E_CONTENT_MISMATCH",
            "imported block bytes differ from their expected SHA-256",
        ));
    }
    Ok(())
}

fn write_image(
    spec: &BlockSpec,
    data: &File,
    source: Option<OwnedFd>,
    base: Option<&BlockObject>,
) -> Result<()> {
    if let Some(source) = source {
        import_bytes(File::from(source), data, spec)?;
        data.set_permissions(Permissions::from_mode(0o400))
            .map_err(io_fault)?;
    } else if let Some(base) = base {
        type Storage = Box<dyn DynStorage>;
        let image: Storage =
            Box::new(ImageFile::try_from(data.try_clone().map_err(io_fault)?).map_err(io_fault)?);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .map_err(io_fault)?
            .block_on(
                Qcow2::<Storage, Arc<FormatAccess<Storage>>>::create_builder(image)
                    .size(spec.capacity_bytes)
                    .backing(base.spec.resource_id.clone(), base.format.clone())
                    .create(),
            )
            .map_err(io_fault)?;
    } else {
        data.set_len(spec.capacity_bytes).map_err(io_fault)?;
    }
    data.sync_all().map_err(io_fault)
}

fn staged_directory(root: &File, name: &str) -> Result<File> {
    let path = fd_path(root).join(name);
    match std::fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_fault(error)),
    }
    let dir =
        crate::worker::openat(root, name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(io_fault)?;
    dir.set_permissions(Permissions::from_mode(0o700))
        .map_err(io_fault)?;
    clear_object_files(&dir)?;
    Ok(dir)
}

fn clear_object_files(dir: &File) -> Result<()> {
    for file in ["data", "descriptor.json", ".descriptor-sealing"] {
        match std::fs::remove_file(fd_path(&dir).join(file)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_fault(error)),
        }
    }
    Ok(())
}

fn remove_object_dir(root: &File, name: &str) -> Result<()> {
    let dir = match crate::worker::openat(root, name, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_fault(error)),
    };
    clear_object_files(&dir)?;
    std::fs::remove_dir(fd_path(root).join(name)).map_err(io_fault)?;
    root.sync_all().map_err(io_fault)
}

fn read_published(root: &File, spec: &BlockSpec) -> Result<Option<BlockObject>> {
    let dir =
        match crate::worker::openat(root, &spec.resource_id, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(dir) => dir,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_fault(error)),
        };
    let marker = crate::worker::openat(&dir, "descriptor.json", libc::O_RDONLY | libc::O_NONBLOCK)
        .map_err(io_fault)?;
    let metadata = marker.metadata().map_err(io_fault)?;
    if !metadata.is_file() || metadata.len() > 8192 {
        return Err(conflict("object publication marker is invalid"));
    }
    let object: BlockObject = serde_json::from_reader(marker)
        .map_err(|_| conflict("object publication marker is invalid"))?;
    if &object.spec != spec || object.format != spec.format() {
        return Err(conflict("object publication does not match its intent"));
    }
    open_final(root, &object, spec.mutable()).map_err(io_fault)?;
    Ok(Some(object))
}

pub fn create(
    catalog: &mut Catalog,
    root: &File,
    request: &Request,
    source: Option<OwnedFd>,
    importing: bool,
) -> Result<Value> {
    let spec: BlockSpec = request.payload()?;
    spec.verify(importing)?;
    if importing != source.is_some() {
        return Err(Fault::invalid(
            "block import requires exactly one source descriptor",
        ));
    }
    let operation = catalog.active_operation(request)?;
    if operation.kind != "catalog" {
        return Err(Fault::invalid(
            "managed block creation requires a catalog operation",
        ));
    }
    let parent = if let Some(id) = &spec.backing_id {
        let closure = catalog.block_closure(id)?;
        if closure.len() >= MAX_CLOSURE_DEPTH
            || closure[0].spec.mutable()
            || closure[0].spec.capacity_bytes != spec.capacity_bytes
        {
            return Err(Fault::invalid(
                "writable head requires a matching immutable backing generation",
            ));
        }
        Some(closure.into_iter().next().expect("checked block closure"))
    } else {
        None
    };
    if let Some(prior) = catalog.block_intent(&spec.resource_id)? {
        if prior.0 != operation.operation_id || prior.1 != spec {
            return Err(conflict(
                "managed block already has a different creation intent",
            ));
        }
        if prior.2.is_some() {
            return catalog.resource(&spec.resource_id);
        }
    } else {
        catalog.ready()?;
        if crate::worker::openat(root, &spec.resource_id, libc::O_RDONLY | libc::O_DIRECTORY)
            .is_ok()
        {
            return Err(conflict("block object directory already exists"));
        }
        catalog.begin_block(&operation.operation_id, &spec)?;
    }

    let object = if let Some(object) = read_published(root, &spec)? {
        root.sync_all().map_err(io_fault)?;
        object
    } else {
        let staging = staging_name(&operation.operation_id, &spec.resource_id);
        let dir = staged_directory(root, &staging)?;
        let dir_path = fd_path(&dir);
        let data = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir_path.join("data"))
            .map_err(io_fault)?;
        write_image(&spec, &data, source, parent.as_ref())?;
        let object = BlockObject {
            backing_identity: backing_identity(&data).map_err(io_fault)?,
            format: spec.format().into(),
            spec,
        };
        drop(data);
        let marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir_path.join("descriptor.json"))
            .map_err(io_fault)?;
        let mut marker = marker;
        serde_json::to_writer(&mut marker, &object).map_err(|e| io_fault(e.into()))?;
        marker.write_all(b"\n").map_err(io_fault)?;
        marker.sync_all().map_err(io_fault)?;
        dir.sync_all().map_err(io_fault)?;
        publish_directory(root, &staging, &object.spec.resource_id).map_err(io_fault)?;
        object
    };
    catalog.commit_block(&operation.operation_id, &object)
}

pub fn abort(catalog: &Catalog, root: &File, request: &Request) -> Result<Value> {
    let input: BlockId = request.payload()?;
    if !valid_id(&input.resource_id) {
        return Err(Fault::invalid("invalid managed block resource ID"));
    }
    let operation = catalog.active_operation(request)?;
    if let Some((owner, spec, identity)) = catalog.block_intent(&input.resource_id)? {
        if owner != operation.operation_id || identity.is_some() {
            return Err(conflict(
                "managed block belongs to another operation or is already committed",
            ));
        }
        let staging = staging_name(&owner, &input.resource_id);
        let discarding = format!("{staging}-abort");
        if read_published(root, &spec)?.is_some() {
            publish_directory(root, &input.resource_id, &discarding).map_err(io_fault)?;
        }
        remove_object_dir(root, &discarding)?;
        remove_object_dir(root, &staging)?;
        catalog.db.execute(
            "DELETE FROM managed_blocks WHERE resource_id=? AND operation_id=?",
            params![input.resource_id, owner],
        )?;
    }
    Ok(json!({"resource_id":input.resource_id,"state":"aborted"}))
}

pub fn collect(catalog: &Catalog, root: &File, resource: &str) -> Result<()> {
    let Some((_, spec, identity)) = catalog.block_intent(resource)? else {
        return Ok(());
    };
    let Some(identity) = identity else {
        return Err(Fault::new(
            "E_CATALOG",
            "collected block resource has an unfinished creation intent",
        ));
    };
    if spec.mutable() {
        return Err(Fault::invalid(
            "mutable block heads are not immutable GC objects",
        ));
    }
    let object = BlockObject {
        format: spec.format().into(),
        spec,
        backing_identity: identity,
    };
    match open_final(root, &object, false) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_fault(error)),
    };
    remove_object_dir(root, resource)
}

pub fn seal_heads(
    catalog: &mut Catalog,
    root: &File,
    request: &Request,
    mut heads: Vec<VolumeHead>,
) -> Result<Value> {
    let op = catalog.matching_operation(request)?;
    if op.kind != "catalog" || heads.is_empty() || heads.len() > 64 {
        return Err(Fault::invalid(
            "block seal requires a catalog operation and 1 to 64 heads",
        ));
    }
    heads.sort_unstable();
    if heads
        .windows(2)
        .any(|pair| pair[0].volume_id == pair[1].volume_id)
    {
        return Err(Fault::invalid("duplicate volume in block seal set"));
    }
    let prior = catalog.seal_pins(&op.operation_id)?;
    let mut by_resource: Vec<_> = heads
        .iter()
        .map(|head| head.head_resource_id.as_str())
        .collect();
    by_resource.sort_unstable();
    if !prior.is_empty() && !prior.iter().map(|(id, _)| id.as_str()).eq(by_resource) {
        return Err(conflict("block seal set changed"));
    }
    let terminal = !prior.is_empty() && prior.iter().all(|(_, state)| state == "dropped");
    let mut objects = Vec::new();
    for head in &heads {
        if !valid_id(&head.volume_id) || !valid_id(&head.head_resource_id) {
            return Err(Fault::invalid("invalid volume or head ID"));
        }
        let closure = catalog.block_closure(&head.head_resource_id)?;
        let object = closure.into_iter().next().expect("closed block head");
        if object.spec.volume_id.as_ref() != Some(&head.volume_id) || terminal != object.spec.sealed
        {
            return Err(conflict(
                "block seal does not name the same volume generation",
            ));
        }
        if !terminal && catalog.volume_identity(head)? != object.backing_identity {
            return Err(crate::grants::fence_unproven(
                "volume head changed during block seal",
            ));
        }
        objects.push(object);
    }
    if terminal {
        return Ok(json!({"generations":objects}));
    }
    catalog.active_operation(request)?;
    if prior.is_empty() {
        catalog.ready()?;
    }
    let mut handles = Vec::new();
    for object in &objects {
        let dir = crate::worker::openat(
            root,
            &object.spec.resource_id,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .map_err(io_fault)?;
        let input = crate::worker::openat(&dir, "data", libc::O_RDONLY | libc::O_NONBLOCK)
            .map_err(io_fault)?;
        let mode = input.metadata().map_err(io_fault)?.mode() & 0o777;
        let file = if mode == 0o400 && !prior.is_empty() {
            let mut frozen = object.clone();
            frozen.spec.sealed = true;
            open_object(root, &frozen, false)?
        } else {
            let file = open_object(root, object, true)?;
            crate::worker::ofd_lock(&file).map_err(|_| {
                crate::grants::fence_unproven("a prior writer still locks one of the heads")
            })?;
            file
        };
        handles.push((dir, file));
    }
    if prior.is_empty() {
        catalog.begin_block_seal(&op.operation_id, &heads)?;
    }
    for ((directory, handle), object) in handles.iter().zip(&mut objects) {
        handle.sync_all().map_err(io_fault)?;
        handle
            .set_permissions(Permissions::from_mode(0o400))
            .map_err(io_fault)?;
        handle.sync_all().map_err(io_fault)?;
        object.spec.sealed = true;
        let path = fd_path(directory);
        let staging = path.join(".descriptor-sealing");
        let mut marker = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staging)
            .map_err(io_fault)?;
        serde_json::to_writer(&mut marker, &object).map_err(|e| io_fault(e.into()))?;
        marker.sync_all().map_err(io_fault)?;
        std::fs::rename(staging, path.join("descriptor.json")).map_err(io_fault)?;
        directory.sync_all().map_err(io_fault)?;
    }
    catalog.commit_block_seal(&op.operation_id, &objects)?;
    Ok(json!({"generations":objects}))
}

pub fn acquire_read(
    catalog: &mut Catalog,
    root: &File,
    request: &Request,
    execution: &Execution,
) -> Result<LeasePacket> {
    catalog.ready()?;
    let operation = catalog.active_operation(request)?;
    let input: Acquire = request.payload()?;
    if operation.kind != "resource_lease"
        || !valid_id(&input.lease_id)
        || !valid_id(&input.resource_id)
        || input.offset != 0
    {
        return Err(Fault::invalid("invalid managed block read lease request"));
    }
    let layers = catalog.block_closure(&input.resource_id)?;
    if layers[0].spec.mutable() || input.access != "ro" {
        return Err(Fault::new(
            "E_VOLUME_WRITER_CONFLICT",
            "block read leases require an immutable generation",
        ));
    }
    let mut descriptors = Vec::new();
    let mut table = Vec::new();
    for layer in &layers {
        let fd = open_object(root, layer, false)?;
        table.push(FdEntry {
            index: descriptors.len(),
            resource_id: layer.spec.resource_id.clone(),
            role: "block_ancestor".into(),
        });
        descriptors.push(OwnedFd::from(fd));
    }
    let lease = catalog.acquire_lease(&LeaseRecord {
        lease_id: input.lease_id,
        resource_id: input.resource_id,
        incarnation_id: execution.incarnation_id.clone(),
        operation_id: operation.operation_id,
        state: "pending".into(),
        delivered: 0,
        revision: 1,
    })?;
    let total = descriptors.len();
    Ok(LeasePacket {
        result: json!({"lease":lease,"offset":0,"next_offset":total,"total":total,"layers":layers}),
        fd_table: table,
        fds: descriptors,
        delivered: (lease.lease_id, total),
    })
}

pub fn ack_read(catalog: &mut Catalog, request: &Request, execution: &Execution) -> Result<Value> {
    let (input, lease) = Escrow::scoped_lease(catalog, request, execution)?;
    let total = catalog.block_closure(&lease.resource_id)?.len();
    if total != lease.delivered {
        return Err(Fault::new(
            "E_INCOMPLETE_TRANSFER",
            "block lease has undelivered backings",
        ));
    }
    Ok(json!(catalog.update_lease(
        &lease,
        input.expected_revision,
        false
    )?))
}

pub fn reconcile_read(
    catalog: &mut Catalog,
    root: &File,
    request: &Request,
    execution: &Execution,
    descriptors: Vec<OwnedFd>,
) -> Result<Value> {
    let (input, lease) = Escrow::scoped_lease(catalog, request, execution)?;
    let layers = catalog.block_closure(&lease.resource_id)?;
    let total = layers.len();
    if descriptors.len() != total || request.fd_table.len() != total {
        return Err(Fault::new(
            "E_INCOMPLETE_TRANSFER",
            "block lease re-export requires every ancestor",
        ));
    }
    for ((layer, entry), descriptor) in layers.iter().zip(&request.fd_table).zip(descriptors) {
        let expected = open_object(root, layer, false)?;
        let held = File::from(descriptor);
        let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) };
        if entry.role != "block_ancestor"
            || entry.resource_id != layer.spec.resource_id
            || flags < 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & libc::O_PATH != 0
            || backing_identity(&expected).map_err(io_fault)?
                != backing_identity(&held).map_err(io_fault)?
        {
            return Err(crate::grants::fence_unproven(
                "block lease re-export does not match its immutable closure",
            ));
        }
    }
    if lease.state == "attached" && input.expected_revision.checked_add(1) == Some(lease.revision) {
        return Ok(json!({"lease":lease,"received":total,"total":total}));
    }
    if lease.state != "unknown" || input.expected_revision != lease.revision {
        return Err(Fault::new(
            "E_STALE_REVISION",
            "block lease is no longer unknown at that revision",
        ));
    }
    catalog.commit_reexport(&lease.resource_id, Some(&lease), total)?;
    let attached = catalog.lease(&lease.lease_id)?;
    Ok(json!({"lease":attached,"received":total,"total":total}))
}

impl Catalog {
    pub fn has_managed_block(&self, resource: &str) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_blocks WHERE resource_id=?)",
            [resource],
            |row| row.get(0),
        )?)
    }
    fn block_intent(&self, resource: &str) -> Result<Option<(String, BlockSpec, Option<String>)>> {
        let record: Option<(String, String, Option<String>)> = self.db.query_row(
            "SELECT operation_id,spec_json,backing_identity FROM managed_blocks WHERE resource_id=?",
            [resource], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional()?;
        record
            .map(|(op, spec, identity)| {
                Ok((
                    op,
                    serde_json::from_str(&spec)
                        .map_err(|_| Fault::new("E_CATALOG", "invalid stored block spec"))?,
                    identity,
                ))
            })
            .transpose()
    }

    fn begin_block(&self, op: &str, spec: &BlockSpec) -> Result<()> {
        let inserted = self.db.execute(
            "INSERT OR IGNORE INTO managed_blocks SELECT ?,?,?,NULL
            WHERE NOT EXISTS(SELECT 1 FROM resources WHERE resource_id=?)
            AND NOT EXISTS(SELECT 1 FROM volume_heads WHERE volume_id=?)
            AND NOT EXISTS(SELECT 1 FROM managed_blocks WHERE json_extract(spec_json,'$.volume_id')=?
                AND coalesce(json_extract(spec_json,'$.sealed'),0)=0)",
            params![
                spec.resource_id,
                op,
                json!(spec).to_string(),
                spec.resource_id,
                spec.volume_id,
                spec.volume_id,
            ],
        )?;
        if inserted == 0 {
            return Err(conflict("block object identifier already exists"));
        }
        Ok(())
    }

    fn commit_block(&mut self, op: &str, object: &BlockObject) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let descriptor = json!({"schema":"ManagedBlockObject/1", "object":object}).to_string();
        let digest = format!("sha256:{:x}", Sha256::digest(descriptor.as_bytes()));
        let mutable = object.spec.mutable();
        tx.execute(
            "INSERT INTO resources VALUES(?,?,'available','durable',?,?,?, ?,1)",
            params![
                object.spec.resource_id,
                if mutable { "block_head" } else { "descriptor" },
                !mutable,
                descriptor,
                digest,
                op
            ],
        )?;
        if let Some(id) = &object.spec.backing_id {
            tx.execute(
                "INSERT INTO resource_edges VALUES(?,?,'block_backing')",
                params![object.spec.resource_id, id],
            )?;
        }
        if let Some(volume) = &object.spec.volume_id {
            tx.execute(
                "INSERT INTO volume_heads VALUES(?,?,?)",
                params![volume, object.spec.resource_id, object.backing_identity],
            )?;
        }
        tx.execute(
            "UPDATE managed_blocks SET backing_identity=? WHERE resource_id=?",
            params![object.backing_identity, object.spec.resource_id],
        )?;
        tx.commit()?;
        self.resource(&object.spec.resource_id)
    }

    pub fn block_closure(&self, resource: &str) -> Result<Vec<BlockObject>> {
        let mut target = resource.to_string();
        let mut closure = Vec::new();
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(target.clone()) || closure.len() >= MAX_CLOSURE_DEPTH {
                return Err(Fault::invalid(
                    "managed block closure contains a cycle or exceeds its depth",
                ));
            }
            let (_, spec, identity) = self
                .block_intent(&target)?
                .ok_or_else(|| Fault::new("E_NOT_FOUND", "managed block object is absent"))?;
            let object = BlockObject {
                format: spec.format().into(),
                backing_identity: identity.ok_or_else(|| {
                    Fault::new("E_RESOURCE_UNAVAILABLE", "managed block object is staging")
                })?,
                spec,
            };
            if self.resource(&object.spec.resource_id)?["state"] != "available"
                || (!closure.is_empty() && object.spec.mutable())
            {
                return Err(Fault::new(
                    "E_RESOURCE_UNAVAILABLE",
                    "block closure contains an unavailable or mutable ancestor",
                ));
            }
            let next = object.spec.backing_id.clone();
            closure.push(object);
            match next {
                Some(id) => target = id,
                None => return Ok(closure),
            }
        }
    }

    fn seal_pins(&self, op: &str) -> Result<Vec<(String, String)>> {
        let mut query = self.db.prepare(
            "SELECT resource_id,state FROM root_refs
            WHERE owner_kind='block_seal' AND owner_id=? ORDER BY resource_id",
        )?;
        let mut pins = Vec::new();
        for row in query.query_map([op], |row| Ok((row.get(0)?, row.get(1)?)))? {
            pins.push(row?);
        }
        Ok(pins)
    }

    pub fn require_unsealed_head(&self, resource: &str) -> Result<()> {
        let pending: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM root_refs
                WHERE owner_kind='block_seal' AND resource_id=? AND state='active')",
            [resource],
            |row| row.get(0),
        )?;
        if pending {
            return Err(crate::grants::fence_unproven("volume head is being sealed"));
        }
        Ok(())
    }

    fn begin_block_seal(&mut self, op: &str, heads: &[VolumeHead]) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for head in heads {
            let conflict: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM writer_reservations WHERE volume_id=? OR head_resource_id=?)
                 OR EXISTS(SELECT 1 FROM root_refs
                    WHERE owner_kind='block_seal' AND resource_id=? AND state='active')",
                params![head.volume_id,head.head_resource_id,head.head_resource_id], |row| row.get(0),
            )?;
            if conflict {
                return Err(crate::grants::fence_unproven(
                    "a writer or another seal still owns one of the heads",
                ));
            }
            tx.execute(
                "INSERT INTO root_refs VALUES('block_seal',?,?,'active',1,?)",
                params![op, head.head_resource_id, op],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn commit_block_seal(&mut self, op: &str, objects: &[BlockObject]) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for object in objects {
            let id = &object.spec.resource_id;
            let volume = object
                .spec
                .volume_id
                .as_deref()
                .expect("sealed mutable volume");
            let changed = tx.execute(
                "DELETE FROM volume_heads WHERE volume_id=? AND head_resource_id=?",
                [volume, id],
            )?;
            if changed != 1 {
                return Err(crate::grants::fence_unproven(
                    "volume head changed during commit",
                ));
            }
            let descriptor = json!({"schema":"ManagedBlockObject/1", "object":object}).to_string();
            let digest = format!("sha256:{:x}", Sha256::digest(descriptor.as_bytes()));
            tx.execute(
                "UPDATE resources SET kind='descriptor',immutable=1,descriptor_json=?,descriptor_digest=?,revision=revision+1
                WHERE resource_id=? AND kind='block_head' AND state='available'",
                params![descriptor,digest,id],
            )?;
            tx.execute(
                "UPDATE managed_blocks SET spec_json=? WHERE resource_id=?",
                params![json!(object.spec).to_string(), id],
            )?;
            tx.execute(
                "UPDATE root_refs SET state='dropped',revision=revision+1
                WHERE owner_kind='block_seal' AND owner_id=? AND resource_id=?",
                params![op, id],
            )?;
            tx.execute(
                "INSERT INTO root_refs VALUES('operation',?,?,'active',1,?)
                ON CONFLICT(owner_kind,owner_id,resource_id) DO UPDATE SET
                    state='active',revision=root_refs.revision+1
                WHERE root_refs.state='dropped'",
                params![op, id, op],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
