//! Read a fixed durable capture without acquiring its Guest execution.

mod filesystem;

use crate::{
    blocks::{self, BlockObject},
    catalog::Catalog,
    ipc::{valid_digest, valid_id, Fault, Request, Result},
    native_control::Endpoint,
    statepoint_catalog,
    statepoint_store::{self, Manifest},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use smolvm_protocol::{saved_files as topology, AgentRequest, AgentResponse};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Mutex, OnceLock},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const SIDECAR: &str = "SavedFileMounts.json";
const MAX_TRANSFER: u64 = 4 << 30;

pub(super) fn host(error: io::Error) -> Fault {
    Fault::new("E_HOST_IO", error.to_string())
}
pub(super) fn unavailable(message: impl ToString) -> Fault {
    Fault::new("E_SAVED_FILE_UNAVAILABLE", message.to_string())
}
fn unsupported(message: &str) -> Fault {
    Fault::new("E_CAPABILITY_UNSUPPORTED", message)
}

pub(crate) fn record_mounts(catalog: &Catalog, endpoint: &Endpoint, operation: &str) -> Result<()> {
    if catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM saved_file_mounts WHERE operation_id=?)",
        [operation],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(());
    }

    let info = match crate::resource_resize::observations::agent(
        endpoint,
        &AgentRequest::CaptureSavedFileMounts,
    ) {
        Ok(AgentResponse::Ok { data: Some(data) }) => {
            serde_json::from_value::<Vec<u8>>(data.get("mountinfo").cloned().unwrap_or_default())
                .ok()
                .filter(|raw| topology::parse(raw).is_ok())
        }
        _ => None,
    };
    catalog.db.execute(
        "INSERT INTO saved_file_mounts(operation_id,mountinfo) VALUES(?,?) ON CONFLICT DO NOTHING",
        (operation, info),
    )?;
    Ok(())
}

pub(crate) fn mounts(db: &Connection, operation: &str) -> Result<Option<Vec<u8>>> {
    Ok(db
        .query_row(
            "SELECT mountinfo FROM saved_file_mounts WHERE operation_id=?",
            [operation],
            |row| row.get(0),
        )
        .optional()?
        .flatten())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MountReceipt {
    capture_id: String,
    capture_digest: String,
    mountinfo: String,
}

pub(crate) fn write_mounts(staging: &Path, manifest: &Manifest, raw: Vec<u8>) -> io::Result<()> {
    topology::parse(&raw)?;
    let receipt = MountReceipt {
        capture_id: manifest.statepoint.capture_id.clone(),
        capture_digest: manifest.digest()?,
        mountinfo: STANDARD.encode(raw),
    };
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(staging.join(SIDECAR))?;
    serde_json::to_writer(&mut file, &receipt)?;
    file.sync_all()
}

fn read_mounts(
    root: &Path,
    representation: &str,
    manifest: &Manifest,
) -> Result<Vec<topology::Mount>> {
    let path = root.join(representation).join(SIDECAR);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                unsupported("the capture has no synchronized Guest mount topology")
            } else {
                host(err)
            }
        })?;
    let mut raw = Vec::new();
    file.take(40 << 10).read_to_end(&mut raw).map_err(host)?;
    let saved: MountReceipt = serde_json::from_slice(&raw).map_err(unavailable)?;
    if saved.capture_id != manifest.statepoint.capture_id
        || saved.capture_digest != manifest.digest().map_err(host)?
    {
        return Err(unavailable(
            "saved mount topology belongs to a different capture",
        ));
    }
    topology::parse(&STANDARD.decode(saved.mountinfo).map_err(unavailable)?).map_err(unavailable)
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Scope,
    List,
    Stat,
    Exists,
    Realpath,
    Read,
    Archive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    job_id: String,
    capture_id: String,
    manifest_digest: String,
    source_operation_id: String,
    instance_id: String,
    operation: Operation,
    #[serde(default)]
    path: String,
    #[serde(default)]
    cursor: String,
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    offset: u64,
    length: Option<u64>,
    #[serde(default)]
    follow: bool,
}

pub(super) struct Disk {
    pub layers: Vec<(BlockObject, File)>,
    pub volume: String,
    pub generation: String,
    pub capacity: u64,
}

struct Job {
    bundle: String,
    capture: String,
    started: Instant,
    task: JoinHandle<Result<File>>,
}

fn jobs() -> &'static Mutex<BTreeMap<String, Job>> {
    static JOBS: OnceLock<Mutex<BTreeMap<String, Job>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn bundle<'a>(catalog: &Catalog, request: &'a Request) -> Result<&'a str> {
    let bundle = request
        .bundle_digest
        .as_deref()
        .filter(|id| valid_digest(id));
    let Some(bundle) = bundle.filter(|_| request.route_id.as_deref() == Some("deep")) else {
        return Err(Fault::invalid("invalid saved file Worker route"));
    };
    catalog.bundle(bundle)?;
    Ok(bundle)
}

pub(crate) fn prepare(
    catalog: &Catalog,
    objects: &File,
    points: &Path,
    request: &Request,
) -> Result<Value> {
    let bundle = bundle(catalog, request)?;
    let input: Input = request.payload()?;
    if !valid_id(&input.job_id)
        || !valid_id(&input.capture_id)
        || !valid_id(&input.source_operation_id)
        || !valid_id(&input.instance_id)
        || !valid_digest(&input.manifest_digest)
    {
        return Err(Fault::invalid("invalid saved file capture identity"));
    }
    let path = STANDARD
        .decode(&input.path)
        .map_err(|_| Fault::invalid("invalid saved file path encoding"))?;
    let cursor = STANDARD
        .decode(&input.cursor)
        .map_err(|_| Fault::invalid("invalid saved file cursor encoding"))?;
    if input.operation != Operation::Scope && !topology::valid_path(&path)
        || input.operation == Operation::List && !(1..=200).contains(&input.limit)
        || !cursor.is_empty()
            && (input.operation != Operation::List || !topology::valid_path(&cursor))
        || input.operation != Operation::Read && (input.offset != 0 || input.length.is_some())
    {
        return Err(Fault::invalid("invalid saved file query"));
    }
    let mut jobs = jobs()
        .lock()
        .map_err(|_| unavailable("saved reader queue unavailable"))?;
    jobs.retain(|_, job| {
        !job.task.is_finished() || job.started.elapsed() < Duration::from_secs(120)
    });
    if jobs.len() >= 2 || jobs.contains_key(&input.job_id) {
        return Err(Fault::new(
            "E_RESOURCE_LIMIT",
            "saved file readers are busy",
        ));
    }

    let record = catalog.require_statepoint(&input.capture_id)?;
    let origin = catalog.operation(&input.source_operation_id)?;
    let source = catalog.execution(&record.point.incarnation_id)?;
    if origin.operation_id != record.operation_id
        || origin.instance_id != input.instance_id
        || source.instance_id != input.instance_id
        || source.bundle_digest != bundle
        || origin.bundle_digest != bundle
        || origin.route_id != "deep"
        || record.manifest_digest.as_deref() != Some(input.manifest_digest.as_str())
        || !matches!(
            record.phase.as_str(),
            "durable" | "stop_committed" | "hibernated"
        )
        || !statepoint_catalog::has_root(&catalog.db, &record)?
    {
        return Err(Fault::new(
            "E_STATE_CONFLICT",
            "saved view does not identify this durable capture",
        ));
    }
    let manifest = statepoint_store::read(points, &record.point, bundle, &record.operation_id)
        .map_err(unavailable)?;
    if manifest.digest().map_err(host)? != input.manifest_digest {
        return Err(unavailable("saved capture manifest digest differs"));
    }
    let mounts = read_mounts(points, &record.point.representation_id, &manifest)?;

    // The open descriptors hold the immutable input even if catalog roots
    // are released after admission. The background task never sees writers.
    let mut disks = BTreeMap::new();
    for (slot, device) in record
        .point
        .devices
        .iter()
        .filter_map(|device| device.block())
        .enumerate()
    {
        if slot == 0 && device.role != "root" {
            return Err(unavailable("saved view has no managed root disk"));
        }
        let generation = device
            .writable_head_id
            .as_ref()
            .unwrap_or(&device.generation_id);
        if !record.point.disk_generations.contains(generation) {
            return Err(unavailable(
                "saved disk has no immutable captured generation",
            ));
        }
        let mut layers = Vec::new();
        for layer in catalog.block_closure(generation)? {
            if layer.spec.mutable() {
                return Err(unavailable("saved view contains a writable generation"));
            }
            let file = blocks::open_object(objects, &layer, false)?;
            layers.push((layer, file));
        }
        disks.insert(
            slot,
            Disk {
                layers,
                volume: device.volume_id.clone(),
                generation: generation.clone(),
                capacity: device.capacity_bytes,
            },
        );
    }
    if !disks.contains_key(&0) {
        return Err(unavailable("saved view has no captured root disk"));
    }
    let job_id = input.job_id.clone();
    let capture = input.capture_id.clone();
    let task = thread::Builder::new()
        .name("saved-file-reader".to_owned())
        .spawn(move || filesystem::serve(input, path, cursor, mounts, disks))
        .map_err(host)?;
    jobs.insert(
        job_id.clone(),
        Job {
            bundle: bundle.into(),
            capture,
            started: Instant::now(),
            task,
        },
    );
    Ok(json!({"job_id":job_id}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lookup {
    job_id: String,
}

pub(crate) fn read(catalog: &Catalog, request: &Request) -> Result<(Value, File)> {
    let bundle = bundle(catalog, request)?;
    let input: Lookup = request.payload()?;
    let mut jobs = jobs()
        .lock()
        .map_err(|_| unavailable("saved reader queue unavailable"))?;
    let job = jobs
        .get(&input.job_id)
        .filter(|job| job.bundle == bundle)
        .ok_or_else(|| Fault::new("E_NOT_FOUND", "saved file request does not exist"))?;
    if !job.task.is_finished() {
        return Err(Fault::new(
            "E_SAVED_FILE_PENDING",
            "saved file reader is preparing its result",
        ));
    }
    let job = jobs.remove(&input.job_id).unwrap();
    drop(jobs);
    let file = job
        .task
        .join()
        .map_err(|_| unavailable("saved reader failed"))??;
    let bytes = file.metadata().map_err(host)?.len();
    Ok((json!({"capture_id":job.capture,"bytes":bytes}), file))
}
