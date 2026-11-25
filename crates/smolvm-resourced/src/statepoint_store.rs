//! Durable representation of a parked point using the upstream chunk store.

use crate::catalog::Execution;
use crate::statepoint_capture::{Capture, Device, Export, MAX_CHECKPOINT_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smolvm_checkpoint::{Writer, format::PackManifest, store};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;

const MANIFEST: &str = "CaptureManifest.json";
const CHECKPOINT: &str = "checkpoint.bin";
const MEMORY: &str = "memory.bin";
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Region {
    pub gpa: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Point {
    pub schema: String,
    pub capture_id: String,
    pub representation_id: String,
    pub incarnation_id: String,
    pub execution_epoch: i64,
    pub source_ram_digest: String,
    pub checkpoint_digest: String,
    pub checkpoint_bytes: u64,
    pub capture_anchor: String,
    pub helper_digest: String,
    pub regions: Vec<Region>,
    pub devices: Vec<Device>,
    pub disk_generations: Vec<String>,
}

impl Point {
    pub fn new(
        source: &Execution,
        export: &Export,
        capture: &Capture,
        disk_generations: Vec<String>,
    ) -> Self {
        Self {
            schema: "StatePoint/1".into(),
            capture_id: export.capture_id.clone(),
            representation_id: export.representation_id.clone(),
            incarnation_id: source.incarnation_id.clone(),
            execution_epoch: source.execution_epoch,
            source_ram_digest: digest(capture.descriptor_json.to_string().as_bytes()),
            checkpoint_digest: digest(&capture.checkpoint),
            checkpoint_bytes: capture.checkpoint.len() as u64,
            capture_anchor: capture.anchor.clone(),
            helper_digest: capture.helper_digest.clone(),
            regions: capture
                .descriptor
                .regions
                .iter()
                .map(|region| Region {
                    gpa: region.gpa,
                    length: region.length,
                })
                .collect(),
            devices: capture.devices.clone(),
            disk_generations,
        }
    }

    pub fn memory_bytes(&self) -> io::Result<u64> {
        self.regions.iter().try_fold(0u64, |total, region| {
            total
                .checked_add(region.length)
                .ok_or_else(|| invalid("StatePoint RAM size overflow"))
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    schema: String,
    pub statepoint: Point,
    pub required_bundle: String,
    pub commit_id: String,
    encoding: String,
    durability: String,
    closure_digest: String,
    chunk_index_digest: String,
    disk_assets: Vec<DiskAsset>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskAsset {
    resource_id: String,
    bytes: u64,
    digest: String,
}

impl Manifest {
    pub fn digest(&self) -> io::Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }

    pub(crate) fn disk_hashes(&self) -> impl Iterator<Item = (&str, &str, u64)> {
        self.disk_assets
            .iter()
            .map(|disk| (disk.resource_id.as_str(), disk.digest.as_str(), disk.bytes))
    }
}

fn digest(data: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(data))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn disk_digests(disks: BTreeMap<String, File>, flush: bool) -> io::Result<Vec<DiskAsset>> {
    disks
        .into_iter()
        .map(|(resource_id, mut file)| {
            if flush {
                file.sync_all()?;
            }
            let mut digest = Sha256::new();
            let bytes = io::copy(&mut file, &mut digest)?;
            if bytes != file.metadata()?.len() {
                return Err(invalid("captured disk length changed"));
            }
            Ok(DiskAsset {
                resource_id,
                bytes,
                digest: format!("sha256:{:x}", digest.finalize()),
            })
        })
        .collect()
}

struct RamReader<'a> {
    capture: &'a Capture,
    extents: std::vec::IntoIter<&'a crate::escrow::Extent>,
    current: Option<&'a crate::escrow::Extent>,
    cursor: u64,
}

impl<'a> RamReader<'a> {
    fn new(capture: &'a Capture) -> Self {
        let mut extents = capture
            .descriptor
            .regions
            .iter()
            .flat_map(|region| &region.extents)
            .collect::<Vec<_>>()
            .into_iter();
        let current = extents.next();
        Self {
            capture,
            extents,
            current,
            cursor: 0,
        }
    }
}

impl Read for RamReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let Some(extent) = self.current else {
            return Ok(0);
        };
        let count = (extent.length - self.cursor).min(output.len() as u64) as usize;
        self.capture.backings[&extent.backing_id]
            .read_exact_at(&mut output[..count], extent.backing_offset + self.cursor)?;
        self.cursor += count as u64;
        if self.cursor == extent.length {
            self.current = self.extents.next();
            self.cursor = 0;
        }
        Ok(count)
    }
}

pub(crate) fn write(
    directory: &Path,
    point: Point,
    required_bundle: String,
    commit_id: String,
    capture: Capture,
    disks: BTreeMap<String, File>,
) -> io::Result<Manifest> {
    let staging = tempfile::Builder::new()
        .prefix(".statepoint-")
        .tempdir_in(directory)?;
    let mut writer = Writer::new(&directory.join(".chunks"), staging.path())?;
    let cpu = writer.ingest(
        CHECKPOINT,
        point.checkpoint_bytes,
        0o400,
        &mut Cursor::new(&capture.checkpoint),
    )?;
    let ram = writer.ingest(
        MEMORY,
        point.memory_bytes()?,
        0o400,
        &mut RamReader::new(&capture),
    )?;
    // This internal chunk index has no bootable OCI payload. Native identity,
    // disk generations and the exact reader are in CaptureManifest below.
    let index_manifest = PackManifest::new(
        "StatePoint/1".into(),
        required_bundle.clone(),
        "linux/amd64".into(),
        "linux/amd64".into(),
    );
    writer.finish(staging.path(), index_manifest, vec![cpu, ram])?;
    drop(writer);
    drop(capture);
    let manifest = Manifest {
        schema: "CaptureManifest/1".into(),
        closure_digest: digest(&serde_json::to_vec(&point)?),
        chunk_index_digest: store::index_digest(staging.path())?,
        encoding: "smolvm-checkpoint-zstd-sha256-v1".into(),
        durability: "durable".into(),
        disk_assets: disk_digests(disks, true)?,
        statepoint: point,
        required_bundle,
        commit_id,
    };
    let mut header = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(staging.path().join(MANIFEST))?;
    header.write_all(&serde_json::to_vec(&manifest)?)?;
    header.sync_all()?;
    File::open(staging.path())?.sync_all()?;
    store::publish(
        staging.path(),
        &directory.join(&manifest.statepoint.representation_id),
    )?;
    Ok(manifest)
}

pub(crate) fn read(
    directory: &Path,
    expected: &Point,
    bundle: &str,
    commit_id: &str,
) -> io::Result<Manifest> {
    let artifact = directory.join(&expected.representation_id);
    let file = File::open(artifact.join(MANIFEST))?;
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(invalid("StatePoint manifest is oversized"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if &manifest.statepoint != expected
        || manifest.schema != "CaptureManifest/1"
        || manifest.commit_id != commit_id
        || manifest.required_bundle != bundle
        || manifest.closure_digest != digest(&serde_json::to_vec(expected)?)
        || manifest.durability != "durable"
        || manifest.encoding != "smolvm-checkpoint-zstd-sha256-v1"
        || manifest.chunk_index_digest != store::index_digest(&artifact)?
    {
        return Err(invalid(
            "StatePoint manifest, closure or required reader changed",
        ));
    }
    Ok(manifest)
}

pub(crate) fn materialize(
    directory: &Path,
    manifest: &Manifest,
    disks: BTreeMap<String, File>,
) -> io::Result<(File, File)> {
    materialize_in(directory, manifest, disks, directory)
}

pub(crate) fn materialize_in(
    directory: &Path,
    manifest: &Manifest,
    disks: BTreeMap<String, File>,
    scratch_dir: &Path,
) -> io::Result<(File, File)> {
    if disk_digests(disks, false)? != manifest.disk_assets {
        return Err(invalid("StatePoint disk generation length or hash changed"));
    }
    let artifact = directory.join(&manifest.statepoint.representation_id);
    let scratch = tempfile::Builder::new()
        .prefix(".restore-")
        .tempdir_in(scratch_dir)?;
    let output = scratch.path().join("materialized");
    let pack = store::materialize(&artifact, &output)?;
    if pack.digest != manifest.required_bundle {
        return Err(invalid("checkpoint store requires a different bundle"));
    }
    let mut checkpoint = File::open(output.join(CHECKPOINT))?;
    let memory = File::open(output.join(MEMORY))?;
    let mut bytes = Vec::new();
    (&mut checkpoint)
        .take(MAX_CHECKPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != manifest.statepoint.checkpoint_bytes
        || digest(&bytes) != manifest.statepoint.checkpoint_digest
        || memory.metadata()?.len() != manifest.statepoint.memory_bytes()?
    {
        return Err(invalid(
            "materialized checkpoint or RAM layout differs from StatePoint",
        ));
    }
    Ok((File::open(output.join(CHECKPOINT))?, memory))
}

/// An interrupted publication can replay only once every dependency is read
/// and validated. Sync the parent again in case the previous Worker stopped
/// after the atomic rename and before its directory flush.
pub(crate) fn verify_replay(
    directory: &Path,
    manifest: &Manifest,
    disks: BTreeMap<String, File>,
) -> io::Result<()> {
    let _ = materialize(directory, manifest, disks)?;
    fs::File::open(directory)?.sync_all()
}
