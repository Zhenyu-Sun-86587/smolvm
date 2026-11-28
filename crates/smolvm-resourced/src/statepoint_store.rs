//! Durable representation of a parked point using the upstream chunk store.

use crate::catalog::Execution;
use crate::statepoint_capture::{Capture, Device, Export, KernelCapture, MAX_CHECKPOINT_BYTES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smolvm_checkpoint::{Writer, format::PackManifest, store::{self, ChunkedFile}};
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

    pub fn new_kernel(
        source: &Execution,
        export: &Export,
        capture: &KernelCapture,
        layout_digest: String,
        disk_generations: Vec<String>,
    ) -> Self {
        Self {
            schema: "StatePoint/1".into(),
            capture_id: export.capture_id.clone(),
            representation_id: export.representation_id.clone(),
            incarnation_id: source.incarnation_id.clone(),
            execution_epoch: source.execution_epoch,
            source_ram_digest: layout_digest,
            checkpoint_digest: digest(&capture.checkpoint),
            checkpoint_bytes: capture.checkpoint.len() as u64,
            capture_anchor: capture.anchor.clone(),
            helper_digest: capture.helper_digest.clone(),
            regions: capture.regions.iter().map(|region| Region {
                gpa: region.guest_start,
                length: region.size,
            }).collect(),
            devices: capture.devices.clone(),
            disk_generations,
        }
    }

    pub fn validate_checkpoint(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 != self.checkpoint_bytes || digest(bytes) != self.checkpoint_digest {
            return Err(invalid("checkpoint bytes differ from StatePoint"));
        }
        Ok(())
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

pub(crate) fn write_native(
    directory: &Path,
    point: Point,
    required_bundle: String,
    commit_id: String,
    capture: Capture,
    disks: BTreeMap<String, File>,
    mountinfo: Option<Vec<u8>>,
) -> io::Result<Manifest> {
    write(
        directory,
        point,
        required_bundle,
        commit_id,
        &capture.checkpoint,
        &mut RamReader::new(&capture),
        disks,
        mountinfo,
    )
}

pub(crate) fn write(
    directory: &Path,
    point: Point,
    required_bundle: String,
    commit_id: String,
    checkpoint: &[u8],
    ram: &mut impl Read,
    disks: BTreeMap<String, File>,
    mountinfo: Option<Vec<u8>>,
) -> io::Result<Manifest> {
    point.validate_checkpoint(checkpoint)?;
    let staging = tempfile::Builder::new()
        .prefix(".statepoint-")
        .tempdir_in(directory)?;
    let mut writer = Writer::new(&directory.join(".chunks"), staging.path())?;
    let cpu = writer.ingest(
        CHECKPOINT,
        point.checkpoint_bytes,
        0o400,
        &mut Cursor::new(checkpoint),
    )?;
    let ram = writer.ingest(
        MEMORY,
        point.memory_bytes()?,
        0o400,
        ram,
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
    if let Some(raw) = mountinfo {
        crate::saved_files::write_mounts(staging.path(), &manifest, raw)?;
    }
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

/// Validate a surviving Restore RAM file against the verified durable index.
pub(crate) fn verify_retained_ram(
    directory: &Path,
    manifest: &Manifest,
    file: &File,
) -> io::Result<()> {
    let ram = ChunkedFile::open(&directory.join(&manifest.statepoint.representation_id), MEMORY)?;
    let chunk_size = ChunkedFile::chunk_size();
    let size = ram.size();
    if size != manifest.statepoint.memory_bytes()?
        || file.metadata()?.len() != size
        || ram.chunks() as u64 != size.div_ceil(chunk_size)
    {
        return Err(invalid("retained StatePoint RAM has a different layout"));
    }
    let mut buffer = vec![0; chunk_size as usize];
    for index in 0..ram.chunks() {
        let offset = index as u64 * chunk_size;
        let current = &mut buffer[..(size - offset).min(chunk_size) as usize];
        file.read_exact_at(current, offset)?;
        let matches = match ram.read(index)? {
            Some(stored) => stored == current,
            None => current.iter().all(|byte| *byte == 0),
        };
        if !matches {
            return Err(invalid("retained StatePoint RAM differs from the durable image"));
        }
    }
    Ok(())
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
    manifest.statepoint.validate_checkpoint(&bytes)?;
    if memory.metadata()?.len() != manifest.statepoint.memory_bytes()? {
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

pub(crate) fn collect(directory: &Path, resource: &str) -> io::Result<()> {
    if !crate::ipc::valid_id(resource) {
        return Err(invalid("invalid StatePoint representation ID"));
    }
    let artifact = directory.join(resource);
    let tombstone = directory.join(format!(".gc-{resource}"));
    match fs::symlink_metadata(&artifact) {
        Ok(meta) if meta.is_dir() => store::publish(&artifact, &tombstone)?,
        Ok(_) => return Err(invalid("StatePoint representation is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match fs::symlink_metadata(&tombstone) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(&tombstone)?,
        Ok(_) => return Err(invalid("StatePoint tombstone is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    File::open(directory)?.sync_all()?;
    store::prune_in_batches(&directory.join(".chunks"), 128)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{backing_identity, blocks, catalog::Catalog};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn historical_layer_requires_the_committed_bytes_before_adopting_its_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = File::open(temp.path()).unwrap();
        fs::create_dir(temp.path().join("disk")).unwrap();
        let data = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(temp.path().join("disk/data"))
            .unwrap();
        data.set_len(512).unwrap();
        data.set_permissions(fs::Permissions::from_mode(0o400)).unwrap();
        let (dev, ino) = backing_identity::live(&data).unwrap();
        let durable = backing_identity::durable(&data).unwrap();
        let recorded_dev = if durable.is_some() { dev ^ 1 } else { dev };
        let mut object = blocks::BlockObject {
            spec: blocks::BlockSpec {
                resource_id: "disk".into(),
                capacity_bytes: 512,
                volume_id: Some("volume".into()),
                backing_id: None,
                content_sha256: None,
                sealed: true,
            },
            format: "raw".into(),
            backing_identity: format!("inode:{recorded_dev}:{ino}"),
            verified_identity: None,
        };
        let checkpoint = b"checkpoint";
        let point = Point {
            schema: "StatePoint/1".into(),
            capture_id: "point".into(),
            representation_id: "artifact".into(),
            incarnation_id: "source".into(),
            execution_epoch: 1,
            source_ram_digest: digest(b"ram-layout"),
            checkpoint_digest: digest(checkpoint),
            checkpoint_bytes: checkpoint.len() as u64,
            capture_anchor: "anchor".into(),
            helper_digest: digest(b"helper"),
            regions: vec![Region { gpa: 0, length: 4096 }],
            devices: Vec::new(),
            disk_generations: vec!["disk".into()],
        };
        let disk = |file| BTreeMap::from([("disk".to_string(), file)]);
        let manifest = write(
            temp.path(),
            point.clone(),
            digest(b"bundle"),
            "commit".into(),
            checkpoint,
            &mut io::repeat(0),
            disk(data.try_clone().unwrap()),
        ).unwrap();
        let committed = manifest.digest().unwrap();
        let manifest = read(temp.path(), &point, &digest(b"bundle"), "commit").unwrap();
        assert_eq!(committed, manifest.digest().unwrap());
        let (file, proof) = blocks::open_for_statepoint_verification(&root, &object).unwrap();
        assert_eq!(proof.is_some(), durable.is_some());
        data.write_all_at(b"changed", 0).unwrap();
        assert_eq!(
            materialize(temp.path(), &manifest, disk(file)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        data.write_all_at(b"\0\0\0\0\0\0\0", 0).unwrap();
        let (file, _) = blocks::open_for_statepoint_verification(&root, &object).unwrap();
        materialize(temp.path(), &manifest, disk(file)).unwrap();

        if let Some(proof) = proof {
            use rusqlite::{params, Connection};
            let catalog = Catalog { db: Connection::open_in_memory().unwrap() };
            catalog.db.execute_batch(
                "CREATE TABLE managed_blocks(resource_id TEXT PRIMARY KEY, backing_identity TEXT);
                 CREATE TABLE resources(resource_id TEXT PRIMARY KEY, immutable INTEGER, state TEXT);"
            ).unwrap();
            catalog.db.execute_batch(include_str!("schema_backing_identities.sql")).unwrap();
            catalog.db.execute(
                "INSERT INTO managed_blocks VALUES (?,?)",
                params![proof.resource_id, proof.legacy_identity],
            ).unwrap();
            catalog.db.execute(
                "INSERT INTO resources VALUES (?,1,'available')", [&proof.resource_id],
            ).unwrap();
            let wire = serde_json::to_vec(&object).unwrap();
            assert_eq!(
                blocks::open_object(&root, &object, false).unwrap_err().code,
                "E_BACKING_IDENTITY_UNPROVEN"
            );
            catalog.commit_verified_backings(&[proof]).unwrap();
            object.verified_identity = catalog.db.query_row(
                "SELECT durable_identity FROM verified_block_backings WHERE resource_id='disk'",
                [],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(wire, serde_json::to_vec(&object).unwrap());
            blocks::open_object(&root, &object, false).unwrap();
        }
        assert_eq!(committed, manifest.digest().unwrap());
    }
}
