//! Receive an immutable point from the registered source's native VMM actor.

use crate::catalog::{Catalog, Execution, Operation};
use crate::escrow::{check_backing, Descriptor};
use crate::ipc::{self, valid_id, Fault, Result};
use crate::native_control::Endpoint;
use crate::worker::pid_exited;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use socket2::Socket;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

pub(crate) const MAX_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const MAX_RAM_BACKINGS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Purpose {
    Checkpoint,
    Hibernate,
    RollbackRescue,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Export {
    pub capture_id: String,
    pub representation_id: String,
    pub purpose: Purpose,
    pub session: u32,
    pub hold_token: String,
}

impl Export {
    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.capture_id)
            || !valid_id(&self.representation_id)
            || self.capture_id == self.representation_id
            || self.session == 0
            || self.hold_token.len() != 32
            || !u128::from_str_radix(&self.hold_token, 16).is_ok_and(|token| token != 0)
        {
            return Err(Fault::invalid(
                "invalid StatePoint identity or held source scope",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Header {
    protocol: String,
    export: String,
    session: u32,
    hold_token: String,
    checkpoint_bytes: usize,
    descriptor_bytes: usize,
    fd_count: usize,
    devices: Vec<Device>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct Device {
    device_id: String,
    virtio_type: u32,
    mmio_address: u64,
    irq: u32,
    offered_features: u64,
    negotiated_features: u64,
    block: Option<Block>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bootstrap_init_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct Block {
    capacity_bytes: u64,
    read_only: bool,
    managed_attachment: Attachment,
    managed_backing_identities: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct Attachment {
    attachment_id: String,
    device_id: String,
    role: String,
    volume_id: String,
    generation_id: String,
    writable_head_id: Option<String>,
    grant_id: Option<String>,
    execution_epoch: i64,
    capacity_bytes: u64,
    layers: Vec<String>,
}

impl Device {
    pub(crate) fn managed_source(&self)->Option<(&str,(&str,&str))> {
        let a=&self.block.as_ref()?.managed_attachment;
        Some((&a.device_id,(a.writable_head_id.as_deref().unwrap_or(&a.generation_id),&a.volume_id)))
    }
}
pub(crate) struct Capture {
    pub checkpoint: Vec<u8>,
    pub descriptor: Descriptor,
    pub descriptor_json: Value,
    pub backings: BTreeMap<String, File>,
    pub devices: Vec<Device>,
    pub anchor: String,
    pub helper_digest: String,
}

#[derive(Deserialize)]
struct ParkedGate {
    anchor: [u8; 16],
    helper: [u8; 32],
    #[serde(default)]
    writer_hold_token: Option<String>,
}

fn parked_gate(mut checkpoint: &[u8]) -> Result<ParkedGate> {
    fn count(input: &mut &[u8]) -> Option<usize> {
        let (header, remaining) = input.split_at_checked(4)?;
        *input = remaining;
        Some(u32::from_le_bytes(header.try_into().unwrap()) as usize)
    }
    fn take<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
        let length = count(input)?;
        let (section, remaining) = input.split_at_checked(length)?;
        *input = remaining;
        Some(section)
    }
    let invalid = || Fault::invalid("native checkpoint lacks its parked Guest gate");
    take(&mut checkpoint).ok_or_else(invalid)?;
    let cpus = count(&mut checkpoint)
        .filter(|count| (1..=256).contains(count))
        .ok_or_else(invalid)?;
    for _ in 0..cpus {
        take(&mut checkpoint).ok_or_else(invalid)?;
    }
    let devices: Value = serde_json::from_slice(take(&mut checkpoint).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let mut gates = devices["devices"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .filter_map(|device| device.get("ParkedGuestGate"));
    let gate = gates.next().ok_or_else(invalid)?;
    if gates.next().is_some() {
        return Err(invalid());
    }
    serde_json::from_value(gate.clone()).map_err(|_| invalid())
}

pub(crate) fn host_io(error: io::Error) -> Fault {
    Fault::new("E_HOST_IO", error.to_string())
}

pub(crate) fn control_reply(mut stream: &UnixStream, command: &str) -> Result<Value> {
    writeln!(stream, "{command}").map_err(host_io)?;
    let mut header = Vec::new();
    // Do not buffer bytes past the newline. A later recvmsg must own the
    // ancillary descriptors associated with the bytes after the metadata.
    for _ in 0..ipc::MAX_PACKET {
        let mut byte = [0];
        stream.read_exact(&mut byte).map_err(host_io)?;
        if byte[0] == b'\n' {
            if let Some(value) = header.strip_prefix(b"OK ") {
                return serde_json::from_slice(value)
                    .map_err(|_| Fault::invalid("malformed native capture receipt"));
            }
            return Err(Fault::new(
                "E_CAPTURE_NOT_HELD",
                String::from_utf8_lossy(&header).into_owned(),
            ));
        }
        header.push(byte[0]);
    }
    Err(Fault::invalid("oversized native capture receipt"))
}

pub(crate) fn acquire(endpoint: &Endpoint, export: &Export) -> Result<Capture> {
    let (socket, pidfd) = endpoint.connect()?;
    let mut stream = UnixStream::from(OwnedFd::from(socket));
    let command = format!("CAPTURE_EXPORT {} {}", export.session, export.hold_token);
    let response = control_reply(&stream, &command)?;
    let header: Header = serde_json::from_value(response)
        .map_err(|_| Fault::invalid("native capture metadata is incomplete"))?;
    if header.protocol != "CaptureControl/1"
        || header.export != "parked"
        || header.session != export.session
        || header.hold_token != export.hold_token
        || header.checkpoint_bytes == 0
        || header.checkpoint_bytes > MAX_CHECKPOINT_BYTES
        || header.descriptor_bytes == 0
        || header.descriptor_bytes > ipc::MAX_PACKET
        || header.fd_count == 0
        || header.fd_count > MAX_RAM_BACKINGS
        || header.devices.is_empty()
    {
        return Err(Fault::invalid(
            "native capture does not describe the requested parked point",
        ));
    }
    let mut checkpoint = vec![0; header.checkpoint_bytes];
    let mut mapping = vec![0; header.descriptor_bytes];
    stream.read_exact(&mut checkpoint).map_err(host_io)?;
    let gate = parked_gate(&checkpoint)?;
    if gate.anchor == [0; 16]
        || gate.helper == [0; 32]
        || gate
            .writer_hold_token
            .as_deref()
            .is_some_and(|token| token != export.hold_token)
    {
        return Err(Fault::invalid(
            "native checkpoint has a different measured capture gate",
        ));
    }
    stream.read_exact(&mut mapping).map_err(host_io)?;
    let descriptor_json: Value = serde_json::from_slice(&mapping)
        .map_err(|_| Fault::invalid("native RAM mapping is invalid"))?;
    let descriptor: Descriptor = serde_json::from_value(descriptor_json.clone())
        .map_err(|_| Fault::invalid("native RAM mapping is invalid"))?;
    descriptor.validate()?;
    if descriptor.regions.len() > 256 || descriptor.backing_sizes.len() != header.fd_count {
        return Err(Fault::invalid(
            "native RAM mapping exceeds its expected file layout",
        ));
    }
    let socket = Socket::from(OwnedFd::from(stream));
    let mut backings = BTreeMap::new();
    for (id, &length) in &descriptor.backing_sizes {
        let packet = ipc::receive_packet_with_limit(&socket, 1)?;
        if packet.body != b"F" || packet.descriptors.len() != 1 {
            return Err(Fault::invalid("native capture FD packet is invalid"));
        }
        let backing = check_backing(packet.descriptors.into_iter().next().unwrap(), length)?;
        let (device, inode, _) = backing.identity();
        if *id != format!("ram-{device:x}-{inode:x}") {
            return Err(Fault::invalid(
                "native capture FD does not match its layout identity",
            ));
        }
        backings.insert(id.clone(), backing.file);
    }
    if pid_exited(&pidfd).map_err(host_io)? {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "registered VMM exited during capture export",
        ));
    }
    Ok(Capture {
        checkpoint,
        descriptor,
        descriptor_json,
        backings,
        devices: header.devices,
        anchor: hex::encode(gate.anchor),
        helper_digest: format!("sha256:{}", hex::encode(gate.helper)),
    })
}

pub(crate) fn disk_roots(
    catalog: &Catalog,
    operation: &Operation,
    source: &Execution,
    export: &Export,
    devices: &[Device],
) -> Result<Vec<String>> {
    let mut device_ids = HashSet::new();
    let mut writers = HashMap::new();
    let mut roots = BTreeMap::new();
    for device in devices {
        if !device_ids.insert(device.device_id.as_str())
            || device.virtio_type == 2 && device.block.is_none()
        {
            return Err(Fault::invalid(
                "captured block transport inventory is incomplete",
            ));
        }
        let Some(block) = &device.block else { continue };
        let attachment = &block.managed_attachment;
        if attachment.device_id != device.device_id
            || attachment.capacity_bytes != block.capacity_bytes
            || attachment.execution_epoch != source.execution_epoch
        {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "captured block attachment scope changed",
            ));
        }
        let root = match (
            &attachment.writable_head_id,
            &attachment.grant_id,
            block.read_only,
        ) {
            (None, None, true) => &attachment.generation_id,
            (Some(head), Some(grant), false) => {
                if writers
                    .insert(attachment.volume_id.clone(), (head.clone(), grant.clone()))
                    .is_some()
                {
                    return Err(Fault::invalid("capture repeats a writable volume"));
                }
                head
            }
            _ => {
                return Err(Fault::invalid(
                    "captured block has no consistent access mode",
                ))
            }
        };
        let closure = catalog.block_closure(root)?;
        if closure[0].spec.mutable()
            || closure[0].spec.capacity_bytes != block.capacity_bytes
            || !closure
                .iter()
                .map(|layer| &layer.spec.resource_id)
                .eq(&attachment.layers)
            || closure.len() != block.managed_backing_identities.len()
            || closure
                .iter()
                .zip(&block.managed_backing_identities)
                .any(|(layer, (dev, ino))| layer.backing_identity != format!("inode:{dev}:{ino}"))
        {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "captured block graph differs from its sealed generation",
            ));
        }
        roots.insert(root.clone(), ());
    }
    if !writers.is_empty() {
        crate::pivots::require_capture_pivot(
            catalog,
            &operation.operation_id,
            source,
            &export.hold_token,
            &writers,
        )?;
    }
    Ok(roots.into_keys().collect())
}

pub(crate) fn open_disks(
    catalog: &Catalog,
    objects: &File,
    roots: &[String],
) -> Result<BTreeMap<String, File>> {
    let mut available = BTreeMap::new();
    for root in roots {
        for layer in catalog.block_closure(root)? {
            let id = layer.spec.resource_id.clone();
            if let std::collections::btree_map::Entry::Vacant(entry) = available.entry(id) {
                entry.insert(crate::blocks::open_object(objects, &layer, false)?);
            }
        }
    }
    Ok(available)
}
