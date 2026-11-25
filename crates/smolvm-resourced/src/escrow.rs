use crate::catalog::{Catalog, Execution};
use crate::escrow_catalog::{LeaseRecord, TransferRecord};
use crate::ipc::{valid_digest, valid_id, Fault, FdEntry, Request, Result, MAX_FDS};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

const MAX_BACKINGS: usize = 512;
const MAX_EXTENTS: usize = 1024;
const MAX_TRANSFERS: usize = 32;
const MAX_ESCROW_FDS: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Region {
    gpa: u64,
    length: u64,
    extents: Vec<Extent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Extent {
    offset: u64,
    length: u64,
    backing_id: String,
    backing_offset: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    regions: Vec<Region>,
    backing_sizes: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    transfer_id: String,
    resource_id: String,
    descriptor_digest: String,
    descriptor: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    transfer_id: String,
    batch_index: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferId {
    transfer_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Acquire {
    pub lease_id: String,
    pub resource_id: String,
    pub access: String,
    #[serde(default)]
    pub offset: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseUpdate {
    pub lease_id: String,
    pub expected_revision: i64,
}

struct Backing {
    file: File,
    device: u64,
    inode: u64,
    length: u64,
}

impl Backing {
    fn identity(&self) -> (u64, u64, u64) {
        (self.device, self.inode, self.length)
    }
}

struct Transfer {
    descriptor: Descriptor,
    incarnation_id: String,
    backings: BTreeMap<String, Backing>,
    next_batch: usize,
}

struct Generation {
    bundle_digest: String,
    backings: BTreeMap<String, Backing>,
}

struct Reexport {
    incarnation_id: String,
    resource_id: String,
    operation_id: String,
    backings: BTreeMap<String, Backing>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum ReexportKey {
    Lease(String),
    Transfer(String),
}

#[derive(Default)]
pub struct Escrow {
    staging: HashMap<String, Transfer>,
    generations: HashMap<String, Generation>,
    reexports: HashMap<ReexportKey, Reexport>,
}

pub struct LeasePacket {
    pub result: Value,
    pub fd_table: Vec<FdEntry>,
    pub fds: Vec<OwnedFd>,
    pub delivered: (String, usize),
}

fn require_id(id: &str) -> Result<()> {
    if !valid_id(id) {
        return Err(Fault::invalid("invalid escrow identifier"));
    }
    Ok(())
}

fn unavailable(message: &str) -> Fault {
    Fault::new("E_RESOURCE_UNAVAILABLE", message)
}

fn transfer_state(record: &TransferRecord, id: &str) -> Value {
    json!({"transfer_id":id, "resource_id":record.resource_id, "state":record.state,
        "descriptor_digest":record.descriptor_digest})
}

impl Descriptor {
    fn validate(&self) -> Result<()> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return Err(Fault::new("E_HOST_IO", "cannot determine host page size"));
        }
        let page = page_size as u64;
        if self.regions.is_empty()
            || self.backing_sizes.is_empty()
            || self.backing_sizes.len() > MAX_BACKINGS
        {
            return Err(Fault::invalid(
                "invalid RAM generation region or backing count",
            ));
        }
        for (id, size) in &self.backing_sizes {
            require_id(id)?;
            if *size == 0 || *size > i64::MAX as u64 || size % page != 0 {
                return Err(Fault::invalid("invalid RAM backing size"));
            }
        }
        let mut region_end = 0;
        let mut count = 0;
        let mut used = HashSet::new();
        for region in &self.regions {
            if region.length == 0
                || region.gpa < region_end
                || region.gpa % page != 0
                || region.length % page != 0
            {
                return Err(Fault::invalid("overlapping or unaligned RAM regions"));
            }
            region_end = region
                .gpa
                .checked_add(region.length)
                .ok_or_else(|| Fault::invalid("RAM region address overflows"))?;
            let mut next = 0;
            for extent in &region.extents {
                count += 1;
                let size = self
                    .backing_sizes
                    .get(&extent.backing_id)
                    .ok_or_else(|| Fault::invalid("RAM extent has an unknown backing"))?;
                if count > MAX_EXTENTS
                    || extent.offset != next
                    || extent.length == 0
                    || extent.length % page != 0
                    || extent.backing_offset % page != 0
                    || extent
                        .backing_offset
                        .checked_add(extent.length)
                        .is_none_or(|end| end > *size)
                {
                    return Err(Fault::invalid(
                        "invalid RAM extent coverage or backing bounds",
                    ));
                }
                next = next
                    .checked_add(extent.length)
                    .ok_or_else(|| Fault::invalid("RAM extent coverage overflows"))?;
                used.insert(extent.backing_id.as_str());
            }
            if next != region.length {
                return Err(Fault::invalid("RAM extents do not cover the region"));
            }
        }
        if used.len() != self.backing_sizes.len() {
            return Err(Fault::invalid("RAM descriptor contains unused backing IDs"));
        }
        Ok(())
    }
}

fn check_backing(descriptor: OwnedFd, wanted_length: u64) -> Result<Backing> {
    let fd = descriptor.as_raw_fd();
    let file = File::from(descriptor);
    let info = file
        .metadata()
        .map_err(|_| Fault::invalid("could not stat RAM backing"))?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    let must_seal = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    let path = format!("/proc/self/fd/{fd}");
    let is_memfd = fs::read_link(&path)
        .ok()
        .is_some_and(|p| p.as_os_str().as_encoded_bytes().starts_with(b"/memfd:"));
    if !is_memfd
        || !info.is_file()
        || info.len() != wanted_length
        || flags < 0
        || flags & libc::O_PATH != 0
        || (flags & libc::O_ACCMODE) == libc::O_WRONLY
        || seals < 0
        || seals & must_seal != must_seal
    {
        return Err(Fault::invalid(
            "RAM backing must be a correctly sized sealed memfd",
        ));
    }
    // Preserve an existing read-only capability from a provider that could have a
    // different UID. Reopening an O_RDWR memfd requires permission on its inode.
    let readonly = if flags & libc::O_ACCMODE == libc::O_RDONLY {
        file
    } else {
        File::open(&path).map_err(|_| Fault::invalid("cannot reopen sealed memfd read-only"))?
    };
    let opened = readonly
        .metadata()
        .map_err(|_| Fault::invalid("cannot verify reopened sealed memfd"))?;
    if opened.dev() != info.dev() || opened.ino() != info.ino() || opened.len() != wanted_length {
        return Err(Fault::invalid("reopened memfd identity changed"));
    }
    Ok(Backing {
        file: readonly,
        device: info.dev(),
        inode: info.ino(),
        length: wanted_length,
    })
}

impl Escrow {
    fn parked_descriptors(&self) -> usize {
        self.staging
            .values()
            .map(|transfer| transfer.backings.len())
            .sum::<usize>()
            + self
                .generations
                .values()
                .map(|generation| generation.backings.len())
                .sum::<usize>()
            + self
                .reexports
                .values()
                .map(|transfer| transfer.backings.len())
                .sum::<usize>()
    }

    pub fn begin(
        &mut self,
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<Value> {
        catalog.ready()?;
        let op = catalog.active_operation(request)?;
        if op.kind != "generation" {
            return Err(Fault::invalid(
                "generation transfer requires a generation operation",
            ));
        }
        let mut input: Begin = request.payload()?;
        require_id(&input.transfer_id)?;
        require_id(&input.resource_id)?;
        input.descriptor.sort_all_objects();
        let actual = format!(
            "sha256:{:x}",
            Sha256::digest(input.descriptor.to_string().as_bytes())
        );
        if !valid_digest(&input.descriptor_digest) || actual != input.descriptor_digest {
            return Err(Fault::invalid("generation descriptor digest mismatch"));
        }
        let descriptor: Descriptor = serde_json::from_value(input.descriptor.clone())
            .map_err(|e| Fault::invalid(e.to_string()))?;
        descriptor.validate()?;
        if let Some(record) = catalog.transfer(&input.transfer_id)? {
            if record.resource_id == input.resource_id
                && record.descriptor_digest == actual
                && record.operation_id == op.operation_id
                && record.incarnation_id == execution.incarnation_id
            {
                return Ok(transfer_state(&record, &input.transfer_id));
            }
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "generation transfer does not match prior intent",
            ));
        }
        if self.staging.len() >= MAX_TRANSFERS {
            return Err(Fault::new(
                "E_RESOURCE_LIMIT",
                "too many staged generation transfers",
            ));
        }
        let record = TransferRecord {
            resource_id: input.resource_id,
            operation_id: op.operation_id,
            incarnation_id: execution.incarnation_id.clone(),
            descriptor_digest: actual,
            state: "staging".into(),
        };
        catalog.begin_transfer(&input.transfer_id, &record, &input.descriptor)?;
        let result = transfer_state(&record, &input.transfer_id);
        self.staging.insert(
            input.transfer_id,
            Transfer {
                descriptor,
                incarnation_id: execution.incarnation_id.clone(),
                backings: BTreeMap::new(),
                next_batch: 0,
            },
        );
        Ok(result)
    }

    fn scoped_transfer(
        &self,
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
        id: &str,
    ) -> Result<TransferRecord> {
        require_id(id)?;
        let op = catalog.active_operation(request)?;
        let record = catalog
            .transfer(id)?
            .ok_or_else(|| Fault::new("E_NOT_FOUND", "generation transfer does not exist"))?;
        if record.operation_id != op.operation_id
            || record.incarnation_id != execution.incarnation_id
        {
            return Err(Fault::new(
                "E_PERMISSION_DENIED",
                "generation transfer belongs to another execution",
            ));
        }
        Ok(record)
    }

    pub fn batch(
        &mut self,
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
        fds: Vec<OwnedFd>,
    ) -> Result<Value> {
        catalog.ready()?;
        let input: Batch = request.payload()?;
        let record = self.scoped_transfer(catalog, request, execution, &input.transfer_id)?;
        if record.state != "staging" {
            return Err(unavailable("generation transfer is not staging"));
        }
        if fds.is_empty()
            || fds.len() != request.fd_table.len()
            || input.batch_index >= MAX_BACKINGS
        {
            return Err(Fault::invalid(
                "generation batch descriptor count or index is invalid",
            ));
        }
        let parked = self.parked_descriptors();
        let transfer = self
            .staging
            .get_mut(&input.transfer_id)
            .ok_or_else(|| unavailable("staged descriptors did not survive broker restart"))?;
        if input.batch_index > transfer.next_batch {
            return Err(Fault::invalid(
                "generation batches must be delivered in order",
            ));
        }
        let mut incoming = BTreeMap::new();
        let mut identities = HashSet::new();
        for (item, fd) in request.fd_table.iter().zip(fds) {
            if item.role != "immutable_backing" || incoming.contains_key(&item.resource_id) {
                return Err(Fault::invalid("unexpected or duplicate generation backing"));
            }
            let length = *transfer
                .descriptor
                .backing_sizes
                .get(&item.resource_id)
                .ok_or_else(|| Fault::invalid("FD table refers to an undeclared backing"))?;
            let backing = check_backing(fd, length)?;
            if !identities.insert((backing.device, backing.inode)) {
                return Err(Fault::invalid("duplicate memfd identity"));
            }
            incoming.insert(item.resource_id.clone(), backing);
        }
        let manifest = json!(incoming
            .iter()
            .map(|(id, backing)| (id, backing.device, backing.inode, backing.length))
            .collect::<Vec<_>>())
        .to_string();
        if let Some(prior) = catalog.batch(&input.transfer_id, input.batch_index)? {
            if manifest == prior {
                return Ok(
                    json!({"transfer_id":input.transfer_id,"next_batch":transfer.next_batch}),
                );
            }
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "generation batch is a different set of descriptors",
            ));
        }
        if parked + incoming.len() > MAX_ESCROW_FDS {
            return Err(Fault::new(
                "E_RESOURCE_LIMIT",
                "worker escrow descriptor budget exhausted",
            ));
        }
        if transfer.backings.iter().any(|(id, fd)| {
            incoming.contains_key(id) || identities.contains(&(fd.device, fd.inode))
        }) {
            return Err(Fault::invalid(
                "generation backing is repeated across batches",
            ));
        }
        catalog.add_batch(&input.transfer_id, input.batch_index, &manifest)?;
        transfer.backings.extend(incoming);
        transfer.next_batch += 1;
        Ok(json!({"transfer_id":input.transfer_id,"next_batch":transfer.next_batch}))
    }

    pub fn commit(
        &mut self,
        catalog: &mut Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<Value> {
        catalog.ready()?;
        let input: TransferId = request.payload()?;
        let record = self.scoped_transfer(catalog, request, execution, &input.transfer_id)?;
        if record.state == "committed" && self.generations.contains_key(&record.resource_id) {
            return Ok(transfer_state(&record, &input.transfer_id));
        }
        if record.state != "staging" {
            return Err(unavailable("generation transfer cannot be committed"));
        }
        let transfer = self
            .staging
            .get(&input.transfer_id)
            .ok_or_else(|| unavailable("staged descriptor data is missing"))?;
        if transfer.backings.len() != transfer.descriptor.backing_sizes.len() {
            return Err(Fault::new(
                "E_INCOMPLETE_TRANSFER",
                "generation has missing backing descriptors",
            ));
        }
        catalog.commit_transfer(&input.transfer_id)?;
        let transfer = self
            .staging
            .remove(&input.transfer_id)
            .expect("validated staged transfer");
        self.generations.insert(
            record.resource_id.clone(),
            Generation {
                bundle_digest: execution.bundle_digest.clone(),
                backings: transfer.backings,
            },
        );
        Ok(transfer_state(
            &TransferRecord {
                state: "committed".into(),
                ..record
            },
            &input.transfer_id,
        ))
    }

    pub fn abort(
        &mut self,
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<Value> {
        let input: TransferId = request.payload()?;
        let record = self.scoped_transfer(catalog, request, execution, &input.transfer_id)?;
        if record.state == "staging" {
            catalog.abort_transfer(&input.transfer_id)?;
            self.staging.remove(&input.transfer_id);
            return Ok(transfer_state(
                &TransferRecord {
                    state: "aborted".into(),
                    ..record
                },
                &input.transfer_id,
            ));
        }
        if matches!(record.state.as_str(), "aborted" | "lost") {
            return Ok(transfer_state(&record, &input.transfer_id));
        }
        Err(unavailable("published generation cannot be aborted"))
    }

    pub fn acquire(
        &self,
        catalog: &mut Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<LeasePacket> {
        catalog.ready()?;
        let operation = catalog.active_operation(request)?;
        if operation.kind != "resource_lease" {
            return Err(Fault::invalid(
                "descriptor leases require a resource_lease operation",
            ));
        }
        let input: Acquire = request.payload()?;
        require_id(&input.lease_id)?;
        require_id(&input.resource_id)?;
        if input.access != "ro" {
            return Err(Fault::new(
                "E_CAPABILITY_UNSUPPORTED",
                "generation leases are read-only",
            ));
        }
        let generation = self
            .generations
            .get(&input.resource_id)
            .filter(|g| g.bundle_digest == execution.bundle_digest)
            .ok_or_else(|| unavailable("sealed descriptors are unavailable for this bundle"))?;
        let total = generation.backings.len();
        if input.offset >= total || input.offset % MAX_FDS != 0 {
            return Err(Fault::invalid("invalid generation descriptor offset"));
        }
        if input.offset > 0 && catalog.lease(&input.lease_id)?.delivered < input.offset {
            return Err(Fault::invalid(
                "generation descriptor batches must be acquired in order",
            ));
        }
        let requested = LeaseRecord {
            lease_id: input.lease_id,
            resource_id: input.resource_id,
            incarnation_id: execution.incarnation_id.clone(),
            operation_id: operation.operation_id,
            state: "pending".into(),
            delivered: 0,
            revision: 1,
        };
        let lease = catalog.acquire_lease(&requested)?;
        let mut fds = Vec::new();
        let mut table = Vec::new();
        for (index, (id, backing)) in generation
            .backings
            .iter()
            .skip(input.offset)
            .take(MAX_FDS)
            .enumerate()
        {
            let fd = backing.file.try_clone().map_err(|_| {
                Fault::new("E_HOST_IO", "cannot duplicate sealed generation backing")
            })?;
            fds.push(OwnedFd::from(fd));
            table.push(FdEntry {
                index,
                resource_id: id.clone(),
                role: "immutable_backing".into(),
            });
        }
        let next = input.offset + fds.len();
        Ok(LeasePacket {
            result: json!({"lease":lease, "offset":input.offset, "next_offset":next, "total":total}),
            fd_table: table,
            fds,
            delivered: (lease.lease_id, next),
        })
    }

    pub fn update_lease(
        &mut self,
        catalog: &mut Catalog,
        request: &Request,
        execution: &Execution,
        release: bool,
    ) -> Result<Value> {
        let (input, lease) = Self::scoped_lease(catalog, request, execution)?;
        if !release && lease.state == "pending" {
            let total = self
                .generations
                .get(&lease.resource_id)
                .map(|g| g.backings.len());
            if total != Some(lease.delivered) {
                return Err(Fault::new(
                    "E_INCOMPLETE_TRANSFER",
                    "generation lease has undelivered backings",
                ));
            }
        }
        let updated = catalog.update_lease(&lease, input.expected_revision, release)?;
        if release {
            self.reexports.remove(&ReexportKey::Lease(input.lease_id));
        }
        Ok(json!(updated))
    }

    pub(crate) fn scoped_lease(
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<(LeaseUpdate, LeaseRecord)> {
        let input: LeaseUpdate = request.payload()?;
        require_id(&input.lease_id)?;
        let lease = catalog.lease(&input.lease_id)?;
        let operation = catalog.matching_operation(request)?;
        if lease.incarnation_id != execution.incarnation_id
            || lease.operation_id != operation.operation_id
        {
            return Err(Fault::new(
                "E_PERMISSION_DENIED",
                "descriptor lease belongs to another execution",
            ));
        }
        Ok((input, lease))
    }

    pub fn reexport(
        &mut self,
        catalog: &mut Catalog,
        request: &Request,
        execution: &Execution,
        fds: Vec<OwnedFd>,
    ) -> Result<Value> {
        let (key, resource_id, operation_id, lease, already_attached) =
            if request.payload.get("transfer_id").is_some() {
                let input: TransferId = request.payload()?;
                let record =
                    self.scoped_transfer(catalog, request, execution, &input.transfer_id)?;
                if !matches!(record.state.as_str(), "missing" | "committed")
                    || !catalog.provider_pinned(&record.resource_id, &record.operation_id)?
                {
                    return Err(unavailable(
                        "generation publisher does not have a recovery pin",
                    ));
                }
                let attached = self.generations.contains_key(&record.resource_id);
                (
                    ReexportKey::Transfer(input.transfer_id),
                    record.resource_id,
                    record.operation_id,
                    None,
                    attached,
                )
            } else {
                let (input, lease) = Self::scoped_lease(catalog, request, execution)?;
                let attached = lease.state == "attached"
                    && input.expected_revision.checked_add(1) == Some(lease.revision)
                    && self.generations.contains_key(&lease.resource_id);
                if !attached
                    && (lease.state != "unknown" || input.expected_revision != lease.revision)
                {
                    return Err(Fault::new(
                        "E_STALE_REVISION",
                        "RAM re-export requires the current unknown lease",
                    ));
                }
                (
                    ReexportKey::Lease(input.lease_id),
                    lease.resource_id.clone(),
                    lease.operation_id.clone(),
                    Some(lease),
                    attached,
                )
            };
        if fds.is_empty() || fds.len() != request.fd_table.len() {
            return Err(Fault::invalid("RAM re-export requires a matching FD table"));
        }
        let identities = catalog.backing_identities(&resource_id)?;
        let mut incoming = BTreeMap::new();
        for (item, fd) in request.fd_table.iter().zip(fds) {
            let wanted = identities
                .get(&item.resource_id)
                .ok_or_else(|| Fault::invalid("RAM re-export backing is unknown"))?;
            let backing = check_backing(fd, wanted.2)?;
            if item.role != "immutable_backing" || backing.identity() != *wanted {
                return Err(Fault::new(
                    "E_FENCE_UNPROVEN",
                    "RAM re-export does not match the original sealed inode",
                ));
            }
            if incoming.insert(item.resource_id.clone(), backing).is_some() {
                return Err(Fault::invalid("duplicate RAM re-export backing"));
            }
        }
        let total = identities.len();
        if already_attached {
            self.reexports.remove(&key);
            return Ok(Self::reexport_receipt(&key, lease.as_ref(), total, total));
        }
        let already_parked = self.reexports.get(&key).map(|transfer| &transfer.backings);
        let additional = incoming
            .keys()
            .filter(|id| already_parked.is_none_or(|backings| !backings.contains_key(*id)))
            .count();
        let parked = self.parked_descriptors();
        if parked + additional > MAX_ESCROW_FDS {
            return Err(Fault::new(
                "E_RESOURCE_LIMIT",
                "worker escrow descriptor budget exhausted",
            ));
        }
        let transfer = self
            .reexports
            .entry(key.clone())
            .or_insert_with(|| Reexport {
                incarnation_id: execution.incarnation_id.clone(),
                resource_id: resource_id.clone(),
                operation_id,
                backings: BTreeMap::new(),
            });
        transfer.backings.extend(incoming);
        let received = transfer.backings.len();
        if received != total {
            return Ok(Self::reexport_receipt(
                &key,
                lease.as_ref(),
                received,
                total,
            ));
        }
        catalog.commit_reexport(&resource_id, lease.as_ref(), total)?;
        let transfer = self.reexports.remove(&key).expect("validated re-export");
        self.generations.entry(resource_id).or_insert(Generation {
            bundle_digest: execution.bundle_digest.clone(),
            backings: transfer.backings,
        });
        let attached = lease
            .map(|prior| catalog.lease(&prior.lease_id))
            .transpose()?;
        Ok(Self::reexport_receipt(
            &key,
            attached.as_ref(),
            received,
            total,
        ))
    }

    fn reexport_receipt(
        key: &ReexportKey,
        lease: Option<&LeaseRecord>,
        received: usize,
        total: usize,
    ) -> Value {
        match key {
            ReexportKey::Lease(_) => json!({"lease":lease, "received":received, "total":total}),
            ReexportKey::Transfer(id) => json!({
                "transfer_id":id, "received":received, "total":total,
                "state":if received == total {"committed"} else {"missing"},
            }),
        }
    }

    pub fn forget_provider(&mut self, operation_id: &str, resource_id: &str) {
        self.reexports.retain(|key, transfer| {
            !matches!(key, ReexportKey::Transfer(_))
                || transfer.operation_id != operation_id
                || transfer.resource_id != resource_id
        });
    }

    pub fn collect(&mut self, id: &str) {
        self.generations.remove(id);
        self.reexports
            .retain(|_, transfer| transfer.resource_id != id);
    }

    pub fn forget_execution(&mut self, incarnation_id: &str) {
        self.staging
            .retain(|_, transfer| transfer.incarnation_id != incarnation_id);
        self.reexports
            .retain(|_, transfer| transfer.incarnation_id != incarnation_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn validates_seals_and_reopens_read_only() {
        let raw = unsafe {
            libc::memfd_create(
                c"resourced-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(unsafe { libc::ftruncate(raw, 4096) }, 0);
        assert!(check_backing(fd.try_clone().unwrap(), 4096).is_err());
        assert_eq!(
            unsafe {
                libc::fcntl(
                    raw,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK,
                )
            },
            0
        );
        assert!(check_backing(fd.try_clone().unwrap(), 8192).is_err());
        let reopened = check_backing(fd, 4096).unwrap().file;
        assert_eq!(
            unsafe { libc::fcntl(reopened.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
    }
}
