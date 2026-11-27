//! Durable launch provenance for guests with an explicitly declared block closure.
use crate::blocks::{BlockObject, BlockSpec};
use crate::catalog::{Catalog, Operation, VolumeHead};
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::native_client::Launch;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub network_id: String,
    pub route_domain_id: String,
    pub cidr: String,
    pub mode: NetworkMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    Native,
    FixedInternal,
}

impl Network {
    pub(crate) fn fixed_route(&self) -> Option<(Ipv4Addr, Ipv4Addr, u8)> {
        (self.mode == NetworkMode::FixedInternal).then_some((
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(10, 0, 2, 2),
            24,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Disk {
    pub attachment_id: String,
    pub device_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub generation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_id: Option<String>,
    pub read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Machine {
    pub name: String,
    pub boot_profile: String,
    pub cpus: u8,
    pub memory_mib: u32,
    pub disks: Vec<Disk>,
    pub init: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    /// Opt into the existing hot-add devices. This execution geometry has no
    /// compatible managed StatePoint reader in the parked runtime.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub live_compute_growth: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_fork_profile: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    #[serde(flatten)]
    pub disk: Disk,
    pub volume_id: String,
    pub head_id: Option<String>,
    pub capacity_bytes: u64,
    #[serde(default)]
    pub reattach: bool,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Plan {
    pub launch: Launch,
    pub machine: Machine,
    pub devices: Vec<Device>,
    pub grant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore: Option<Restore>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Restore {
    pub batch_id: String,
    pub capture_id: String,
    pub anchor: String,
    pub helper_digest: String,
    pub source_pivot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable: Option<crate::managed_state_restore::Durable>,
}
pub(crate) fn key(op: &str, label: &str, slot: usize) -> String {
    let digest = Sha256::digest(format!("{op}\0{label}\0{slot}").as_bytes());
    format!("{label}-{}", &hex::encode(digest)[..32])
}
pub fn machine_id(serve: &str, name: &str) -> String {
    format!("i-{serve}-{:x}", Sha256::digest(name.as_bytes()))
}
pub(crate) fn serve_id(instance: &str, name: &str) -> Result<String> {
    let id = instance
        .strip_prefix("i-")
        .and_then(|s| s.split_once('-'))
        .map(|(s, _)| s)
        .filter(|s| s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| Fault::invalid("missing isolated Serve identity"))?;
    if instance != machine_id(id, name) {
        return Err(Fault::invalid(
            "machine name does not match its execution scope",
        ));
    }
    Ok(id.to_string())
}
impl Machine {
    pub fn kernel_cow(&self) -> bool {
        self.memory_fork_profile.as_deref() == Some(smolvm_runtime_protocol::kernel_cow::PROFILE)
    }

    pub(crate) fn devices(
        &self,
        c: &Catalog,
        op: &str,
        route: &str,
        bundle: &str,
        expected: &crate::ipc::Expected,
    ) -> Result<Vec<Device>> {
        if !valid_id(&self.name)
            || self.cpus == 0
            || self.memory_mib < 64
            || !matches!(self.boot_profile.as_str(), "oci-v1" | "system-debian-v1")
            || self.memory_fork_profile.is_some() && (!self.kernel_cow() || self.live_compute_growth)
            || self.live_compute_growth
                && (!cfg!(target_arch = "x86_64")
                    || self.boot_profile != "system-debian-v1"
                    || self.cpus > 16)
            || !self.init.starts_with('/')
            || self.init.as_bytes().contains(&0)
            || self.init.len() > 1024
            || (self.boot_profile == "system-debian-v1"
                && !matches!(self.init.as_str(), "/sbin/init" | "/lib/systemd/systemd"))
            || self.args.len() > 64
            || self
                .args
                .iter()
                .any(|a| a.len() > 2048 || a.as_bytes().contains(&0))
        {
            return Err(Fault::invalid(
                "invalid managed boot profile, resources or Guest executable",
            ));
        }
        if self.disks.is_empty() || self.disks.len() > 16 || self.disks[0].role != "root" {
            return Err(Fault::invalid(
                "managed boot requires a root disk in the first slot",
            ));
        }
        let original:Option<String>=c.db.query_row(
            "SELECT m.operation_id FROM managed_launches m JOIN operations o USING(operation_id) WHERE o.instance_id=? AND o.phase='COMPLETED' ORDER BY o.expected_execution_epoch DESC LIMIT 1",
            [&expected.instance_id],|r|r.get(0)).optional()?;
        let previous = original
            .map(|id| plan(c, &c.operation(&id)?))
            .transpose()?
            .flatten();
        if previous
            .as_ref()
            .is_some_and(|p| p.machine.network != self.network)
        {
            return Err(Fault::new(
                "E_NETWORK_ATTACHMENT_CONFLICT",
                "managed network changes require a separate attachment operation",
            ));
        }
        let mut disks = self.disks.clone();
        if let Some(previous) = previous.as_ref() {
            if self.boot_profile == "system-debian-v1" && previous.restore.is_some() {
                let declared = &disks[0];
                let captured = previous.machine.disks.first()
                    .ok_or_else(|| Fault::new("E_CATALOG", "restored System has no root declaration"))?;
                if declared.device_id == "root" && declared.device_id == captured.device_id
                    && declared.role == captured.role && declared.read_only == captured.read_only
                    && declared.volume_id.is_none() && captured.volume_id.is_none()
                    && valid_id(&declared.attachment_id)
                {
                    let closure = c.block_closure(&captured.generation_id)?;
                    if declared.generation_id == captured.generation_id || closure.last().is_some_and(
                        |base| base.spec.resource_id == declared.generation_id
                    ) {
                        // System's launch template cites the installed base.
                        // Continue the stopped target's captured root slot and head.
                        disks[0] = captured.clone();
                    }
                }
            }
            let mut intrinsic = Vec::new();
            for (old, device) in previous.machine.disks.iter().zip(&previous.devices) {
                if old.volume_id.is_some() {
                    continue;
                }
                // An independent restore keeps the capture's wire slot IDs.
                // Its product attachment can be edited after a fenced stop.
                let product: bool = c.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM product_volume_attachments
                     WHERE volume_id=? AND instance_id=? AND device_key=?)",
                    params![device.volume_id, expected.instance_id, old.device_id],
                    |row| row.get(0),
                )?;
                if !product {
                    intrinsic.push(old);
                }
            }
            if previous.machine.boot_profile != self.boot_profile
                || intrinsic.into_iter().ne(disks.iter().filter(|d| d.volume_id.is_none()))
            {
                return Err(Fault::new(
                    "E_VOLUME_CONFLICT",
                    "different block attachments require a separate volume operation",
                ));
            }
        }
        let mut attachments = HashSet::new();
        let mut ids = HashSet::new();
        let mut volumes = HashSet::new();
        let mut layers = HashSet::new();
        let mut devices = Vec::new();
        for (i, disk) in disks.iter().enumerate() {
            let prior_root = if i == 0 && self.boot_profile == "system-debian-v1"
                && disk.device_id == "root" && disk.volume_id.is_none()
            {
                previous.as_ref().and_then(|plan| plan.devices.first())
                    .filter(|device| device.disk.device_id == disk.device_id)
            } else {
                None
            };
            let attachment_id = prior_root.map_or(&disk.attachment_id, |device| &device.disk.attachment_id);
            if ![&disk.device_id, &disk.attachment_id]
                .iter()
                .all(|v| valid_id(v))
                || !ids.insert(&disk.device_id)
                || !attachments.insert(attachment_id)
                || !(i == 0
                    || matches!(disk.role.as_str(), "data" | "overlay" | "cache" | "storage"))
            {
                return Err(Fault::invalid("duplicate or invalid managed disk slot"));
            }
            if let Some(volume) = disk.volume_id.as_deref() {
                if !disk.generation_id.is_empty() || !valid_id(volume) || !volumes.insert(volume) {
                    return Err(Fault::invalid("invalid or duplicate reserved volume"));
                }
                let (device, closure) = crate::product_volumes::launch_device(
                    c,
                    route,
                    bundle,
                    &expected.instance_id,
                    expected.execution_epoch + 1,
                    disk,
                    volume,
                )?;
                layers.extend(closure.into_iter().map(|layer| layer.spec.resource_id));
                devices.push(device);
                continue;
            }
            if !valid_id(&disk.generation_id) {
                return Err(Fault::invalid(
                    "managed disk requires a generation or reserved volume",
                ));
            }
            let closure = c.block_closure(&disk.generation_id)?;
            let base = &closure[0].spec;
            if base.mutable() {
                return Err(Fault::new(
                    "E_VOLUME_WRITER_CONFLICT",
                    "source disk generation is writable",
                ));
            }
            for layer in &closure {
                layers.insert(layer.spec.resource_id.clone());
            }
            let old = prior_root.or_else(|| previous.as_ref().and_then(|plan| {
                plan.devices.iter().find(|device| device.disk.attachment_id == disk.attachment_id)
            }));
            let volume_id = old
                .map(|d| d.volume_id.clone())
                .unwrap_or_else(|| key(op, "volume", i));
            let mut active = disk.clone();
            active.attachment_id = attachment_id.clone();
            let (head_id, reattach) = if disk.read_only {
                (None, false)
            } else if old.is_some() {
                let id: String =
                    c.db.query_row(
                        "SELECT head_resource_id FROM volume_heads WHERE volume_id=?",
                        [&volume_id],
                        |r| r.get(0),
                    )
                    .optional()?
                    .ok_or_else(|| {
                        Fault::new(
                            "E_RESOURCE_UNAVAILABLE",
                            "managed volume lost its current head",
                        )
                    })?;
                let current = c.block_closure(&id)?;
                let head = &current[0].spec;
                if !head.mutable()
                    || head.volume_id.as_deref() != Some(&volume_id)
                    || head.capacity_bytes != base.capacity_bytes
                {
                    return Err(Fault::new(
                        "E_VOLUME_CONFLICT",
                        "current managed volume does not match its durable attachment",
                    ));
                }
                active.generation_id = head
                    .backing_id
                    .clone()
                    .ok_or_else(|| Fault::invalid("managed head has no immutable backing"))?;
                for l in current {
                    layers.insert(l.spec.resource_id);
                }
                (Some(id), true)
            } else {
                (Some(key(op, "head", i)), false)
            };
            if let Some(id) = &head_id {
                layers.insert(id.clone());
            }
            devices.push(Device {
                disk: active,
                volume_id,
                head_id,
                capacity_bytes: base.capacity_bytes,
                reattach,
            });
        }
        crate::product_volumes::require_launch_set(c, route, &expected.instance_id, volumes.len())?;
        if layers.len() > crate::ipc::MAX_FDS {
            return Err(Fault::new(
                "E_RESOURCE_LIMIT",
                "disk descriptor set exceeds the packet limit",
            ));
        }
        Ok(devices)
    }
}
impl Plan {
    pub fn network_attachment_id(&self) -> Option<String> {
        self.machine
            .network
            .as_ref()
            .map(|_| key(&self.launch.execution.instance_id, "net", 0))
    }

    pub(crate) fn heads(&self) -> Vec<VolumeHead> {
        self.devices
            .iter()
            .filter_map(|d| {
                d.head_id.as_ref().map(|id| VolumeHead {
                    volume_id: d.volume_id.clone(),
                    head_resource_id: id.clone(),
                })
            })
            .collect()
    }
    pub(crate) fn head_spec(&self, resource: &str) -> Option<BlockSpec> {
        self.devices
            .iter()
            .find(|dev| dev.head_id.as_deref() == Some(resource))
            .map(|dev| BlockSpec {
                resource_id: resource.to_owned(),
                capacity_bytes: dev.capacity_bytes,
                volume_id: Some(dev.volume_id.clone()),
                backing_id: Some(dev.disk.generation_id.clone()),
                content_sha256: None,
                sealed: false,
            })
    }
}
pub(crate) fn plan(c: &Catalog, op: &Operation) -> Result<Option<Plan>> {
    let row:Option<(String,String,String)>=c.db.query_row("SELECT incarnation_id,spec_json,devices_json FROM managed_launches WHERE operation_id=?",
        [&op.operation_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    row.map(|(inc, spec, devices)| {
        Ok(Plan {
            launch: Launch {
                operation_id: op.operation_id.clone(),
                request_digest: op.request_digest.clone(),
                execution: crate::ipc::Expected {
                    instance_id: op.instance_id.clone(),
                    incarnation_id: Some(inc),
                    execution_epoch: op.expected_execution_epoch + 1,
                },
            },
            machine: serde_json::from_str(&spec)
                .map_err(|e| Fault::new("E_CATALOG", e.to_string()))?,
            devices: serde_json::from_str(&devices)
                .map_err(|e| Fault::new("E_CATALOG", e.to_string()))?,
            grant_id: key(&op.operation_id, "grant", 0),
            restore: match crate::managed_state_restore::plan(c, op)? {
                Some(restore) => Some(restore),
                None => crate::managed_fork::restore(c, &op.operation_id)?,
            },
        })
    })
    .transpose()
}
pub(crate) fn submit(c: &mut Catalog, r: &Request, machine: Machine) -> Result<Operation> {
    let (id, _) = r.operation()?;
    let (route, bundle, expected) = r.scope()?;
    if route != "deep" || expected.incarnation_id.is_some() || expected.execution_epoch == i64::MAX
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "managed launch needs an unoccupied epoch",
        ));
    }
    let serve = serve_id(&expected.instance_id, &machine.name)?;
    let existing = match c.operation(id) {
        Ok(existing) => Some(existing),
        Err(e) if e.code == "E_NOT_FOUND" => None,
        Err(e) => return Err(e),
    };
    if let Some(existing) = existing {
        let original = plan(c, &existing)?.ok_or_else(|| {
            Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "operation already belongs to another handler",
            )
        })?;
        if original.machine != machine {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "managed launch profile changed",
            ));
        }
        return c.begin(r, "launch");
    }
    let (epoch, incarnation, active) = crate::catalog::binding(&c.db, route, &expected.instance_id)?;
    if epoch != expected.execution_epoch || incarnation.is_some() {
        return Err(Fault::new("E_STALE_EXECUTION", "managed launch binding changed"));
    }
    if active.is_some() {
        return Err(Fault::new("E_OPERATION_IN_PROGRESS", "this instance already has an active operation"));
    }
    if crate::statepoint_catalog::retained_statepoint(&c.db, route, &expected.instance_id, epoch)?.is_some() {
        return Err(Fault::new("E_STATE_CONFLICT", "a saved execution requires StatePoint restore"));
    }
    let devices = machine.devices(c, id, route, bundle, expected)?;
    if machine.kernel_cow() {
        crate::managed_kernel_cow::require_worker(bundle)?;
    }
    if let Some(network) = &machine.network {
        c.register_private_network(&crate::network_catalog::RegisterNetwork {
            network_id: network.network_id.clone(),
            route_domain_id: network.route_domain_id.clone(),
            cidr: network.cidr.clone(),
        })?;
    }
    let storage = devices
        .iter()
        .filter(|d| !d.disk.read_only)
        .try_fold(0u64, |count, dev| count.checked_add(dev.capacity_bytes))
        .ok_or_else(|| Fault::new("E_RESOURCE_LIMIT", "disk budget overflow"))?;
    let capacity = crate::admission::Capacity {
        vcpus: machine.cpus.into(),
        memory_mib: machine.memory_mib.into(),
        storage_bytes: storage,
    };
    let spec = serde_json::to_string(&machine).map_err(|e| Fault::invalid(e.to_string()))?;
    let encoded = serde_json::to_string(&devices).map_err(|e| Fault::invalid(e.to_string()))?;
    let incarnation = key(id, "vmm", 0);
    c.begin_with(r,"launch",|tx|{
        crate::admission::reserve(tx,id,&expected.instance_id,capacity)?;
        tx.execute("INSERT INTO managed_launches(operation_id,incarnation_id,serve_instance,machine_name,spec_json,devices_json,vcpus,memory_mib)
            VALUES(?,?,?,?,?,?,?,?)",params![
            id,incarnation,serve,machine.name,spec,encoded,machine.cpus,machine.memory_mib])?;
        for device in &devices {
            tx.execute("INSERT OR IGNORE INTO root_refs(owner_kind,owner_id,resource_id,state,revision,created_by_operation)
                VALUES('operation',?,?,'active',1,?)",params![id,device.disk.generation_id,id])?;
            if device.reattach {
                let head = device.head_id.as_ref().ok_or_else(|| Fault::invalid("missing reattached head"))?;
                tx.execute("INSERT OR IGNORE INTO root_refs(owner_kind,owner_id,resource_id,state,revision,created_by_operation)
                    VALUES('operation',?,?,'active',1,?)",params![id,head,id])?;
            }
        }
        Ok(())
    })
}
pub(crate) fn pending(c: &Catalog, serve: &str, bundle: &str) -> Result<Vec<Plan>> {
    if serve.len() != 32 || !serve.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Fault::invalid("invalid Serve identity"));
    }
    let mut q = c.db.prepare(
        "SELECT m.operation_id FROM managed_launches m JOIN operations o USING(operation_id)
        WHERE m.serve_instance=? AND o.bundle_digest=? AND o.phase='NEW' ORDER BY m.rowid",
    )?;
    let ids = q.query_map(params![serve, bundle], |r| r.get::<_, String>(0))?;
    ids.map(|id| {
        plan(c, &c.operation(&id?)?)?.ok_or_else(|| Fault::invalid("missing managed launch"))
    })
    .collect()
}
#[derive(Deserialize, Serialize)]
pub struct DiskSet {
    pub device: Device,
    pub layers: Vec<BlockObject>,
}

/// Persist the exact pre-registration process across Worker and Serve restarts.
pub(crate) fn claim(c: &Catalog, op: &str, boot: &str, pid: i32, start: i64) -> Result<()> {
    let row: Option<(Option<String>, Option<i32>, Option<i64>)> =
        c.db.query_row(
            "SELECT claim_boot,claim_pid,claim_start FROM managed_launches WHERE operation_id=?",
            [op],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((claimed_boot, old_pid, old_start)) = row else {
        return Ok(());
    };
    if claimed_boot.as_deref() == Some(boot) {
        let (old_pid, old_start) = old_pid
            .zip(old_start)
            .ok_or_else(|| Fault::new("E_CATALOG", "incomplete managed process claim"))?;
        if old_pid == pid && old_start == start {
            return Ok(());
        }
        match crate::worker::pid_start(old_pid) {
            Ok(observed) if observed == old_start => {
                return Err(Fault::new(
                    "E_OPERATION_IN_PROGRESS",
                    "previous launch process still exists",
                ))
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(Fault::new("E_FENCE_UNPROVEN", e.to_string()))
            }
            _ => {}
        }
    }
    c.db.execute(
        "UPDATE managed_launches SET claim_boot=?,claim_pid=?,claim_start=? WHERE operation_id=?",
        params![boot, pid, start, op],
    )?;
    Ok(())
}
