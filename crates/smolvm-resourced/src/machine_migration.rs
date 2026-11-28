//! Exact-attempt Worker authority for a cross-Worker transfer.

use crate::catalog::{Catalog, Execution, Operation};
use crate::ipc::{Expected, Fault, FdEntry, PROTOCOL, Request, Result, valid_digest, valid_id};
use crate::managed::{self, Device, Machine};
use crate::migration_product_volumes as products;
use crate::statepoint_catalog::Record;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Endpoint {
    worker_id: String,
    runtime_instance_id: String,
    local_instance_id: String,
    runtime_name: String,
    bundle_id: String,
    bundle_digest: String,
    reader_id: String,
    binding_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    binding_incarnation_id: String,
    generation: i64,
    owner_epoch: i64,
    #[serde(deserialize_with = "deserialize_execution")]
    execution: Expected,
}

fn deserialize_execution<'de, D>(deserializer: D) -> std::result::Result<Expected, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut execution = Expected::deserialize(deserializer)?;
    if execution.incarnation_id.as_deref() == Some("") {
        execution.incarnation_id = None;
    }
    Ok(execution)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ticket {
    id: String,
    machine_id: String,
    mode: String,
    source: Endpoint,
    target: Endpoint,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    request: Step,
    ticket_digest: String,
    bundle_manifest: Value,
    #[serde(default)]
    import: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    ticket: Ticket,
    step: String,
    hold: Option<Value>,
    ready: Option<Value>,
    fence: Option<Value>,
    abort: Option<Value>,
    decision: Option<Decision>,
    network: Option<Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    migration_id: String,
    ticket_digest: String,
    source: Endpoint,
    target: Endpoint,
    source_fence_proof: String,
    target_ready_proof: String,
}

#[derive(Deserialize, Serialize)]
struct HeldDetails {
    generation_ids: Vec<String>,
    capture_operation_id: String,
    machine: Machine,
    devices: Vec<Device>,
    profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    product_volumes: Vec<products::Volume>,
}

fn product_volumes(
    catalog: &Catalog,
    input: &Input,
    devices: &[Device],
) -> Result<Vec<products::Volume>> {
    let source = &input.ticket().source;
    products::source(
        catalog,
        &source.bundle_digest,
        &source.execution.instance_id,
        devices,
    )
}

fn conflict(message: &str) -> Fault {
    Fault::new("E_STATE_CONFLICT", message)
}

fn unsupported(message: &str) -> Fault {
    Fault::new("E_CAPABILITY_UNSUPPORTED", message)
}

pub(crate) fn pending(message: &str) -> Fault {
    Fault::new("E_OPERATION_IN_PROGRESS", message)
}

fn fenced(message: &str) -> Fault {
    Fault::new("E_FENCE_UNPROVEN", message)
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn encode(value: impl Serialize) -> Result<String> {
    serde_json::to_string(&value).map_err(|error| Fault::invalid(error.to_string()))
}

fn native_id(id: &str, side: &str) -> String {
    format!("migration-{side}-{}", &digest(id.as_bytes())[7..39])
}

fn proof_payload(mut receipt: Value) -> Result<String> {
    receipt
        .as_object_mut()
        .ok_or_else(|| Fault::invalid("migration receipt must be an object"))?
        .remove("proof");
    Ok(digest(encode(receipt)?.as_bytes()))
}

impl Input {
    fn ticket(&self) -> &Ticket {
        &self.request.ticket
    }

    fn target(&self) -> bool {
        matches!(
            self.request.step.as_str(),
            "preflight_target"
                | "prepare_target"
                | "activate_target"
                | "abort_target"
                | "finalize_target"
        )
    }

    fn endpoint(&self) -> &Endpoint {
        if self.target() {
            &self.ticket().target
        } else {
            &self.ticket().source
        }
    }

    fn op(&self) -> String {
        native_id(
            &self.ticket().id,
            if self.target() { "target" } else { "source" },
        )
    }

    fn validate(&self, catalog: &Catalog, request: &Request) -> Result<()> {
        let ticket = self.ticket();
        let endpoint = self.endpoint();
        let bundle = &endpoint.bundle_digest;
        if request.route_id.as_deref() != Some("deep")
            || request.bundle_digest.as_deref() != Some(bundle)
            || !matches!(ticket.mode.as_str(), "cold" | "live")
            || !valid_digest(&self.ticket_digest)
            || !valid_id(&ticket.id)
            || !valid_id(&ticket.machine_id)
            || ticket.source.worker_id == ticket.target.worker_id
            || ticket.source.bundle_digest != ticket.target.bundle_digest
            || ticket.source.reader_id != ticket.target.reader_id
            || ticket.source.owner_epoch < 1
            || ticket.source.owner_epoch.checked_add(1) != Some(ticket.target.owner_epoch)
            || ticket.target.execution.incarnation_id.as_deref()
                != Some(&managed::key(&native_id(&ticket.id, "target"), "vmm", 0))
        {
            return Err(Fault::invalid(
                "invalid migration ticket or unmatched Worker route",
            ));
        }
        for side in [&ticket.source, &ticket.target] {
            let local = managed::serve_id(&side.execution.instance_id, &side.runtime_name)?;
            if local != side.local_instance_id
                || side.generation < 1
                || side.execution.execution_epoch < 1
                || side.execution.execution_epoch == i64::MAX
                || side
                    .execution
                    .incarnation_id
                    .as_deref()
                    .is_some_and(|id| !valid_id(id))
            {
                return Err(Fault::invalid("invalid migration Worker execution"));
            }
        }
        let executable = catalog.bundle(bundle)?;
        let executable = executable
            .strip_prefix("sha256:")
            .ok_or_else(|| Fault::invalid("invalid executable measure"))?;
        let manifest = smolvm_runtime_protocol::handshake(self.bundle_manifest.clone(), executable)
            .map_err(|error| Fault::new("E_BUNDLE_UNAVAILABLE", error.to_string()))?;
        if manifest.bundle_digest != *bundle || manifest.state_reader_id != endpoint.reader_id {
            return Err(Fault::new(
                "E_BUNDLE_UNAVAILABLE",
                "migration requires the exact original Bundle and reader",
            ));
        }
        if self
            .request
            .network
            .as_ref()
            .is_some_and(|network| !network.is_null())
        {
            return Err(unsupported(
                "managed cross-Worker network activation is unavailable for this transfer",
            ));
        }
        Ok(())
    }

    fn native(&self, expected: Expected, payload: Value) -> Request {
        Request {
            protocol: PROTOCOL.into(),
            request_id: "machine-migration".into(),
            method: "MachineMigrationStep".into(),
            route_id: Some("deep".into()),
            bundle_digest: Some(self.endpoint().bundle_digest.clone()),
            operation_id: Some(self.op()),
            request_digest: Some(self.ticket_digest.clone()),
            expected: Some(expected),
            fd_table: Vec::new(),
            payload,
        }
    }

    fn check(&self, received: Option<&Value>, step: &str, endpoint: &Endpoint) -> Result<String> {
        let receipt = received.ok_or_else(|| fenced("missing prerequisite migration receipt"))?;
        let actual = receipt["proof"]
            .as_str()
            .filter(|value| valid_digest(value))
            .ok_or_else(|| fenced("invalid migration proof"))?;
        if receipt["migration_id"] != self.ticket().id
            || receipt["step"] != step
            || receipt["ticket_digest"] != self.ticket_digest
            || receipt["execution"] != execution_json(&endpoint.execution)
            || proof_payload(receipt.clone())? != actual
        {
            return Err(fenced(
                "migration receipt belongs to another attempt or execution",
            ));
        }
        Ok(actual.into())
    }

    fn decision(&self) -> Result<String> {
        let decision = self
            .request
            .decision
            .as_ref()
            .ok_or_else(|| fenced("missing committed owner decision"))?;
        let source = self.check(
            self.request.fence.as_ref(),
            "fence_source",
            &self.ticket().source,
        )?;
        let target = self.check(
            self.request.ready.as_ref(),
            "prepare_target",
            &self.ticket().target,
        )?;
        if decision.migration_id != self.ticket().id
            || decision.ticket_digest != self.ticket_digest
            || decision.source != self.ticket().source
            || decision.target != self.ticket().target
            || decision.source_fence_proof != source
            || decision.target_ready_proof != target
        {
            return Err(fenced(
                "committed owner decision differs from the exact fence and ready receipts",
            ));
        }
        encode(decision)
    }
}

fn execution_json(expected: &Expected) -> Value {
    json!({"instance_id":expected.instance_id, "execution_epoch":expected.execution_epoch,
        "incarnation_id":expected.incarnation_id.as_deref().unwrap_or("")})
}

pub(crate) fn requires_owner(catalog: &Catalog, operation: &str) -> Result<bool> {
    Ok(catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='target'
         AND native_operation_id=? AND decision_json IS NULL)",
        [operation],
        |row| row.get(0),
    )?)
}

pub(crate) fn guard_operation(
    db: &rusqlite::Connection,
    route: &str,
    instance: &str,
    operation: &str,
) -> Result<()> {
    let held = route == "deep" && db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE instance_id=? AND native_operation_id<>?
         AND state NOT IN ('aborted','resumed') AND (side='source' OR state<>'complete'))", params![instance, operation], |row| row.get::<_, bool>(0))?;
    if held {
        return Err(fenced("machine is reserved for a cross-Worker migration"));
    }
    Ok(())
}

fn state(catalog: &Catalog, input: &Input) -> Result<Option<(String, Option<String>)>> {
    let row: Option<(String, String, String, String, Option<String>)> = catalog.db.query_row(
        "SELECT ticket_digest,ticket_json,side,state,decision_json FROM machine_migrations WHERE migration_id=?",
        [&input.ticket().id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).optional()?;
    row.map(|(hash, ticket, side, state, decision)| {
        if hash != input.ticket_digest
            || ticket != encode(input.ticket())?
            || side != if input.target() { "target" } else { "source" }
        {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "migration ID scope changed",
            ));
        }
        Ok((state, decision))
    })
    .transpose()
}

fn reserve(catalog: &Catalog, input: &Input) -> Result<()> {
    catalog.ready()?;
    catalog.db.execute(
        "INSERT INTO machine_migrations (migration_id,ticket_digest,ticket_json,side,instance_id,native_operation_id,state)
         VALUES(?,?,?,?,?,?,'reserved') ON CONFLICT(migration_id) DO NOTHING",
        params![input.ticket().id,input.ticket_digest,encode(input.ticket())?,
            if input.target() {"target"} else {"source"},input.endpoint().execution.instance_id,input.op()])?;
    state(catalog, input)?;
    Ok(())
}

fn previous(catalog: &Catalog, input: &Input, step: &str) -> Result<Option<Value>> {
    let raw: Option<String> = catalog
        .db
        .query_row(
            "SELECT result FROM machine_migration_receipts WHERE migration_id=? AND step=?",
            params![input.ticket().id, step],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|raw| {
        serde_json::from_str(&raw).map_err(|error| Fault::new("E_CATALOG", error.to_string()))
    })
    .transpose()
}

fn make_receipt(input: &Input, mut result: Value) -> Result<Value> {
    result
        .as_object_mut()
        .unwrap()
        .retain(|_, value| !value.is_null());
    result["migration_id"] = json!(input.ticket().id);
    result["ticket_digest"] = json!(input.ticket_digest);
    result["step"] = json!(input.request.step);
    result["execution"] = execution_json(&input.endpoint().execution);
    result["proof"] = json!(proof_payload(result.clone())?);
    Ok(result)
}

fn remember(catalog: &mut Catalog, input: &Input, phase: &str, result: Value) -> Result<Value> {
    let result = make_receipt(input, result)?;
    let tx = catalog.db.transaction()?;
    tx.execute(
        "UPDATE machine_migrations SET state=? WHERE migration_id=?",
        params![phase, input.ticket().id],
    )?;
    tx.execute(
        "INSERT INTO machine_migration_receipts VALUES(?,?,?)",
        params![input.ticket().id, input.request.step, encode(&result)?],
    )?;
    tx.commit()?;
    Ok(result)
}

fn cpu_clock_profile() -> Result<String> {
    if !cfg!(target_arch = "x86_64") {
        return Err(unsupported(
            "held migration currently requires Linux x86-64 KVM",
        ));
    }
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|_| unsupported("KVM is unavailable"))?;
    use std::os::fd::AsRawFd;
    // KVM API version and KVM_CAP_TSC_CONTROL from linux/kvm.h.
    if unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae00) } != 12
        || unsafe { libc::ioctl(kvm.as_raw_fd(), 0xae03, 60) } <= 0
    {
        return Err(unsupported(
            "KVM cannot restore the captured guest TSC frequency",
        ));
    }
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo")
        .map_err(|_| unsupported("CPU fingerprint is unavailable"))?;
    let signatures = cpuinfo
        .split("\n\n")
        .filter_map(|record| {
            let data = record
                .lines()
                .filter_map(|line| line.split_once(':'))
                .filter(|(key, _)| {
                    matches!(
                        key.trim(),
                        "vendor_id" | "cpu family" | "model" | "stepping" | "flags"
                    )
                })
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        key.trim(),
                        value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
                    )
                })
                .collect::<Vec<_>>();
            (!data.is_empty()).then(|| data.join("\n"))
        })
        .collect::<BTreeSet<_>>();
    let Some(signature) = signatures.iter().next().filter(|_| signatures.len() == 1) else {
        return Err(unsupported(
            "held migration requires a uniform, measurable CPU fingerprint",
        ));
    };
    if !signature
        .lines()
        .any(|line| line == "vendor_id=GenuineIntel" || line == "vendor_id=AuthenticAMD")
        || !signature
            .split_ascii_whitespace()
            .any(|feature| feature == "constant_tsc")
    {
        return Err(unsupported(
            "held migration requires Intel or AMD KVM with a constant TSC",
        ));
    }
    Ok(digest(signature.as_bytes()))
}

fn source_plan(catalog: &Catalog, input: &Input) -> Result<(Execution, managed::Plan)> {
    let ep = &input.ticket().source;
    let execution = match ep.execution.incarnation_id.as_deref() {
        Some(incarnation) => {
            let execution = catalog.execution(incarnation)?;
            if !execution.matches("deep", &ep.bundle_digest, &ep.execution) {
                return Err(fenced("source execution differs from the migration ticket"));
            }
            execution
        }
        None if input.ticket().mode == "cold" => {
            let (epoch, incarnation, _) =
                crate::catalog::binding(&catalog.db, "deep", &ep.execution.instance_id)?;
            if epoch != ep.execution.execution_epoch
                || incarnation.is_some()
                || !valid_id(&ep.binding_incarnation_id)
            {
                return Err(fenced(
                    "stopped source slot differs from the migration ticket",
                ));
            }
            let execution = catalog.execution(&ep.binding_incarnation_id)?;
            if execution.instance_id != ep.execution.instance_id
                || execution.route_id != "deep"
                || execution.bundle_digest != ep.bundle_digest
                || execution.execution_epoch > epoch
                || execution.phase != "exited"
            {
                return Err(fenced(
                    "stopped source lacks a confirmed historical execution",
                ));
            }
            execution
        }
        None => return Err(unsupported("a held migration requires a live source")),
    };
    let op = catalog.operation(&execution.last_operation_id)?;
    let plan = managed::plan(catalog, &op)?
        .filter(|_| op.phase == "COMPLETED")
        .ok_or_else(|| unsupported("source has no complete managed disk provenance"))?;
    if plan.machine.name != ep.runtime_name || plan.machine.network.is_some() {
        return Err(unsupported(
            "source network topology has no reversible cross-Worker fence",
        ));
    }
    Ok((execution, plan))
}

fn source_point(catalog: &Catalog, input: &Input) -> Result<Record> {
    catalog.require_statepoint(&managed::key(&input.op(), "point", 0))
}

fn hold_source(catalog: &mut Catalog, objects: &File, boot: &str, input: &Input) -> Result<Value> {
    let (execution, plan) = source_plan(catalog, input)?;
    if input.endpoint().execution.incarnation_id.is_none() {
        return hold_stopped_source(catalog, objects, input, plan);
    }
    if execution.phase != "registered" || execution.host_boot_id != boot {
        return Err(fenced(
            "source execution is not registered on this Worker boot",
        ));
    }
    let profile = if input.ticket().mode == "live" {
        Some(cpu_clock_profile()?)
    } else {
        None
    };
    let selected = product_volumes(catalog, input, &plan.devices)?;
    reserve(catalog, input)?;
    products::reserve_source(catalog, &input.ticket().id, &selected)?;
    let request = input.native(input.endpoint().execution.clone(), json!({}));
    let capture = managed::key(&input.op(), "point", 0);
    let op = crate::managed_fork::submit(
        catalog,
        boot,
        &request,
        "hibernate",
        crate::managed_fork::Input {
            children: Vec::new(),
            capture_id: Some(capture.clone()),
            mode: None,
            admission: None,
            memory_fork_backend: None,
        },
    )?;
    if op.phase == "ABORTED" {
        return Err(fenced("source could not reach the held capture boundary"));
    }
    let stage: String = catalog.db.query_row(
        "SELECT stage FROM managed_fork_batches WHERE operation_id=?",
        [&op.operation_id],
        |row| row.get(0),
    )?;
    if stage != "durable_hold" {
        return Err(pending(
            "source is still entering the held capture boundary",
        ));
    }
    let record = source_point(catalog, input)?;
    if record.phase != "durable" {
        return Err(pending("source StatePoint bytes are being exported"));
    }
    let endpoint =
        crate::native_control::Endpoint::load(&catalog.db, &execution.incarnation_id, boot)?;
    let reply = endpoint.command(&format!(
        "CAPTURE_QUERY {} {}",
        record.export.session, record.export.hold_token
    ))?;
    let capture_state: Value =
        serde_json::from_str(&reply).map_err(|_| fenced("invalid source hold receipt"))?;
    if capture_state["source_disposition"] != "HELD" || capture_state["phase"] != "prepared" {
        return Err(fenced("source no longer owns the final held capture"));
    }
    let mut devices = Vec::new();
    for (slot, device) in record
        .point
        .devices
        .iter()
        .filter_map(|d| d.block())
        .enumerate()
    {
        let generation = device
            .writable_head_id
            .as_ref()
            .unwrap_or(&device.generation_id);
        let disk = plan
            .machine
            .disks
            .get(slot)
            .ok_or_else(|| fenced("captured disk slot is absent from managed launch"))?;
        if disk.attachment_id != device.attachment_id
            || disk.device_id != device.device_id
            || disk.role != device.role
        {
            return Err(fenced("captured disk differs from managed launch"));
        }
        devices.push(Device {
            disk: managed::Disk {
                generation_id: generation.clone(),
                volume_id: None,
                ..disk.clone()
            },
            volume_id: device.volume_id.clone(),
            head_id: None,
            capacity_bytes: device.capacity_bytes,
            reattach: false,
        });
    }
    if devices.len() != plan.machine.disks.len() {
        return Err(fenced(
            "captured writable device set differs from managed launch",
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Fault::new("E_HOST_IO", error.to_string()))?
        .as_millis() as u64;
    let product_volumes = product_volumes(catalog, input, &devices)?;
    products::check_held(catalog, &input.ticket().id, &product_volumes)?;
    let details = HeldDetails {
        generation_ids: record.point.disk_generations,
        capture_operation_id: op.operation_id,
        machine: plan.machine,
        devices,
        profile,
        product_volumes,
    };
    remember(
        catalog,
        input,
        "held",
        json!({"capture_id":capture,"manifest_digest":record.manifest_digest,
        "paused_at_unix_ms":now,"details":details}),
    )
}

fn inspect(catalog: &mut Catalog, input: &Input, boot: &str) -> Result<Value> {
    let (execution, plan) = source_plan(catalog, input)?;
    if input.endpoint().execution.incarnation_id.is_some()
        && (execution.phase != "registered" || execution.host_boot_id != boot)
    {
        return Err(fenced("source execution is unavailable"));
    }
    let profile = if input.ticket().mode == "live" {
        if plan.machine.live_compute_growth {
            return Err(unsupported(
                "the StatePoint reader cannot restore live compute growth",
            ));
        }
        Some(cpu_clock_profile()?)
    } else {
        None
    };
    let product_volumes = product_volumes(catalog, input, &plan.devices)?;
    make_receipt(
        input,
        json!({"details":{"profile":profile,"product_volumes":product_volumes}}),
    )
}

fn preflight(catalog: &mut Catalog, input: &Input) -> Result<Value> {
    let endpoint = input.endpoint();
    let (epoch, incarnation, active) =
        crate::catalog::binding(&catalog.db, "deep", &endpoint.execution.instance_id)?;
    if epoch + 1 != endpoint.execution.execution_epoch || incarnation.is_some() || active.is_some()
    {
        return Err(fenced(
            "target slot is not empty at the admitted execution epoch",
        ));
    }
    if input.ticket().mode == "live" {
        let target = cpu_clock_profile()?;
        if let Some(source) = input
            .request
            .hold
            .as_ref()
            .filter(|receipt| receipt["step"] == "inspect_source")
        {
            input.check(Some(source), "inspect_source", &input.ticket().source)?;
            if source["details"]["profile"] != target {
                return Err(unsupported(
                    "held migration requires identical CPU fingerprints and KVM TSC support",
                ));
            }
        }
    }
    make_receipt(input, json!({}))
}

fn import_spec(input: &Input) -> Result<Value> {
    let mut spec = input.import.clone().ok_or_else(|| {
        Fault::new(
            "E_MIGRATION_TRANSFER_REQUIRED",
            "verified transfer has not arrived",
        )
    })?;
    if spec["import_id"] != input.ticket().id
        || spec["state_reader_id"] != input.endpoint().reader_id
        || !spec["worker_manifest_digest"]
            .as_str()
            .is_some_and(valid_digest)
        || !spec["closure_digest"].as_str().is_some_and(valid_digest)
    {
        return Err(fenced(
            "transferred closure differs from the migration ticket",
        ));
    }
    spec["bundle_manifest"] = input.bundle_manifest.clone();
    Ok(spec)
}

fn prepare_target(
    catalog: &mut Catalog,
    objects: &File,
    points: &Path,
    input: &Input,
    wire: &Request,
    descriptors: Vec<OwnedFd>,
) -> Result<Value> {
    input.check(
        input.request.hold.as_ref(),
        "hold_source",
        &input.ticket().source,
    )?;
    let hold = input.request.hold.as_ref().unwrap();
    let details: HeldDetails = serde_json::from_value(hold["details"].clone())
        .map_err(|error| Fault::invalid(error.to_string()))?;
    if details.generation_ids.is_empty()
        || details.machine.network.is_some()
        || details.devices.is_empty()
    {
        return Err(fenced("source hold has no eligible immutable disk closure"));
    }
    let live = input.ticket().mode == "live";
    if live && details.profile.as_deref() != Some(cpu_clock_profile()?.as_str()) {
        return Err(unsupported("held migration CPU or clock profile changed"));
    }
    reserve(catalog, input)?;
    let endpoint = input.endpoint();
    let op = input.op();
    let saved_import: Option<String> = catalog.db.query_row(
        "SELECT import_json FROM machine_migrations WHERE migration_id=?",
        [&input.ticket().id],
        |row| row.get(0),
    )?;
    if let Some(saved) = saved_import {
        if !descriptors.is_empty() && saved != encode(import_spec(input)?)? {
            return Err(fenced(
                "target import receipt differs from the original transferred closure",
            ));
        }
    } else {
        let spec = import_spec(input)?;
        if spec["generation_ids"] != json!(details.generation_ids) || descriptors.len() != 1 {
            return Err(fenced(
                "target import differs from the exact selected generations",
            ));
        }
        let mut request = input.native(endpoint.execution.clone(), spec.clone());
        request.fd_table = wire
            .fd_table
            .iter()
            .map(|fd| FdEntry {
                index: fd.index,
                resource_id: fd.resource_id.clone(),
                role: fd.role.clone(),
            })
            .collect();
        if live {
            let selection = crate::disk_closure_import::MigrationCapture {
                points,
                capture_id: hold["capture_id"]
                    .as_str()
                    .ok_or_else(|| Fault::invalid("missing capture ID"))?,
                operation_id: &details.capture_operation_id,
                manifest_digest: hold["manifest_digest"]
                    .as_str()
                    .ok_or_else(|| Fault::invalid("missing capture digest"))?,
                source: &input.ticket().source.execution,
            };
            crate::disk_closure_import::import_migration(
                catalog,
                objects,
                &request,
                descriptors,
                selection,
            )?;
        } else {
            crate::disk_closure_import::import(catalog, objects, &request, descriptors)?;
        }
        catalog.db.execute(
            "UPDATE machine_migrations SET import_json=? WHERE migration_id=?",
            params![encode(&spec)?, input.ticket().id],
        )?;
    }

    let expected = Expected {
        instance_id: endpoint.execution.instance_id.clone(),
        incarnation_id: None,
        execution_epoch: endpoint.execution.execution_epoch - 1,
    };
    let native = input.native(expected, json!({}));
    products::install_target(
        catalog,
        &native,
        &input.ticket().id,
        &details.product_volumes,
        &details.devices,
    )?;
    if live {
        crate::managed_state_restore::submit_migration(
            catalog,
            &native,
            crate::managed_state_restore::Input {
                name: endpoint.runtime_name.clone(),
                capture_id: hold["capture_id"].as_str().unwrap().into(),
                mode: crate::managed_state_restore::RestoreMode::CloneConflicts,
                network_id: None,
            },
        )?;
        let activation = catalog.activation(&op).map_err(|error| {
            if error.code == "E_NOT_FOUND" {
                pending("restored target has not reached its held activation gate")
            } else {
                error
            }
        })?;
        if activation.phase == "failed_held" {
            return Err(fenced("target failed while held"));
        }
        if activation.phase != "identity_ready" {
            return Err(pending(
                "target Guest identity is still being prepared while held",
            ));
        }
    } else {
        queue_cold(catalog, &native, details, &endpoint.runtime_name)?;
    }
    let product_volumes = products::observations(catalog, &native, &input.ticket().id)?;
    remember(
        catalog,
        input,
        "prepared",
        json!({"details":{"native_operation_id":op,
        "request_digest":input.ticket_digest, "held_live":live,"product_volumes":product_volumes},
        "capture_id":hold["capture_id"], "manifest_digest":hold["manifest_digest"]}),
    )
}

fn queue_cold(
    catalog: &mut Catalog,
    native: &Request,
    details: HeldDetails,
    name: &str,
) -> Result<Operation> {
    let (id, _) = native.operation()?;
    let (_, _, expected) = native.scope()?;
    let namespace = managed::serve_id(&expected.instance_id, name)?;
    let mut machine = details.machine;
    machine.name = name.into();
    if machine.disks.len() != details.devices.len() {
        return Err(fenced("target disk set differs from the held source"));
    }
    let mut devices = details.devices;
    let mut selected = BTreeSet::new();
    let mut storage_bytes = 0u64;
    for (index, (disk, device)) in machine.disks.iter_mut().zip(&mut devices).enumerate() {
        if disk.attachment_id != device.disk.attachment_id
            || disk.device_id != device.disk.device_id
            || disk.read_only != device.disk.read_only
            || !valid_id(&device.volume_id)
            || !details.generation_ids.contains(&device.disk.generation_id)
            || !selected.insert(device.volume_id.clone())
        {
            return Err(fenced(
                "target disk or logical volume identity differs from the source",
            ));
        }
        let closure = catalog.block_closure(&device.disk.generation_id)?;
        if closure[0].spec.mutable() || closure[0].spec.capacity_bytes != device.capacity_bytes {
            return Err(fenced(
                "target disk generation does not match the source capacity",
            ));
        }
        if !disk.read_only {
            storage_bytes = storage_bytes
                .checked_add(device.capacity_bytes)
                .ok_or_else(|| Fault::invalid("migrated storage capacity overflow"))?;
            device.head_id = Some(managed::key(id, "head", index));
        }
        *disk = device.disk.clone();
    }
    let capacity = crate::admission::Capacity {
        vcpus: machine.cpus.into(),
        memory_mib: machine.memory_mib.into(),
        storage_bytes,
    };
    let incarnation = managed::key(id, "vmm", 0);
    let spec = encode(&machine)?;
    let encoded = encode(&devices)?;
    catalog.begin_with(native, "launch", |tx| {
        crate::admission::reserve(tx,id,&expected.instance_id,capacity)?;
        for device in &devices {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM volume_heads WHERE volume_id=?)", [&device.volume_id], |row| row.get(0))?;
            if exists {
                return Err(fenced("target already has a head for a migrated logical volume"));
            }
        }
        tx.execute("INSERT INTO managed_launches(operation_id,incarnation_id,serve_instance,machine_name,spec_json,devices_json,vcpus,memory_mib)
            VALUES(?,?,?,?,?,?,?,?)",params![id,incarnation,namespace,machine.name,spec,encoded,machine.cpus,machine.memory_mib])?;
        for device in &devices {
            tx.execute("INSERT OR IGNORE INTO root_refs(owner_kind,owner_id,resource_id,state,revision,created_by_operation)
                VALUES('operation',?,?,'active',1,?)",params![id,device.disk.generation_id,id])?;
        }
        Ok(())
    })
}

fn source_fence(catalog: &mut Catalog, input: &Input, boot: &str) -> Result<Value> {
    let ready = input.check(
        input.request.ready.as_ref(),
        "prepare_target",
        &input.ticket().target,
    )?;
    let hold =
        previous(catalog, input, "hold_source")?.ok_or_else(|| fenced("source hold is absent"))?;
    if input.request.ready.as_ref().unwrap()["manifest_digest"] != hold["manifest_digest"] {
        return Err(fenced(
            "target readiness does not match the captured manifest",
        ));
    }
    if input.endpoint().execution.incarnation_id.is_none() {
        let (epoch, incarnation, active) =
            crate::catalog::binding(&catalog.db, "deep", &input.endpoint().execution.instance_id)?;
        if epoch != input.endpoint().execution.execution_epoch
            || incarnation.is_some()
            || active.as_deref() != Some(&input.op())
        {
            return Err(fenced("stopped writer slot or migration operation changed"));
        }
        return remember(
            catalog,
            input,
            "fenced",
            json!({
            "manifest_digest":hold["manifest_digest"],"details":{"ready_proof":ready,"writer_gate":"confirmed_stopped"}}),
        );
    }
    let record = source_point(catalog, input)?;
    if record.phase != "durable" {
        return Err(fenced(
            "source StatePoint no longer owns the exact held writer pivot",
        ));
    }
    let endpoint =
        crate::native_control::Endpoint::load(&catalog.db, &record.point.incarnation_id, boot)?;
    let scope = format!("{} {}", record.export.session, record.export.hold_token);
    endpoint.command(&format!("CAPTURE_STOP_RESERVE {scope}"))?;
    let status = endpoint.command(&format!("CAPTURE_QUERY {scope}"))?;
    let state: Value =
        serde_json::from_str(&status).map_err(|_| fenced("invalid writer fence observation"))?;
    if state["stop_reserved"] != true
        || state["phase"] != "prepared"
        || state["source_disposition"] != "HELD"
    {
        return Err(fenced(
            "VMM did not corroborate the non-expiring held writer fence",
        ));
    }
    remember(
        catalog,
        input,
        "fenced",
        json!({"capture_id":record.export.capture_id,
        "manifest_digest":record.manifest_digest, "details":{"ready_proof": ready,
        "writer_gate":"capture_stop_reserved","relay_gate":"parked"}}),
    )
}

fn require_local(
    catalog: &Catalog,
    input: &Input,
    step: &str,
    supplied: Option<&Value>,
) -> Result<()> {
    let expected = input.check(supplied, step, input.endpoint())?;
    if previous(catalog, input, step)?
        .as_ref()
        .and_then(|receipt| receipt["proof"].as_str())
        != Some(expected.as_str())
    {
        return Err(fenced(
            "decision does not cite this Worker’s durable receipt",
        ));
    }
    Ok(())
}

fn record_decision(catalog: &Catalog, input: &Input, prior: Option<&str>) -> Result<()> {
    let decision = input.decision()?;
    if prior.is_some_and(|prior| prior != decision) {
        return Err(fenced(
            "owner decision changed after the Worker accepted it",
        ));
    }
    catalog.db.execute("UPDATE machine_migrations SET decision_json=? WHERE migration_id=? AND decision_json IS NULL",
        params![decision,input.ticket().id])?;
    Ok(())
}

fn release_import(catalog: &mut Catalog, objects: &File, input: &Input) -> Result<()> {
    let present: Option<String> = catalog.db.query_row(
        "SELECT import_json FROM machine_migrations WHERE migration_id=?",
        [&input.ticket().id],
        |row| row.get(0),
    )?;
    if let Some(raw) = present {
        let spec: Value =
            serde_json::from_str(&raw).map_err(|error| Fault::invalid(error.to_string()))?;
        let request = input.native(input.endpoint().execution.clone(), json!({"import_id":spec["import_id"],
            "closure_digest":spec["closure_digest"],"worker_manifest_digest":spec["worker_manifest_digest"]}));
        crate::disk_closure_import::release(catalog, objects, &request)?;
    }
    Ok(())
}

impl crate::worker::Worker {
    pub(crate) fn machine_migration(
        &mut self,
        request: &Request,
        descriptors: Vec<OwnedFd>,
    ) -> Result<Value> {
        let input: Input = request.payload()?;
        input.validate(&self.catalog, request)?;
        let step = input.request.step.as_str();
        if step != "prepare_target" && !descriptors.is_empty() {
            return Err(Fault::invalid("unexpected migration transfer descriptor"));
        }
        if state(&self.catalog, &input)?.is_none() {
            if !matches!(
                step,
                "inspect_source"
                    | "preflight_target"
                    | "hold_source"
                    | "prepare_target"
                    | "abort_target"
                    | "resume_source"
            ) {
                return Err(fenced("migration side was not admitted"));
            }
            if step == "abort_target" || step == "resume_source" {
                if step == "resume_source" {
                    input.check(
                        input.request.abort.as_ref(),
                        "abort_target",
                        &input.ticket().target,
                    )?;
                    source_plan(&self.catalog, &input)?;
                }
                reserve(&self.catalog, &input)?;
            }
        }
        if let Some(result) = previous(&self.catalog, &input, step)? {
            let phase = state(&self.catalog, &input)?.unwrap().0;
            if (phase == "aborted" && step != "abort_target")
                || (phase == "resumed" && step != "resume_source")
                || (step == "hold_source" && phase != "held")
            {
                return Err(fenced("migration step no longer has the claimed authority"));
            }
            return Ok(result);
        }
        let (phase, decision) =
            state(&self.catalog, &input)?.unwrap_or_else(|| ("new".into(), None));
        match (step, phase.as_str()) {
            ("inspect_source", "new") => inspect(&mut self.catalog, &input, &self.boot),
            ("preflight_target", "new") => preflight(&mut self.catalog, &input),
            ("hold_source", "new" | "reserved") => {
                hold_source(&mut self.catalog, &self.objects, &self.boot, &input)
            }
            ("prepare_target", "new" | "reserved") => prepare_target(
                &mut self.catalog,
                &self.objects,
                self.statepoints.directory(),
                &input,
                request,
                descriptors,
            ),
            ("fence_source", "held") => source_fence(&mut self.catalog, &input, &self.boot),
            ("activate_target", "prepared") => {
                require_local(
                    &self.catalog,
                    &input,
                    "prepare_target",
                    input.request.ready.as_ref(),
                )?;
                record_decision(&self.catalog, &input, decision.as_deref())?;
                let op = self.catalog.operation(&input.op())?;
                if op.phase == "ABORTED" {
                    return Err(fenced("committed target launch failed"));
                }
                if op.phase != "COMPLETED" {
                    return Err(pending("committed target activation is in progress"));
                }
                let native = input.native(input.endpoint().execution.clone(), json!({}));
                let execution = self.scoped_execution(&native)?;
                self.verify_live_execution(&execution)?;
                let product_volumes =
                    products::observations(&self.catalog, &native, &input.ticket().id)?;
                remember(
                    &mut self.catalog,
                    &input,
                    "active",
                    json!({"details":{"product_volumes":product_volumes}}),
                )
            }
            ("abort_target", "reserved" | "prepared" | "aborting") if decision.is_none() => {
                self.catalog.db.execute(
                    "UPDATE machine_migrations SET state='aborting' WHERE migration_id=?",
                    [&input.ticket().id],
                )?;
                match self.catalog.operation(&input.op()) {
                    Ok(operation) if operation.phase == "NEW" => {
                        let execution = match self.catalog.execution(
                            input
                                .endpoint()
                                .execution
                                .incarnation_id
                                .as_deref()
                                .unwrap(),
                        ) {
                            Ok(execution) => Some(execution),
                            Err(error) if error.code == "E_NOT_FOUND" => None,
                            Err(error) => return Err(error),
                        };
                        let epoch = if let Some(execution) = execution {
                            if !self.stop_vmm(&execution)? {
                                return Err(pending("waiting for held target writers to exit"));
                            }
                            self.finalize_scoped_execution(execution)?;
                            input.endpoint().execution.execution_epoch
                        } else {
                            input.endpoint().execution.execution_epoch - 1
                        };
                        let native = input.native(
                            Expected {
                                instance_id: input.endpoint().execution.instance_id.clone(),
                                incarnation_id: None,
                                execution_epoch: epoch,
                            },
                            json!({}),
                        );
                        self.catalog.finish(&native, true, operation.revision)?;
                    }
                    Ok(operation) if operation.phase != "ABORTED" => {
                        return Err(fenced("target operation has effects"));
                    }
                    Ok(_) => (),
                    Err(error) if error.code == "E_NOT_FOUND" => (),
                    Err(error) => return Err(error),
                }
                products::remove_aborted_target(&self.catalog, &input.ticket().id)?;
                release_import(&mut self.catalog, &self.objects, &input)?;
                remember(&mut self.catalog, &input, "aborted", json!({}))
            }
            ("resume_source", "reserved" | "held" | "fenced" | "resuming")
                if decision.is_none() =>
            {
                input.check(
                    input.request.abort.as_ref(),
                    "abort_target",
                    &input.ticket().target,
                )?;
                self.catalog.db.execute(
                    "UPDATE machine_migrations SET state='resuming' WHERE migration_id=?",
                    [&input.ticket().id],
                )?;
                match self.catalog.operation(&input.op()) {
                    Ok(operation)
                        if operation.phase == "NEW" && operation.kind == "migration_copy" =>
                    {
                        finish_stopped_source(&mut self.catalog, &input)?;
                    }
                    Ok(operation) if operation.phase == "NEW" => {
                        let native = input.native(input.endpoint().execution.clone(), json!({}));
                        crate::managed_fork::cancel(
                            &mut self.catalog,
                            &native,
                            crate::managed_fork::Control {
                                expected_revision: operation.revision,
                            },
                        )?;
                        return Err(pending("waiting for the original source gate to return"));
                    }
                    Ok(operation)
                        if operation.phase != "ABORTED" && operation.kind != "migration_copy" =>
                    {
                        return Err(fenced("source already crossed the irreversible stop"));
                    }
                    Ok(_) => (),
                    Err(error) if error.code == "E_NOT_FOUND" => (),
                    Err(error) => return Err(error),
                }
                if input.endpoint().execution.incarnation_id.is_some() {
                    let native = input.native(input.endpoint().execution.clone(), json!({}));
                    let execution = self.scoped_execution(&native)?;
                    self.verify_live_execution(&execution)?;
                } else {
                    source_plan(&self.catalog, &input)?;
                }
                remember(&mut self.catalog, &input, "resumed", json!({}))
            }
            ("finalize_source", "fenced") => {
                require_local(
                    &self.catalog,
                    &input,
                    "fence_source",
                    input.request.fence.as_ref(),
                )?;
                record_decision(&self.catalog, &input, decision.as_deref())?;
                if input.endpoint().execution.incarnation_id.is_none() {
                    finish_stopped_source(&mut self.catalog, &input)?;
                    return remember(&mut self.catalog, &input, "complete", json!({}));
                }
                let mut record = source_point(&self.catalog, &input)?;
                if record.phase == "durable" {
                    record = self.catalog.statepoint_stop(&record, None)?;
                }
                if record.phase == "stop_committed" {
                    record = self.drive_statepoint_stop(record)?;
                }
                if record.phase != "hibernated" {
                    return Err(pending(
                        "waiting for the old VMM and private writer heads to exit",
                    ));
                }
                remember(&mut self.catalog, &input, "complete", json!({}))
            }
            ("finalize_target", "active") => {
                require_local(
                    &self.catalog,
                    &input,
                    "prepare_target",
                    input.request.ready.as_ref(),
                )?;
                record_decision(&self.catalog, &input, decision.as_deref())?;
                release_import(&mut self.catalog, &self.objects, &input)?;
                remember(&mut self.catalog, &input, "complete", json!({}))
            }
            _ => Err(conflict(
                "migration step is outside its durable Worker state",
            )),
        }
    }
}

pub(crate) fn source_operation(catalog: &Catalog, op: &str) -> Result<bool> {
    Ok(catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='source' AND native_operation_id=?)",
        [op], |row| row.get(0))?)
}

pub(crate) fn is_held_source(catalog: &Catalog, op: &str) -> Result<bool> {
    Ok(catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='source' AND native_operation_id=? AND state='held')",
        [op], |row| row.get(0))?)
}

pub(crate) fn reject_source_command(catalog: &Catalog, op: &str) -> Result<()> {
    if source_operation(catalog, op)? {
        return Err(fenced(
            "source migration gates require the exact migration decision",
        ));
    }
    Ok(())
}

pub(crate) fn permit_target_process(catalog: &Catalog, operation: &Operation) -> Result<()> {
    let held: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='target' AND native_operation_id=?
          AND (state IN ('aborting','aborted') OR (? AND decision_json IS NULL)))",
        params![operation.operation_id,operation.kind=="launch"], |row| row.get(0))?;
    if held {
        return Err(fenced(
            "migration target process does not have launch authority",
        ));
    }
    Ok(())
}

pub(crate) fn permit_target_activation(catalog: &Catalog, operation: &str) -> Result<()> {
    if requires_owner(catalog, operation)? {
        return Err(fenced("held target requires the committed owner decision"));
    }
    Ok(())
}

fn clone_fenced_disk(mut source: File, mut target: &File) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::PermissionsExt;
    let fault = crate::statepoint_capture::host_io;
    let bytes = source.metadata().map_err(fault)?.len();
    let mut buffer = vec![0; 1 << 20];
    let mut remaining = bytes;
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as usize;
        let chunk = &mut buffer[..count];
        source.read_exact(chunk).map_err(fault)?;
        if chunk.iter().any(|byte| *byte != 0) {
            target.write_all(chunk).map_err(fault)?;
        } else {
            target
                .seek(SeekFrom::Current(count as i64))
                .map_err(fault)?;
        }
        remaining -= count as u64;
    }
    target.set_len(bytes).map_err(fault)?;
    target
        .set_permissions(std::fs::Permissions::from_mode(0o400))
        .map_err(fault)?;
    target.sync_all().map_err(fault)
}

fn hold_stopped_source(
    catalog: &mut Catalog,
    objects: &File,
    input: &Input,
    plan: managed::Plan,
) -> Result<Value> {
    let product_volumes = product_volumes(catalog, input, &plan.devices)?;
    reserve(catalog, input)?;
    products::reserve_source(catalog, &input.ticket().id, &product_volumes)?;
    let expected = &input.endpoint().execution;
    let request = input.native(expected.clone(), json!({}));
    let operation = catalog.begin(&request, "migration_copy")?;
    let op = &operation.operation_id;
    let mut devices = plan.devices;
    for (slot, device) in devices.iter_mut().enumerate() {
        if device.disk.read_only {
            let closure = catalog.block_closure(&device.disk.generation_id)?;
            if closure[0].spec.mutable() {
                return Err(fenced(
                    "read-only migration disk is not an immutable generation",
                ));
            }
            continue;
        }
        let head: String = catalog.db.query_row(
            "SELECT head_resource_id FROM volume_heads WHERE volume_id=?",
            [&device.volume_id],
            |row| row.get(0),
        )?;
        let closure = catalog.block_closure(&head)?;
        let object = &closure[0];
        if !object.spec.mutable() || object.spec.volume_id.as_deref() != Some(&device.volume_id) {
            return Err(fenced(
                "stopped machine no longer has the original writable volume head",
            ));
        }
        let (_, file) = crate::blocks::fence_head_for_seal(objects, object, false)?;
        let id = managed::key(op, "migration-cut", slot);
        let mut spec = object.spec.clone();
        spec.resource_id = id.clone();
        spec.sealed = true;
        let prior = catalog.block_intent(&id)?;
        if let Some((owner, recorded, _)) = &prior {
            if owner != op || recorded != &spec {
                return Err(fenced("stopped disk copy scope changed"));
            }
        } else {
            catalog.db.execute(
                "INSERT INTO managed_blocks VALUES(?,?,?,NULL)",
                params![id, op, encode(&spec)?],
            )?;
        }
        if prior
            .as_ref()
            .is_none_or(|(_, _, backing)| backing.is_none())
        {
            let frozen = crate::blocks::materialize_with(objects, op, spec, |_, target| {
                clone_fenced_disk(file, target)
            })?;
            let tx = catalog.db.transaction()?;
            crate::blocks::publish_block_record(&tx, op, &frozen)?;
            tx.execute(
                "INSERT INTO root_refs VALUES('migration_cut',?,?,'active',1,?)",
                params![op, id, op],
            )?;
            tx.commit()?;
        }
        device.disk.generation_id = id;
        device.disk.volume_id = None;
        device.head_id = None;
        device.reattach = false;
    }
    let generation_ids = devices
        .iter()
        .map(|device| device.disk.generation_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let details = HeldDetails {
        generation_ids,
        capture_operation_id: op.clone(),
        machine: plan.machine,
        devices,
        profile: None,
        product_volumes,
    };
    let manifest_digest = digest(encode(&details)?.as_bytes());
    remember(
        catalog,
        input,
        "held",
        json!({"details":details,"manifest_digest":manifest_digest}),
    )
}

fn finish_stopped_source(catalog: &mut Catalog, input: &Input) -> Result<()> {
    let operation = catalog.operation(&input.op())?;
    if operation.phase == "NEW" {
        let native = input.native(input.endpoint().execution.clone(), json!({}));
        catalog.finish(&native, false, operation.revision)?;
    }
    catalog.db.execute(
        "UPDATE root_refs SET state='dropped',revision=revision+1
        WHERE owner_kind='migration_cut' AND owner_id=? AND state='active'",
        [&input.op()],
    )?;
    Ok(())
}
