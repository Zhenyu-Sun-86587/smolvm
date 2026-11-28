//! Exact-attempt Worker authority for a cross-Worker transfer.

use crate::activation_runtime::ActivationRuntime;
use crate::boot_environment;
use crate::catalog::{Catalog, Execution, Operation};
use crate::ipc::{valid_digest, valid_id, Expected, Fault, FdEntry, Request, Result, PROTOCOL};
use crate::managed::{self, Device, Machine};
use crate::migration_product_volumes as products;
use crate::network_lease_catalog::TapLease;
use crate::network_memberships::{self, Membership};
use crate::network_runtime::NetworkRuntime;
use crate::network_transfer::{self, OwnerDecision, SourceFence, Transfer};
use crate::statepoint_catalog::Record;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::Path;

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
    network: Option<MigrationNetwork>,
    boot_environment: Option<boot_environment::Attempt>,
}

#[derive(Deserialize)]
struct MigrationNetwork {
    source_attachment: Attachment,
    membership: Membership,
    overlay_fence: Option<SourceFence>,
    target_abort: Option<network_transfer::Receipt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Attachment {
    lease: TapLease,
    request_digest: String,
    network_id: String,
    dns_name: Option<String>,
    policy_revision: i64,
}

#[derive(Deserialize, Serialize)]
struct ReadyNetwork {
    transfer: Transfer,
    operation_id: String,
    request_digest: String,
}

#[derive(Serialize)]
struct HistoricalNetwork {
    published_revision: i64,
    retired_revision: i64,
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
        if self.request.boot_environment.is_some()
            && (ticket.mode != "cold"
                || !matches!(
                    self.request.step.as_str(),
                    "preflight_target" | "prepare_target" | "activate_target"
                ))
        {
            return Err(Fault::invalid(
                "boot environment is only valid for a new cold target",
            ));
        }
        if let Some(network) = &self.request.network {
            let lease = &network.source_attachment.lease;
            let expected = &ticket.source.execution;
            let incarnation = expected
                .incarnation_id
                .as_deref()
                .unwrap_or(&ticket.source.binding_incarnation_id);
            if lease.route_id != "deep"
                || lease.bundle_digest != ticket.source.bundle_digest
                || lease.instance_id != expected.instance_id
                || lease.execution_epoch != Some(expected.execution_epoch)
                || lease.incarnation_id.as_deref() != Some(incarnation)
                || lease.revision < 1
                || lease.state != "attached"
                || lease.gate != "open"
                || !valid_id(&lease.lease_id)
                || !valid_id(&lease.operation_id)
                || !valid_digest(&network.source_attachment.request_digest)
                || !network.membership.valid()
                || network.membership.policy_revision
                    != network.source_attachment.policy_revision.max(1)
            {
                return Err(fenced(
                    "network intent differs from the exact source execution or policy",
                ));
            }
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
    let intent = network_intent(input)?;
    catalog.db.execute(
        "INSERT OR IGNORE INTO machine_migration_network_intents VALUES(?,?)",
        params![input.ticket().id, intent],
    )?;
    verify_network_intent(catalog, input)
}

fn network_intent(input: &Input) -> Result<String> {
    encode(
        input
            .request
            .network
            .as_ref()
            .map(|net| (&net.source_attachment, &net.membership)),
    )
}

fn verify_network_intent(catalog: &Catalog, input: &Input) -> Result<()> {
    let prior: Option<String> = catalog
        .db
        .query_row(
            "SELECT intent_json FROM machine_migration_network_intents WHERE migration_id=?",
            [&input.ticket().id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(prior) = prior {
        if prior != network_intent(input)? {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "migration network scope changed",
            ));
        }
    }
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

fn cpu_clock_profile(boot: &str) -> Result<String> {
    if !cfg!(target_arch = "x86_64") {
        return Err(unsupported(
            "held migration currently requires Linux x86-64 KVM",
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
    let clock_domain = migration_clock_domain(signature, boot)?;
    let rate = measured_kvm_tsc_rate()?;
    Ok(digest(
        format!("{signature}\nclock_domain={clock_domain}\nkvm_tsc_khz={rate}").as_bytes(),
    ))
}

fn migration_clock_domain(signature: &str, boot: &str) -> Result<String> {
    if !signature
        .lines()
        .any(|line| line == "vendor_id=GenuineIntel" || line == "vendor_id=AuthenticAMD")
    {
        return Err(unsupported(
            "held migration needs a measured Intel or AMD CPU",
        ));
    }
    let flags = signature
        .lines()
        .find_map(|line| line.strip_prefix("flags="))
        .unwrap_or("");
    let has = |wanted| flags.split_ascii_whitespace().any(|flag| flag == wanted);
    if has("constant_tsc") {
        return Ok("constant_tsc".into());
    }
    // Nested KVM can expose a calibrated rate and a usable paravirtual clock
    // without advertising constant TSC. Limit this clock to the same Linux boot.
    let clock =
        std::fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource");
    if has("hypervisor")
        && has("tsc_known_freq")
        && valid_id(boot)
        && clock.is_ok_and(|value| value.trim() == "kvm-clock")
    {
        return Ok(format!("same_boot:{boot}"));
    }
    Err(unsupported(
        "held migration needs constant TSC or a shared calibrated KVM clock within one host boot",
    ))
}

fn measured_kvm_tsc_rate() -> Result<i32> {
    use std::os::fd::{AsRawFd, FromRawFd};
    const GET_API_VERSION: libc::c_ulong = 0xae00;
    const CREATE_VM: libc::c_ulong = 0xae01;
    const CHECK_EXTENSION: libc::c_ulong = 0xae03;
    const CREATE_VCPU: libc::c_ulong = 0xae41;
    const GET_TSC_KHZ: libc::c_ulong = 0xaea3;
    const CLOCK_CAPABILITIES: [libc::c_ulong; 3] = [39, 60, 61]; // clock adjust, TSC control, TSC query
    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|_| unsupported("KVM is unavailable"))?;
    if unsafe { libc::ioctl(kvm.as_raw_fd(), GET_API_VERSION) } != 12
        || CLOCK_CAPABILITIES
            .into_iter()
            .any(|cap| unsafe { libc::ioctl(kvm.as_raw_fd(), CHECK_EXTENSION, cap) } <= 0)
    {
        return Err(unsupported(
            "KVM cannot measure and restore the guest clock and TSC frequency",
        ));
    }
    let create = |fd, command| -> Result<OwnedFd> {
        let result = unsafe { libc::ioctl(fd, command, 0 as libc::c_ulong) };
        if result < 0 {
            return Err(unsupported(
                "KVM cannot provision a vCPU to measure its default TSC frequency",
            ));
        }
        // KVM_CREATE_VM and KVM_CREATE_VCPU return fresh, owned descriptors.
        Ok(unsafe { OwnedFd::from_raw_fd(result) })
    };
    let vm = create(kvm.as_raw_fd(), CREATE_VM)?;
    let vcpu = create(vm.as_raw_fd(), CREATE_VCPU)?;
    let khz = unsafe { libc::ioctl(vcpu.as_raw_fd(), GET_TSC_KHZ) };
    if khz <= 0 {
        return Err(unsupported(
            "KVM did not report a measurable virtual TSC frequency",
        ));
    }
    Ok(khz)
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
                || execution.execution_epoch != epoch
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
    if plan.machine.name != ep.runtime_name {
        return Err(fenced(
            "source managed launch differs from the migration ticket",
        ));
    }
    Ok((execution, plan))
}

fn source_attachment(
    catalog: &Catalog,
    execution: &Execution,
    plan: &managed::Plan,
    stopped: bool,
) -> Result<Option<(Attachment, Option<HistoricalNetwork>)>> {
    let Some(spec) = plan.machine.network.as_ref() else {
        return Ok(None);
    };
    let id = plan.network_attachment_id().unwrap();
    let (lease, history) = if stopped {
        let row = catalog
            .db
            .query_row(
                "SELECT t.lease_id,t.operation_id,t.route_id,t.bundle_digest,t.instance_id,
                    t.incarnation_id,t.execution_epoch,t.host_boot_id,t.broker_session_id,
                    t.revision,k.published_revision,t.descriptor_json
             FROM network_tap_leases t JOIN network_kernel_receipts k USING(lease_id)
             WHERE t.attachment_id=?1 AND t.incarnation_id=?2 AND t.execution_epoch=?3
               AND t.operation_id=?4 AND t.instance_id=?5 AND t.state='retired'
               AND t.revision>k.published_revision
               AND NOT EXISTS(SELECT 1 FROM network_tap_leases active
                 WHERE active.attachment_id=t.attachment_id AND active.state<>'retired')",
                params![
                    id,
                    execution.incarnation_id,
                    execution.execution_epoch,
                    execution.last_operation_id,
                    execution.instance_id
                ],
                |r| {
                    Ok((
                        TapLease {
                            lease_id: r.get(0)?,
                            operation_id: r.get(1)?,
                            route_id: r.get(2)?,
                            bundle_digest: r.get(3)?,
                            instance_id: r.get(4)?,
                            incarnation_id: r.get(5)?,
                            execution_epoch: r.get(6)?,
                            host_boot_id: r.get(7)?,
                            broker_session_id: r.get(8)?,
                            revision: r.get::<_, i64>(9)? - 1,
                            state: "attached".into(),
                            gate: "open".into(),
                            attachment: serde_json::from_str(&r.get::<_, String>(11)?)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        },
                        HistoricalNetwork {
                            published_revision: r.get(10)?,
                            retired_revision: r.get(9)?,
                        },
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| fenced("stopped source has no exact retired published TAP"))?;
        (row.0, Some(row.1))
    } else {
        let leases = catalog.tap_leases_for_execution(execution)?;
        let [lease] = leases.as_slice() else {
            return Err(fenced("migration requires exactly one managed source TAP"));
        };
        if lease.gate != "open"
            || lease.state != "attached"
            || catalog.network_kernel_proof(lease)?.is_none()
        {
            return Err(fenced("source TAP has no exact kernel publication proof"));
        }
        (lease.clone(), None)
    };
    let (network_id, dns_name) = catalog.tap_network_metadata(&lease)?;
    if id != lease.attachment.attachment_id
        || !lease.matches(execution)
        || network_id != spec.network_id
        || lease.attachment.route_domain_id != spec.route_domain_id
        || lease.attachment.device_id != "net0"
        || lease.attachment.mode
            != if spec.fixed_route().is_some() {
                "fixed_internal"
            } else {
                "native"
            }
    {
        return Err(fenced("source attachment differs from the managed launch"));
    }
    let policy_revision =
        network_memberships::lookup(&catalog.db, &lease.instance_id)?.policy_revision;
    let request_digest = catalog.operation(&lease.operation_id)?.request_digest;
    Ok(Some((
        Attachment {
            lease,
            request_digest,
            network_id,
            dns_name,
            policy_revision,
        },
        history,
    )))
}

fn expected_source_attachment(
    catalog: &Catalog,
    input: &Input,
    execution: &Execution,
    plan: &managed::Plan,
) -> Result<()> {
    let observed = source_attachment(
        catalog,
        execution,
        plan,
        input.endpoint().execution.incarnation_id.is_none(),
    )?;
    match (observed, input.request.network.as_ref()) {
        (None, None) => Ok(()),
        (Some((attachment, _)), Some(network)) => {
            // Older lookup clients omit or use zero for the default policy.
            let mut submitted = network.source_attachment.clone();
            submitted.policy_revision = submitted.policy_revision.max(1);
            if attachment != submitted
                || network_memberships::lookup(&catalog.db, &execution.instance_id)?
                    != network.membership
            {
                return Err(fenced(
                    "source TAP or network policy changed during migration",
                ));
            }
            Ok(())
        }
        _ => Err(fenced(
            "migration intent differs from the source network topology",
        )),
    }
}

fn validate_network_domain(
    network: &NetworkRuntime,
    input: &Input,
    spec: &managed::Network,
) -> Result<()> {
    let intent = input
        .request
        .network
        .as_ref()
        .ok_or_else(|| fenced("source network intent is missing"))?;
    let a = &intent.source_attachment.lease.attachment;
    let target = &input.ticket().target.worker_id;
    let source = &input.ticket().source.worker_id;
    let (local, peer) = if input.target() {
        (target, source)
    } else {
        (source, target)
    };
    let valid_mode = match spec.fixed_route() {
        Some((guest, gateway, prefix)) => {
            a.mode == "fixed_internal"
                && a.guest_ipv4 == guest
                && a.gateway_ipv4 == gateway
                && a.guest_prefix == prefix
        }
        None => {
            a.mode == "native"
                && a.guest_ipv4 == a.private_ipv4
                && a.guest_prefix == 32
                && network.overlay().has_peer(&a.route_domain_id, local, peer)
                && network.overlay().allocation().is_some_and(|pool| {
                    pool.network_id == spec.network_id && pool.cidr == spec.cidr
                })
        }
    };
    if !valid_mode
        || intent.source_attachment.network_id != spec.network_id
        || a.route_domain_id != spec.route_domain_id
        || a.device_id != "net0"
    {
        return Err(Fault::new(
            "E_OVERLAY_UNAVAILABLE",
            "migration requires the same managed route domain, mode and guest route",
        ));
    }
    Ok(())
}

fn source_network_expected(input: &Input) -> Expected {
    let mut expected = input.ticket().source.execution.clone();
    if expected.incarnation_id.is_none() {
        expected.incarnation_id = Some(input.ticket().source.binding_incarnation_id.clone());
    }
    expected
}

fn source_point(catalog: &Catalog, input: &Input) -> Result<Record> {
    catalog.require_statepoint(&managed::key(&input.op(), "point", 0))
}

fn hold_source(
    catalog: &mut Catalog,
    objects: &File,
    boot: &str,
    input: &Input,
    network: &NetworkRuntime,
) -> Result<Value> {
    let (execution, plan) = source_plan(catalog, input)?;
    expected_source_attachment(catalog, input, &execution, &plan)?;
    if let Some(spec) = &plan.machine.network {
        validate_network_domain(network, input, spec)?;
    }
    if input.endpoint().execution.incarnation_id.is_none() {
        return hold_stopped_source(catalog, objects, input, plan);
    }
    if execution.phase != "registered" || execution.host_boot_id != boot {
        return Err(fenced(
            "source execution is not registered on this Worker boot",
        ));
    }
    let profile = if input.ticket().mode == "live" {
        Some(cpu_clock_profile(boot)?)
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
    if record
        .point
        .devices
        .iter()
        .filter(|device| device.is_network())
        .count()
        != usize::from(plan.machine.network.is_some())
    {
        return Err(fenced(
            "captured network inventory differs from the managed launch",
        ));
    }
    let product_volumes = product_volumes(catalog, input, &devices)?;
    products::check_held(catalog, &input.ticket().id, &product_volumes)?;
    let parked_at: Option<i64> = catalog.db.query_row(
        "SELECT parked_at_unix_ms FROM machine_migrations WHERE migration_id=?",
        [&input.ticket().id],
        |row| row.get(0),
    )?;
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
        "paused_at_unix_ms":parked_at,"details":details}),
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
        Some(cpu_clock_profile(boot)?)
    } else {
        None
    };
    let (attachment, history) = source_attachment(
        catalog,
        &execution,
        &plan,
        input.endpoint().execution.incarnation_id.is_none(),
    )?
    .map_or((None, None), |(attachment, history)| {
        (Some(attachment), history)
    });
    let product_volumes = product_volumes(catalog, input, &plan.devices)?;
    let storage = plan
        .devices
        .iter()
        .filter(|device| !device.disk.read_only)
        .try_fold(0u64, |sum, device| sum.checked_add(device.capacity_bytes))
        .ok_or_else(|| Fault::invalid("source disk capacity overflow"))?;
    make_receipt(
        input,
        json!({"details":{"profile":profile,
        "vcpus":plan.machine.cpus,"memory_mib":plan.machine.memory_mib,"storage_bytes":storage,
        "product_volumes":product_volumes,"reversible_network":attachment.is_some(),
        "source_attachment":attachment, "historical_network":history,
        "network_topology":plan.machine.network}}),
    )
}

fn preflight(
    catalog: &mut Catalog,
    input: &Input,
    boot: &str,
    network: &NetworkRuntime,
) -> Result<Value> {
    let endpoint = input.endpoint();
    let (epoch, incarnation, active) =
        crate::catalog::binding(&catalog.db, "deep", &endpoint.execution.instance_id)?;
    if epoch + 1 != endpoint.execution.execution_epoch || incarnation.is_some() || active.is_some()
    {
        return Err(fenced(
            "target slot is not empty at the admitted execution epoch",
        ));
    }
    if let Some(source) = input.request.hold.as_ref() {
        input.check(Some(source), "inspect_source", &input.ticket().source)?;
        let source_spec: Option<managed::Network> =
            serde_json::from_value(source["details"]["network_topology"].clone())
                .map_err(|_| fenced("source network topology receipt is malformed"))?;
        match (source_spec.as_ref(), input.request.network.as_ref()) {
            (Some(spec), Some(_)) => validate_network_domain(network, input, spec)?,
            (None, None) => (),
            _ => {
                return Err(fenced(
                    "target preflight is missing the exact source network intent",
                ))
            }
        }
        let capacity = crate::admission::status(&catalog.db)?;
        for dimension in ["vcpus", "memory_mib", "storage_bytes"] {
            let required = source["details"][dimension]
                .as_u64()
                .ok_or_else(|| Fault::invalid("source receipt lacks its managed capacity"))?;
            let total = capacity["capacity"][dimension].as_u64().unwrap_or_default();
            let used = capacity["allocated"][dimension]
                .as_u64()
                .unwrap_or_default();
            if required > total.saturating_sub(used) {
                return Err(Fault::new(
                    "E_RESOURCE_LIMIT",
                    format!("target lacks enough {dimension} for the admitted source"),
                ));
            }
        }
        if input.ticket().mode == "live" {
            let target = cpu_clock_profile(boot)?;
            if source["details"]["profile"] != target {
                return Err(unsupported(
                    "held migration requires identical CPU fingerprints and KVM TSC support",
                ));
            }
            crate::admission::require_capture_space(
                &catalog.db,
                source["details"]["memory_mib"].as_u64().unwrap_or_default(),
            )?;
        }
    } else if input.ticket().mode == "live" {
        return Err(fenced(
            "held target preflight requires CPU, clock and geometry from the exact source",
        ));
    }
    make_receipt(
        input,
        json!({"details":{"boot_environment_migration":true}}),
    )
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

fn requested_transfer(input: &Input) -> Option<Transfer> {
    input.request.network.as_ref().map(|network| {
        make_transfer(
            input.ticket(),
            &network.source_attachment,
            network.membership.policy_revision,
        )
    })
}

fn make_transfer(ticket: &Ticket, source: &Attachment, policy_revision: i64) -> Transfer {
    let lease = &source.lease;
    let a = &lease.attachment;
    Transfer {
        machine_id: ticket.machine_id.clone(),
        source_worker_id: ticket.source.worker_id.clone(),
        target_worker_id: ticket.target.worker_id.clone(),
        expected_owner_epoch: ticket.source.owner_epoch,
        target_execution_epoch: ticket.target.execution.execution_epoch,
        attachment_id: a.attachment_id.clone(),
        attachment_revision: lease.revision,
        target_attachment_id: managed::key(&ticket.target.execution.instance_id, "net", 0),
        // The stable reservation is a new lease: quarantined, offered, attached.
        target_attachment_revision: 3,
        policy_revision,
        migration_id: ticket.id.clone(),
        network_mode: a.mode.clone(),
        private_ipv4: a.private_ipv4,
        guest_ipv4: a.guest_ipv4,
        guest_gateway_ipv4: a.gateway_ipv4,
        guest_prefix: a.guest_prefix,
        guest_mac: a.mac,
        route_domain_id: a.route_domain_id.clone(),
    }
}

pub(crate) fn live_network_transfer(
    catalog: &Catalog,
    operation: &str,
    lease: &TapLease,
) -> Result<Option<Transfer>> {
    let data: Option<(String, String)> = catalog.db.query_row(
        "SELECT m.ticket_json,n.intent_json FROM machine_migrations m
         JOIN machine_migration_network_intents n USING(migration_id)
         JOIN network_transfer_guards g ON g.migration_id=m.migration_id AND g.operation_id=m.native_operation_id
         WHERE m.side='target' AND m.native_operation_id=?1 AND g.attachment_id=?2",
        params![operation,lease.attachment.attachment_id], |r| Ok((r.get(0)?,r.get(1)?)),
    ).optional()?;
    let Some((ticket, scope)) = data else {
        return Ok(None);
    };
    let ticket: Ticket =
        serde_json::from_str(&ticket).map_err(|_| fenced("invalid migration ticket"))?;
    let (source, membership): (Attachment, Membership) = serde_json::from_str(&scope)
        .map_err(|_| fenced("invalid sealed migration network intent"))?;
    let transfer = make_transfer(&ticket, &source, membership.policy_revision);
    if ticket.mode != "live"
        || lease.lease_id == source.lease.lease_id
        || lease.revision != transfer.target_attachment_revision
        || lease.instance_id != ticket.target.execution.instance_id
        || lease.incarnation_id != ticket.target.execution.incarnation_id
        || lease.execution_epoch != Some(ticket.target.execution.execution_epoch)
    {
        return Err(fenced(
            "migration target TAP is outside its execution or transfer revision",
        ));
    }
    Ok(Some(transfer))
}

fn reserve_target_tap(
    catalog: &mut Catalog,
    network: &mut NetworkRuntime,
    input: &Input,
    native: &Request,
    spec: &managed::Network,
    transfer: &Transfer,
) -> Result<TapLease> {
    validate_network_domain(network, input, spec)?;
    catalog.ensure_private_network(&crate::network_catalog::RegisterNetwork {
        network_id: spec.network_id.clone(),
        route_domain_id: spec.route_domain_id.clone(),
        cidr: spec.cidr.clone(),
    })?;
    let fixed = spec.fixed_route();
    let (_, _, expected) = native.scope()?;
    let dns_name = input
        .request
        .network
        .as_ref()
        .unwrap()
        .source_attachment
        .dns_name
        .clone()
        .unwrap_or_else(|| format!("{}.private", managed::key(&expected.instance_id, "vm", 0)));
    let data = serde_json::from_value(json!({
        "attachment_id":transfer.target_attachment_id, "network_id":spec.network_id,
        "device_id":"net0", "mode":transfer.network_mode, "guest_ipv4":fixed.map(|(guest,_,_)|guest),
        "preferred_private_ipv4":transfer.private_ipv4, "transfer_id":input.ticket().id,
        "dns_name":dns_name,
    })).map_err(|_|Fault::invalid("invalid transfer reservation"))?;
    catalog.reserve_network_with_overlay(native, &data, network.overlay())?;
    let lease = match catalog.tap_lease(&transfer.target_attachment_id) {
        Ok(lease) if lease.operation_id == input.op() && lease.gate == "closed" => {
            let expected = &input.ticket().target.execution;
            let ready = match lease.state.as_str() {
                "quarantined" => lease.incarnation_id.is_none() && lease.execution_epoch.is_none(),
                "offered" | "attached" => {
                    lease.incarnation_id == expected.incarnation_id
                        && lease.execution_epoch == Some(expected.execution_epoch)
                }
                _ => false,
            };
            if !ready || lease.instance_id != expected.instance_id {
                return Err(fenced("target TAP no longer owns the held execution lease"));
            }
            lease
        }
        Ok(_) => {
            return Err(fenced(
                "target TAP belongs to a different operation or gate",
            ))
        }
        Err(error) if error.code == "E_NOT_FOUND" => network.prepare(
            catalog,
            &native.derived(
                "PrepareNetworkAttachment",
                json!({
                    "attachment_id":transfer.target_attachment_id,
                    "guest_gateway_ipv4":fixed.map(|(_,gateway,_)|gateway),
                    "guest_prefix":fixed.map(|(_,_,prefix)|prefix),
                }),
            ),
        )?,
        Err(error) => return Err(error),
    };
    if !network_transfer::target_descriptor(transfer, &lease.attachment) {
        return Err(fenced(
            "target TAP cannot preserve the original IP, MAC and gateway",
        ));
    }
    Ok(lease)
}

#[allow(clippy::too_many_arguments)]
fn prepare_target(
    catalog: &mut Catalog,
    objects: &File,
    points: &Path,
    boot: &str,
    input: &Input,
    wire: &Request,
    descriptors: Vec<OwnedFd>,
    network: &mut NetworkRuntime,
    activations: &ActivationRuntime,
    verify_process: impl Fn(&Catalog, &Execution) -> Result<()>,
) -> Result<Value> {
    input.check(
        input.request.hold.as_ref(),
        "hold_source",
        &input.ticket().source,
    )?;
    let hold = input.request.hold.as_ref().unwrap();
    let details: HeldDetails = serde_json::from_value(hold["details"].clone())
        .map_err(|error| Fault::invalid(error.to_string()))?;
    if details.generation_ids.is_empty() || details.devices.is_empty() {
        return Err(fenced("source hold has no eligible immutable disk closure"));
    }
    let live = input.ticket().mode == "live";
    let transfer = requested_transfer(input);
    let network_spec = details.machine.network.clone();
    match (network_spec.as_ref(), transfer.as_ref()) {
        (Some(spec), Some(_)) => validate_network_domain(network, input, spec)?,
        (None, None) => (),
        _ => {
            return Err(fenced(
                "target intent differs from the held source network topology",
            ))
        }
    }
    if live && details.profile.as_deref() != Some(cpu_clock_profile(boot)?.as_str()) {
        return Err(unsupported("held migration CPU or clock profile changed"));
    }
    reserve(catalog, input)?;
    let endpoint = input.endpoint();
    let op = input.op();
    let (import_state, saved_import): (String, Option<String>) = catalog.db.query_row(
        "SELECT state,import_json FROM machine_migrations WHERE migration_id=?",
        [&input.ticket().id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if import_state == "imported" {
        if !descriptors.is_empty()
            && saved_import.as_deref() != Some(encode(import_spec(input)?)?.as_str())
        {
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
        let encoded = encode(&spec)?;
        if saved_import
            .as_deref()
            .is_some_and(|saved| saved != encoded)
        {
            return Err(fenced("transfer retry changed its original closure digest"));
        }
        catalog.db.execute(
            "UPDATE machine_migrations SET state='importing',import_json=?
            WHERE migration_id=? AND decision_json IS NULL",
            params![encoded, input.ticket().id],
        )?;
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
            "UPDATE machine_migrations SET state='imported' WHERE migration_id=?",
            [&input.ticket().id],
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
        if let Some((transfer, spec)) = transfer.as_ref().zip(network_spec.as_ref()) {
            reserve_target_tap(catalog, network, input, &native, spec, transfer)?;
        }
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
        queue_cold(
            catalog,
            &native,
            details,
            &endpoint.runtime_name,
            input.request.boot_environment.as_ref(),
        )?;
        if let Some((transfer, spec)) = transfer.as_ref().zip(network_spec.as_ref()) {
            reserve_target_tap(catalog, network, input, &native, spec, transfer)?;
        }
    }
    let prepared_network = if let Some(transfer) = &transfer {
        let membership = &input.request.network.as_ref().unwrap().membership;
        Some(if live {
            let execution =
                catalog.execution(endpoint.execution.incarnation_id.as_deref().unwrap())?;
            verify_process(catalog, &execution)?;
            let request = input.native(endpoint.execution.clone(), json!({})).derived(
                "PrepareTransfer",
                json!({"transfer":transfer, "membership":membership}),
            );
            let result = network_transfer::handle(
                catalog,
                &execution,
                &request,
                network,
                activations,
                || verify_process(catalog, &execution),
            )?;
            verify_process(catalog, &execution)?;
            result
        } else {
            network_transfer::prepare_cold(catalog, network, &op, transfer, membership)?
        })
    } else {
        None
    };
    let ready_network = transfer.map(|transfer| ReadyNetwork {
        transfer,
        operation_id: op.clone(),
        request_digest: input.ticket_digest.clone(),
    });
    let product_volumes = products::observations(catalog, &native, &input.ticket().id)?;
    remember(
        catalog,
        input,
        "prepared",
        json!({"details":{"native_operation_id":op,
        "request_digest":input.ticket_digest, "held_live":live,"product_volumes":product_volumes,
        "network":ready_network, "network_prepared":prepared_network},
        "capture_id":hold["capture_id"], "manifest_digest":hold["manifest_digest"]}),
    )
}

fn queue_cold(
    catalog: &mut Catalog,
    native: &Request,
    details: HeldDetails,
    name: &str,
    environment: Option<&boot_environment::Attempt>,
) -> Result<Operation> {
    let (id, _) = native.operation()?;
    match catalog.operation(id) {
        Ok(_) if boot_environment::attempt(&catalog.db, id)?.as_ref() != environment => {
            return Err(conflict("cold migration boot environment changed"));
        }
        Ok(_) => (),
        Err(error) if error.code == "E_NOT_FOUND" => (),
        Err(error) => return Err(error),
    }
    let (_, _, expected) = native.scope()?;
    let namespace = managed::serve_id(&expected.instance_id, name)?;
    let mut machine = details.machine;
    machine.name = name.into();
    if environment.is_some() && machine.boot_profile != "system-debian-v1" {
        return Err(unsupported(
            "cold migration Boot environment requires the managed System profile",
        ));
    }
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
        if let Some(environment) = environment {
            boot_environment::record(tx, id, environment)?;
        }
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

fn check_ready_network(input: &Input, transfer: Option<&Transfer>) -> Result<()> {
    let ready = input
        .request
        .ready
        .as_ref()
        .ok_or_else(|| fenced("target readiness is missing"))?;
    match transfer {
        None if ready["details"]["network"].is_null() => Ok(()),
        Some(transfer) => {
            let network: ReadyNetwork = serde_json::from_value(ready["details"]["network"].clone())
                .map_err(|_| fenced("stable target network readiness is missing"))?;
            let prepared: network_transfer::Receipt =
                serde_json::from_value(ready["details"]["network_prepared"].clone())
                    .map_err(|_| fenced("target TAP preparation is missing"))?;
            if network.transfer != *transfer
                || network.operation_id != native_id(&input.ticket().id, "target")
                || network.request_digest != input.ticket_digest
                || prepared.transfer != *transfer
                || prepared.state != "prepared"
                || prepared.published
                || prepared.activation_revision < 1
            {
                return Err(fenced(
                    "target TAP preparation does not match the exact transfer",
                ));
            }
            Ok(())
        }
        _ => Err(fenced("target readiness has another network topology")),
    }
}

fn close_source_tap(
    catalog: &Catalog,
    input: &Input,
    network: &NetworkRuntime,
    execution: &Execution,
    transfer: &Transfer,
) -> Result<Option<SourceFence>> {
    if transfer.network_mode == "native"
        && (!network.overlay().has_peer(
            &transfer.route_domain_id,
            &transfer.source_worker_id,
            &transfer.target_worker_id,
        ) || !network.overlay().permits_source_fence(transfer, execution))
    {
        return Err(fenced(
            "source overlay ownership belongs to another Worker or execution",
        ));
    }
    if network_memberships::lookup(&catalog.db, &execution.instance_id)?
        != input.request.network.as_ref().unwrap().membership
    {
        return Err(fenced("source network membership changed"));
    }
    if execution.phase == "exited" {
        let (_, plan) = source_plan(catalog, input)?;
        expected_source_attachment(catalog, input, execution, &plan)?;
    } else {
        let lease = catalog.tap_lease(&transfer.attachment_id)?;
        let original = &input
            .request
            .network
            .as_ref()
            .unwrap()
            .source_attachment
            .lease;
        let transfer_json = encode(transfer)?;
        let prior: Option<(String, i64, String, String)> = catalog.db.query_row(
            "SELECT lease_id,lease_revision,transfer_json,phase FROM machine_migration_source_taps WHERE migration_id=?",
            [&input.ticket().id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        if lease.lease_id != original.lease_id
            || !lease.matches(execution)
            || lease.state != "attached"
            || !network_transfer::source_descriptor(&lease.attachment, transfer)
            || catalog.network_kernel_proof(&lease)?.is_none()
        {
            return Err(fenced("source TAP no longer has the exact published lease"));
        }
        match prior {
            None if lease.gate == "open" && lease.revision == transfer.attachment_revision => {
                let scope = network.migration_source_proof(&lease)?;
                catalog.db.execute(
                    "INSERT INTO machine_migration_source_taps VALUES(?,?,?,?,?,'closing')",
                    params![
                        transfer.migration_id,
                        lease.lease_id,
                        lease.revision,
                        transfer_json,
                        encode(scope)?,
                    ],
                )?;
            }
            Some((id, rev, scope, phase))
                if id == lease.lease_id
                    && rev == lease.revision
                    && scope == transfer_json
                    && matches!(phase.as_str(), "closing" | "closed") =>
            {
                ()
            }
            _ => return Err(fenced("source TAP fence intent changed")),
        }
        network.close_migration_source(&lease)?;
        catalog.db.execute(
            "UPDATE machine_migration_source_taps SET phase='closed' WHERE migration_id=?",
            [&transfer.migration_id],
        )?;
    }
    Ok((transfer.network_mode == "native")
        .then(|| network_transfer::source_receipt(execution, transfer)))
}

fn reopen_source_tap(
    catalog: &Catalog,
    input: &Input,
    network: &NetworkRuntime,
    execution: &Execution,
) -> Result<Option<Attachment>> {
    let row: Option<(String,i64,String,String,String)> = catalog.db.query_row(
        "SELECT lease_id,lease_revision,transfer_json,phase,kernel_scope_json FROM machine_migration_source_taps WHERE migration_id=?",
        [&input.ticket().id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    let Some((id, revision, scope, phase, kernel_scope)) = row else {
        let (_, plan) = source_plan(catalog, input)?;
        expected_source_attachment(catalog, input, execution, &plan)?;
        return Ok(source_attachment(catalog, execution, &plan, false)?.map(|(a, _)| a));
    };
    let transfer =
        requested_transfer(input).ok_or_else(|| fenced("source network scope is missing"))?;
    let mut reopened = input
        .request
        .network
        .as_ref()
        .unwrap()
        .source_attachment
        .clone();
    let target_abort = input
        .request
        .network
        .as_ref()
        .and_then(|net| net.target_abort.as_ref())
        .ok_or_else(|| fenced("source TAP reopen requires the exact target network abort"))?;
    let abort_details = &input.request.abort.as_ref().unwrap()["details"]["network_aborted"];
    if target_abort.transfer != transfer
        || target_abort.state != "aborted"
        || target_abort.published
        || *abort_details != json!(target_abort)
        || scope != encode(&transfer)?
    {
        return Err(fenced(
            "target network abort differs from the source TAP fence",
        ));
    }
    let lease = catalog.tap_lease(&transfer.attachment_id)?;
    let revision_now = revision + i64::from(phase == "reopened");
    if lease.lease_id != id
        || lease.revision != revision_now
        || !lease.matches(execution)
        || lease.state != "attached"
        || !network_transfer::source_descriptor(&lease.attachment, &transfer)
        || network_memberships::lookup(&catalog.db, &execution.instance_id)?
            != input.request.network.as_ref().unwrap().membership
    {
        return Err(fenced("source TAP reopen would change the original lease"));
    }
    if phase != "reopened" {
        catalog.db.execute(
            "UPDATE machine_migration_source_taps SET phase='reopening' WHERE migration_id=?",
            [&input.ticket().id],
        )?;
        let kernel_scope = serde_json::from_str(&kernel_scope)
            .map_err(|_| fenced("invalid persisted migration TAP kernel scope"))?;
        network.reopen_migration_source(&lease, &kernel_scope)?;
        let tx = catalog.db.unchecked_transaction()?;
        if tx.execute(
            "UPDATE network_tap_leases SET revision=revision+1 WHERE lease_id=? AND revision=? AND state='attached'",
            params![id,revision],
        )? != 1 {
            return Err(fenced("source TAP revision changed during the exact reopen"));
        }
        tx.execute(
            "UPDATE private_packet_wake_rules SET source_lease_revision=?1+1
             WHERE source_lease=?2 AND source_lease_revision=?1 AND source_attachment=?3
               AND source_incarnation=?4 AND source_epoch=?5",
            params![
                revision,
                id,
                transfer.attachment_id,
                execution.incarnation_id,
                execution.execution_epoch
            ],
        )?;
        tx.execute(
            "UPDATE machine_migration_source_taps SET phase='reopened' WHERE migration_id=?",
            [&input.ticket().id],
        )?;
        tx.commit()?;
    }
    reopened.lease = catalog.tap_lease(&transfer.attachment_id)?;
    if reopened.lease.gate != "open" {
        return Err(fenced("reopened source TAP has no publication receipt"));
    }
    Ok(Some(reopened))
}

fn source_fence(
    catalog: &mut Catalog,
    objects: &File,
    input: &Input,
    boot: &str,
    network: &NetworkRuntime,
) -> Result<Value> {
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
    let transfer = requested_transfer(input);
    check_ready_network(input, transfer.as_ref())?;
    if input.endpoint().execution.incarnation_id.is_none() {
        let (epoch, incarnation, active) =
            crate::catalog::binding(&catalog.db, "deep", &input.endpoint().execution.instance_id)?;
        if epoch != input.endpoint().execution.execution_epoch
            || incarnation.is_some()
            || active.as_deref() != Some(&input.op())
        {
            return Err(fenced("stopped writer slot or migration operation changed"));
        }
        let (execution, _) = source_plan(catalog, input)?;
        let details: HeldDetails = serde_json::from_value(hold["details"].clone())
            .map_err(|_| fenced("stopped source hold receipt is malformed"))?;
        for device in details
            .devices
            .iter()
            .filter(|device| !device.disk.read_only)
        {
            let head: String = catalog.db.query_row(
                "SELECT head_resource_id FROM volume_heads WHERE volume_id=?",
                [&device.volume_id],
                |r| r.get(0),
            )?;
            let closure = catalog.block_closure(&head)?;
            crate::blocks::fence_head_for_seal(objects, &closure[0], false)?;
        }
        let overlay_fence = match transfer.as_ref() {
            Some(transfer) => close_source_tap(catalog, input, network, &execution, transfer)?,
            None => None,
        };
        return remember(
            catalog,
            input,
            "fenced",
            json!({
            "manifest_digest":hold["manifest_digest"],"details":{"ready_proof":ready,
                "writer_gate":"confirmed_stopped","relay_gate":"exited",
                "tap_gate":transfer.as_ref().map(|_|"retired"),"overlay_fence":overlay_fence}}),
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
    let execution = catalog.execution(&record.point.incarnation_id)?;
    let operation = catalog.operation(&record.operation_id)?;
    let sealed = crate::statepoint_capture::disk_roots(
        catalog,
        objects,
        &operation,
        &execution,
        &record.export,
        &record.point.devices,
    )?;
    if sealed != record.point.disk_generations
        || record
            .point
            .devices
            .iter()
            .filter(|device| device.is_network())
            .count()
            != usize::from(transfer.is_some())
    {
        return Err(fenced(
            "source writer set or measured network inventory changed",
        ));
    }
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
    let overlay_fence = match transfer.as_ref() {
        Some(transfer) => close_source_tap(catalog, input, network, &execution, transfer)?,
        None => None,
    };
    remember(
        catalog,
        input,
        "fenced",
        json!({"capture_id":record.export.capture_id,
        "manifest_digest":record.manifest_digest, "details":{"ready_proof": ready,
        "writer_gate":"capture_stop_reserved","relay_gate":"parked",
        "tap_gate":transfer.as_ref().map(|_|"closed"),"overlay_fence":overlay_fence}}),
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

fn release_import(
    catalog: &mut Catalog,
    objects: &File,
    points: &Path,
    input: &Input,
) -> Result<()> {
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
        if let Err(error) = crate::disk_closure_import::release(catalog, objects, &request) {
            if error.code != "E_NOT_FOUND" {
                return Err(error);
            }
        }
    }
    if input.ticket().mode == "live" {
        // An interrupted StatePoint import can have published the verified
        // directory before its catalog transaction. The migration-scoped
        // representation has no owner in that case.
        let source = native_id(&input.ticket().id, "source");
        let representation = managed::key(&source, "representation", 0);
        match catalog.resource(&representation) {
            Ok(_) => (),
            Err(error) if error.code == "E_NOT_FOUND" => {
                crate::statepoint_store::collect(points, &representation)
                    .map_err(crate::statepoint_capture::host_io)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn validate_boot_intent(catalog: &Catalog, input: &Input) -> Result<()> {
    if input.ticket().mode == "cold"
        && boot_environment::attempt(&catalog.db, &input.op())? != input.request.boot_environment
    {
        return Err(conflict("cold migration boot environment changed"));
    }
    Ok(())
}

fn abort_receipt(input: &Input) -> Result<()> {
    input.check(
        input.request.abort.as_ref(),
        "abort_target",
        &input.ticket().target,
    )?;
    let details = &input.request.abort.as_ref().unwrap()["details"];
    if !["writer_closed", "tap_closed", "relay_closed"]
        .iter()
        .all(|key| details[*key] == true)
    {
        return Err(fenced(
            "target has not corroborated writer, TAP and relay retirement",
        ));
    }
    Ok(())
}

fn source_overlay_fence(input: &Input, transfer: &Transfer) -> Result<Option<SourceFence>> {
    let scope = input.request.network.as_ref().unwrap();
    let fence = input
        .request
        .fence
        .as_ref()
        .ok_or_else(|| fenced("missing exact source fence"))?;
    let details = &fence["details"];
    let stopped = input.ticket().source.execution.incarnation_id.is_none();
    let tap_gate = if stopped { "retired" } else { "closed" };
    let writer_gate = if stopped {
        "confirmed_stopped"
    } else {
        "capture_stop_reserved"
    };
    let relay_gate = if stopped { "exited" } else { "parked" };
    if details["tap_gate"] != tap_gate
        || details["writer_gate"] != writer_gate
        || details["relay_gate"] != relay_gate
        || details["overlay_fence"] != json!(scope.overlay_fence)
        || (transfer.network_mode == "native") != scope.overlay_fence.is_some()
        || scope
            .overlay_fence
            .as_ref()
            .is_some_and(|proof| !proof.binds(&source_network_expected(input)))
    {
        return Err(fenced(
            "committed network transfer lacks the exact source TAP, writer and relay gates",
        ));
    }
    Ok(scope.overlay_fence.clone())
}

pub(crate) fn cold_target(
    db: &rusqlite::Connection,
    operation: &str,
    migration: &str,
) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='target' AND native_operation_id=?
         AND migration_id=? AND json_extract(ticket_json,'$.mode')='cold')",
        params![operation,migration], |r|r.get(0),
    )?)
}

pub(crate) fn query_boot_environment(catalog: &Catalog, request: &Request) -> Result<Value> {
    let operation = catalog.matching_operation(request)?;
    let (_, _, expected) = request.scope()?;
    let attempt: boot_environment::Attempt = request.payload()?;
    let id = &operation.operation_id;
    let eligible: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='target' AND native_operation_id=?
         AND ticket_digest=? AND json_extract(ticket_json,'$.mode')='cold'
         AND state IN ('prepared','active','complete'))",
        params![id,operation.request_digest], |r|r.get(0),
    )?;
    if !eligible
        || operation.kind != "launch"
        || expected.incarnation_id.is_some()
        || expected.execution_epoch != operation.expected_execution_epoch
        || boot_environment::attempt(&catalog.db, id)?.as_ref() != Some(&attempt)
        || operation.phase == "ABORTED"
    {
        return Err(fenced(
            "boot environment requires the original queued cold migration",
        ));
    }
    Ok(json!(operation))
}

fn seal_aborted_target_heads(catalog: &mut Catalog, objects: &File, input: &Input) -> Result<()> {
    let native = input.native(input.endpoint().execution.clone(), json!({}));
    let operation = match catalog.matching_operation(&native) {
        Ok(operation) => operation,
        Err(error) if error.code == "E_NOT_FOUND" => return Ok(()),
        Err(error) => return Err(error),
    };
    let op = &operation.operation_id;
    if !operation.launches_execution()
        || operation.phase != "ABORTED"
        || operation.expected_incarnation_id.is_some()
        || operation.expected_execution_epoch.checked_add(1)
            != Some(input.endpoint().execution.execution_epoch)
    {
        return Err(fenced(
            "target disk cleanup requires the exact aborted launch",
        ));
    }
    let plan = managed::plan(catalog, &operation)?
        .filter(|plan| plan.launch.execution == input.endpoint().execution)
        .ok_or_else(|| fenced("aborted target launch lost its exact disk plan"))?;
    let tx = catalog.db.unchecked_transaction()?;
    let has_authority: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE migration_id=?1 AND side='target'
                        AND native_operation_id=?2 AND state='aborting' AND decision_json IS NULL)
             AND NOT EXISTS(SELECT 1 FROM executions WHERE last_operation_id=?2 AND phase<>'exited')
             AND NOT EXISTS(SELECT 1 FROM writer_reservations WHERE operation_id=?2)
             AND NOT EXISTS(SELECT 1 FROM writer_grants WHERE operation_id=?2 AND state<>'released')",
        params![input.ticket().id,op], |row|row.get(0),
    )?;
    if !has_authority {
        return Err(fenced(
            "aborted target retains an execution or writer, or its migration decision changed",
        ));
    }
    let mut locks = Vec::new();
    let mut sealed = Vec::new();
    for device in &plan.devices {
        let Some(head) = device.head_id.as_deref() else {
            continue;
        };
        if device.reattach || device.disk.read_only {
            return Err(fenced(
                "aborted migration launch does not own one of its disk heads",
            ));
        }
        let before: Option<(String, String)> = tx
            .query_row(
                "SELECT head_resource_id,backing_identity FROM volume_heads WHERE volume_id=?",
                [&device.volume_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((registered, identity)) = before else {
            if let Some((owner, spec, _)) = catalog.block_intent(head)? {
                if owner != *op || !spec.sealed {
                    return Err(fenced("aborted migration has an unaccounted disk head"));
                }
                sealed.push(head);
            }
            continue;
        };
        let (owner, spec, saved_identity) = catalog
            .block_intent(head)?
            .ok_or_else(|| fenced("aborted target head has no managed backing"))?;
        let expected = plan
            .head_spec(head)
            .ok_or_else(|| fenced("aborted target disk head changed"))?;
        let writer: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM writer_reservations WHERE volume_id=?1 OR head_resource_id=?2)
                OR EXISTS(SELECT 1 FROM root_refs WHERE owner_kind='block_seal' AND resource_id=?2 AND state='active')",
            params![device.volume_id,head], |row|row.get(0),
        )?;
        if registered != head
            || owner != *op
            || spec != expected
            || !spec.mutable()
            || saved_identity.as_deref() != Some(&identity)
            || writer
        {
            return Err(fenced(
                "aborted target head or writer authority differs from its exact launch",
            ));
        }
        let mut object = catalog.block_closure(head)?.remove(0);
        let (directory, file) = crate::blocks::fence_head_for_seal(objects, &object, true)?;
        crate::blocks::seal_fenced_head(&directory, &file, &mut object)?;
        if tx.execute(
            "DELETE FROM volume_heads WHERE volume_id=?1 AND head_resource_id=?2 AND backing_identity=?3",
            params![device.volume_id,head,identity],
        )? != 1 {
            return Err(fenced("aborted target disk head changed while being discarded"));
        }
        crate::blocks::publish_seal_record(&tx, op, &object)?;
        tx.execute(
            "UPDATE root_refs SET state='dropped',revision=revision+1
             WHERE owner_kind='operation' AND owner_id=?1 AND resource_id=?2 AND state='active'",
            params![op, head],
        )?;
        locks.push(file);
        sealed.push(head);
    }
    tx.commit()?;
    drop(locks);
    // The target heads are immutable staging garbage after the transaction.
    // If collection is interrupted, the Worker resumes from 'deleting'.
    for head in sealed {
        let resource = catalog.resource(head)?;
        if resource["state"] == "available" {
            let revision = resource["revision"]
                .as_i64()
                .ok_or_else(|| fenced("aborted target disk has no catalog revision"))?;
            match catalog.mark_gc(head, revision) {
                Ok(_) => (),
                Err(error) if error.code == "E_RESOURCE_PINNED" => (),
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn abort_target_tap(catalog: &Catalog, network: &mut NetworkRuntime, input: &Input) -> Result<()> {
    let Some(transfer) = requested_transfer(input) else {
        return Ok(());
    };
    match catalog.tap_lease(&transfer.target_attachment_id) {
        Ok(lease) if lease.operation_id == input.op() && lease.state == "quarantined" => {
            network.retire_port(catalog, &lease)?;
        }
        Ok(_) => return Err(fenced("target TAP effects have not been retired")),
        Err(error) if error.code == "E_NOT_FOUND" => (),
        Err(error) => return Err(error),
    }
    let unresolved: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_attachments WHERE operation_id=? AND state='unknown')",
        [&input.op()],
        |r| r.get(0),
    )?;
    if unresolved {
        return Err(fenced(
            "target network preparation must be reconciled before abort",
        ));
    }
    catalog.db.execute(
        "UPDATE network_attachments SET state='released',revision=revision+1
         WHERE operation_id=? AND attachment_id=? AND state='reserved'",
        params![input.op(), transfer.target_attachment_id],
    )?;
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
        verify_network_intent(&self.catalog, &input)?;
        if let Some(result) = previous(&self.catalog, &input, step)? {
            let (phase, decision) = state(&self.catalog, &input)?.unwrap();
            if (phase == "aborted" && step != "abort_target")
                || (phase == "resumed" && step != "resume_source")
                || (step == "hold_source" && phase != "held")
            {
                return Err(fenced("migration step no longer has the claimed authority"));
            }
            match step {
                "activate_target" | "finalize_source" | "finalize_target" => {
                    if decision.as_deref() != Some(input.decision()?.as_str()) {
                        return Err(fenced("owner decision changed on replay"));
                    }
                    if step == "activate_target" {
                        validate_boot_intent(&self.catalog, &input)?;
                        let native = input.native(input.endpoint().execution.clone(), json!({}));
                        let execution = self.scoped_execution(&native)?;
                        self.verify_live_execution(&execution)?;
                    }
                }
                "hold_source"
                    if input
                        .request
                        .hold
                        .as_ref()
                        .is_some_and(|hold| hold["step"] == "hold_source") =>
                {
                    require_local(
                        &self.catalog,
                        &input,
                        "hold_source",
                        input.request.hold.as_ref(),
                    )?;
                }
                "prepare_target" => {
                    input.check(
                        input.request.hold.as_ref(),
                        "hold_source",
                        &input.ticket().source,
                    )?;
                    validate_boot_intent(&self.catalog, &input)?;
                    let hold = input.request.hold.as_ref().unwrap();
                    if result["manifest_digest"] != hold["manifest_digest"]
                        || result["capture_id"] != hold["capture_id"]
                    {
                        return Err(fenced(
                            "target prepare retry changed the original source hold",
                        ));
                    }
                    if input.ticket().mode == "live" {
                        let native = input.native(input.endpoint().execution.clone(), json!({}));
                        self.verify_live_execution(&self.scoped_execution(&native)?)?;
                    }
                }
                "fence_source" => {
                    let ready = input.check(
                        input.request.ready.as_ref(),
                        "prepare_target",
                        &input.ticket().target,
                    )?;
                    if result["details"]["ready_proof"] != ready {
                        return Err(fenced("target ready proof changed on source fence replay"));
                    }
                }
                "resume_source" => abort_receipt(&input)?,
                _ => (),
            }
            return Ok(result);
        }
        let (phase, decision) =
            state(&self.catalog, &input)?.unwrap_or_else(|| ("new".into(), None));
        match (step, phase.as_str()) {
            ("inspect_source", "new") => inspect(&mut self.catalog, &input, &self.boot),
            ("preflight_target", "new") => {
                preflight(&mut self.catalog, &input, &self.boot, &self.network)
            }
            ("hold_source", "new" | "reserved") => hold_source(
                &mut self.catalog,
                &self.objects,
                &self.boot,
                &input,
                &self.network,
            ),
            ("prepare_target", "new" | "reserved" | "importing" | "imported") => {
                let verify = |catalog: &Catalog, execution: &Execution| {
                    Self::verify_live_execution_at(catalog, &self.boot, &self.executions, execution)
                };
                prepare_target(
                    &mut self.catalog,
                    &self.objects,
                    self.statepoints.directory(),
                    &self.boot,
                    &input,
                    request,
                    descriptors,
                    &mut self.network,
                    &self.activation,
                    verify,
                )
            }
            ("fence_source", "held") => source_fence(
                &mut self.catalog,
                &self.objects,
                &input,
                &self.boot,
                &self.network,
            ),
            ("activate_target", "prepared") => {
                require_local(
                    &self.catalog,
                    &input,
                    "prepare_target",
                    input.request.ready.as_ref(),
                )?;
                validate_boot_intent(&self.catalog, &input)?;
                let transfer = requested_transfer(&input);
                let source_fence = transfer
                    .as_ref()
                    .map(|transfer| source_overlay_fence(&input, transfer))
                    .transpose()?
                    .flatten();
                record_decision(&self.catalog, &input, decision.as_deref())?;
                let mut published = None;
                if let Some(transfer) = transfer.as_ref() {
                    let owner =
                        OwnerDecision::migration(transfer, input.ticket().target.owner_epoch);
                    if input.ticket().mode == "cold" {
                        if network_transfer::awaiting_owner(&self.catalog, &input.op())?
                            && transfer.network_mode == "native"
                        {
                            network_transfer::authorize_overlay_commit(
                                self.network.overlay(),
                                transfer,
                                source_fence.as_ref(),
                            )?;
                        }
                        network_transfer::authorize_cold(
                            &self.catalog,
                            &input.op(),
                            transfer,
                            &owner,
                        )?;
                    } else {
                        let native = input.native(input.endpoint().execution.clone(), json!({}))
                            .derived("CommitTransfer",json!({"transfer":transfer,"owner_decision":owner,"source_fence":source_fence}));
                        let execution = self.scoped_execution(&native)?;
                        let verify = || {
                            Self::verify_live_execution_at(
                                &self.catalog,
                                &self.boot,
                                &self.executions,
                                &execution,
                            )
                        };
                        verify()?;
                        let receipt = network_transfer::handle(
                            &self.catalog,
                            &execution,
                            &native,
                            &mut self.network,
                            &self.activation,
                            verify,
                        )?;
                        if !receipt.published {
                            return Err(pending("committed target TAP publication is in progress"));
                        }
                        published = Some(receipt);
                    }
                }
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
                if let Some(transfer) = transfer.as_ref().filter(|_| input.ticket().mode == "cold")
                {
                    published = Some(network_transfer::observe_cold(
                        &self.catalog,
                        &input.op(),
                        transfer,
                        &execution,
                    )?);
                }
                let product_volumes =
                    products::observations(&self.catalog, &native, &input.ticket().id)?;
                remember(
                    &mut self.catalog,
                    &input,
                    "active",
                    json!({"details":{"product_volumes":product_volumes,"network_published":published,
                        "boot_environment":op.boot_environment}}),
                )
            }
            ("abort_target", "reserved" | "importing" | "imported" | "prepared" | "aborting")
                if decision.is_none() =>
            {
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
                        abort_target_tap(&self.catalog, &mut self.network, &input)?;
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
                abort_target_tap(&self.catalog, &mut self.network, &input)?;
                let prepared = previous(&self.catalog, &input, "prepare_target")?;
                let aborted = if prepared
                    .as_ref()
                    .is_some_and(|receipt| !receipt["details"]["network_prepared"].is_null())
                {
                    Some(network_transfer::abort_migration(
                        &self.catalog,
                        &requested_transfer(&input).unwrap(),
                        &input.op(),
                    )?)
                } else {
                    None
                };
                seal_aborted_target_heads(&mut self.catalog, &self.objects, &input)?;
                products::remove_aborted_target(&self.catalog, &input.ticket().id)?;
                release_import(
                    &mut self.catalog,
                    &self.objects,
                    self.statepoints.directory(),
                    &input,
                )?;
                remember(
                    &mut self.catalog,
                    &input,
                    "aborted",
                    json!({"details":{
                    "writer_closed":true,"tap_closed":true,"relay_closed":true,"network_aborted":aborted}}),
                )
            }
            ("resume_source", "reserved" | "held" | "fenced" | "resuming")
                if decision.is_none() =>
            {
                abort_receipt(&input)?;
                self.catalog.db.execute(
                    "UPDATE machine_migrations SET state='resuming' WHERE migration_id=?",
                    [&input.ticket().id],
                )?;
                match self.catalog.operation(&input.op()) {
                    Ok(operation)
                        if operation.phase == "NEW" && operation.kind == "migration_copy" =>
                    {
                        finish_stopped_source(&mut self.catalog, &self.objects, &input)?;
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
                let reopened = if input.endpoint().execution.incarnation_id.is_some() {
                    let native = input.native(input.endpoint().execution.clone(), json!({}));
                    let execution = self.scoped_execution(&native)?;
                    self.verify_live_execution(&execution)?;
                    let reopened =
                        reopen_source_tap(&self.catalog, &input, &self.network, &execution)?;
                    self.verify_live_execution(&execution)?;
                    reopened
                } else {
                    let (execution, plan) = source_plan(&self.catalog, &input)?;
                    expected_source_attachment(&self.catalog, &input, &execution, &plan)?;
                    None
                };
                remember(
                    &mut self.catalog,
                    &input,
                    "resumed",
                    json!({"details":{"reopened_attachment":reopened}}),
                )
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
                    finish_stopped_source(&mut self.catalog, &self.objects, &input)?;
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
                self.catalog.db.execute("UPDATE root_refs SET state='dropped',revision=revision+1
                    WHERE owner_kind='statepoint_hibernate' AND owner_id=? AND resource_id=? AND state='active'",
                    params![record.point.capture_id,record.point.representation_id])?;
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
                release_import(
                    &mut self.catalog,
                    &self.objects,
                    self.statepoints.directory(),
                    &input,
                )?;
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

// A migrated cold launch can have a captured root layered on top of the
// original installed base. Later managed starts must preserve that root slot.
pub(crate) fn has_committed_target(catalog: &Catalog, operation: &str) -> Result<bool> {
    Ok(catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='target'
         AND native_operation_id=? AND decision_json IS NOT NULL AND state IN ('active','complete'))",
        [operation], |row| row.get(0))?)
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
    if operation.kind == "launch"
        && network_transfer::awaiting_owner(catalog, &operation.operation_id)?
    {
        return Err(fenced(
            "migration target TAP does not have the committed owner decision",
        ));
    }
    Ok(())
}

pub(crate) fn permit_target_abort(catalog: &Catalog, operation: &str) -> Result<()> {
    let committed: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM machine_migrations WHERE side='target'
         AND native_operation_id=? AND decision_json IS NOT NULL)",
        [operation],
        |r| r.get(0),
    )?;
    if committed {
        return Err(fenced("a committed target cannot be aborted"));
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

fn finish_stopped_source(catalog: &mut Catalog, objects: &File, input: &Input) -> Result<()> {
    let operation = catalog.operation(&input.op())?;
    if operation.phase == "NEW" {
        let staged: Vec<String> = {
            let mut query = catalog.db.prepare(
                "SELECT spec_json FROM managed_blocks WHERE operation_id=? AND backing_identity IS NULL")?;
            let rows = query.query_map([&operation.operation_id], |row| row.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for raw in staged {
            let spec =
                serde_json::from_str(&raw).map_err(|error| Fault::invalid(error.to_string()))?;
            crate::blocks::discard_staged(objects, &operation.operation_id, &spec)?;
        }
        catalog.db.execute(
            "DELETE FROM managed_blocks WHERE operation_id=? AND backing_identity IS NULL",
            [&operation.operation_id],
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(side: &str, epoch: i64) -> Endpoint {
        let local = if side == "source" {
            "1".repeat(32)
        } else {
            "2".repeat(32)
        };
        let name = format!("machine-{side}");
        Endpoint {
            worker_id: side.into(),
            runtime_instance_id: format!("runtime-{side}"),
            local_instance_id: local.clone(),
            runtime_name: name.clone(),
            bundle_id: "bundle".into(),
            bundle_digest: digest(b"bundle"),
            reader_id: "reader".into(),
            binding_id: format!("binding-{side}"),
            binding_incarnation_id: String::new(),
            generation: epoch,
            owner_epoch: epoch,
            execution: Expected {
                instance_id: managed::machine_id(&local, &name),
                incarnation_id: Some(managed::key(&native_id("migration-one", side), "vmm", 0)),
                execution_epoch: 1,
            },
        }
    }

    fn input(step: &str) -> Input {
        Input {
            request: Step {
                ticket: Ticket {
                    id: "migration-one".into(),
                    machine_id: "machine".into(),
                    mode: "cold".into(),
                    source: endpoint("source", 1),
                    target: endpoint("target", 2),
                },
                step: step.into(),
                hold: None,
                ready: None,
                fence: None,
                abort: None,
                decision: None,
                network: None,
                boot_environment: None,
            },
            ticket_digest: digest(b"matching controller ticket"),
            bundle_manifest: Value::Null,
            import: None,
        }
    }

    #[test]
    fn target_tombstone_blocks_delayed_prepare_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.sqlite");
        let mut catalog = Catalog::open(&path, "boot", "serve").unwrap();
        let abort = input("abort_target");
        reserve(&catalog, &abort).unwrap();
        let proof = remember(&mut catalog, &abort, "aborted", json!({})).unwrap();
        drop(catalog);
        let catalog = Catalog::open(&path, "boot", "restart").unwrap();
        let prepare = input("prepare_target");
        assert_eq!(state(&catalog, &prepare).unwrap().unwrap().0, "aborted");
        assert_eq!(
            previous(&catalog, &abort, "abort_target").unwrap(),
            Some(proof)
        );
        assert!(requires_owner(&catalog, &abort.op()).unwrap());
    }

    #[test]
    fn source_never_reacquires_writer_after_committed_retirement() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.sqlite");
        let mut catalog = Catalog::open(&path, "boot", "serve").unwrap();
        let source = input("finalize_source");
        reserve(&catalog, &source).unwrap();
        remember(&mut catalog, &source, "complete", json!({})).unwrap();
        drop(catalog);
        let catalog = Catalog::open(&path, "boot", "restart").unwrap();
        assert_eq!(
            guard_operation(
                &catalog.db,
                "deep",
                &source.endpoint().execution.instance_id,
                "old-wake"
            )
            .unwrap_err()
            .code,
            "E_FENCE_UNPROVEN"
        );
        assert!(guard_operation(
            &catalog.db,
            "deep",
            &source.ticket().target.execution.instance_id,
            "new-wake"
        )
        .is_ok());
    }

    #[test]
    fn owner_decision_requires_the_exact_ready_and_source_fence() {
        let mut activate = input("activate_target");
        let fence = make_receipt(
            &input("fence_source"),
            json!({"manifest_digest":digest(b"final-cut")}),
        )
        .unwrap();
        let ready = make_receipt(
            &input("prepare_target"),
            json!({"manifest_digest":digest(b"final-cut")}),
        )
        .unwrap();
        activate.request.fence = Some(fence.clone());
        activate.request.ready = Some(ready.clone());
        activate.request.decision = Some(Decision {
            migration_id: activate.ticket().id.clone(),
            ticket_digest: activate.ticket_digest.clone(),
            source: activate.ticket().source.clone(),
            target: activate.ticket().target.clone(),
            source_fence_proof: fence["proof"].as_str().unwrap().into(),
            target_ready_proof: ready["proof"].as_str().unwrap().into(),
        });
        assert!(activate.decision().is_ok());
        activate.request.fence.as_mut().unwrap()["execution"]["execution_epoch"] = json!(2);
        assert_eq!(activate.decision().unwrap_err().code, "E_FENCE_UNPROVEN");
    }
}
