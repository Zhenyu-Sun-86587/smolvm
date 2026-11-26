//! Worker-owned live changes to the current managed execution.
mod observations;
pub(crate) mod pressure_hint;

use self::observations::{Balloon, Cpus, Ram, MIB};
use crate::{
    catalog::{Catalog, Execution, Operation},
    ipc::{Fault, Request, Result},
    managed::Machine,
    native_control::Endpoint,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use smolvm_protocol::{
    AgentRequest, OFFLINE_CPU_SHRINK_CAPABILITY, ONLINE_CPU_GROWTH_CAPABILITY,
    ONLINE_MEMORY_GROWTH_CAPABILITY,
};
use std::thread::{self, JoinHandle};

pub(crate) const KIND: &str = "resize_resources";
const BALLOON_WAIT_MS: i64 = 12_000;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "change", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Change {
    CpuOnline { cpus: u8 },
    CpuOffline { cpus: u8 },
    MemoryGrow { memory_mib: u32 },
    Balloon { target_mib: u32 },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Intent {
    change: Change,
    hot: bool,
    cpus: Cpus,
    ram: Option<Ram>,
    balloon: Option<Balloon>,
    memory_current_before: Option<u64>,
}

fn unsupported(detail: &str) -> Fault {
    Fault::new("E_CAPABILITY_UNSUPPORTED", detail)
}

fn pending(detail: &str) -> Fault {
    Fault::new("E_NATIVE_RESIZE_PENDING", detail)
}

fn invalid(detail: impl ToString) -> Fault {
    Fault::invalid(detail.to_string())
}

fn resources(
    catalog: &Catalog,
    boot: &str,
    request: &Request,
) -> Result<(Execution, Endpoint, Machine, Option<String>)> {
    let (route, bundle, expected) = request.scope()?;
    let incarnation = expected
        .incarnation_id
        .as_deref()
        .ok_or_else(|| unsupported("live resources require a current managed execution"))?;
    let bound = catalog.query_binding(
        &request.derived("QueryBinding", json!({"instance_id":expected.instance_id})),
    )?;
    if route != "deep"
        || bound["incarnation_id"].as_str() != Some(incarnation)
        || bound["execution_epoch"].as_i64() != Some(expected.execution_epoch)
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "live resource binding changed",
        ));
    }
    let execution = catalog.execution(incarnation)?;
    if !execution.matches(route, bundle, expected) || execution.phase != "registered" {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "live resource execution changed",
        ));
    }
    let launch = catalog.operation(&execution.last_operation_id)?;
    let plan = crate::managed::plan(catalog, &launch)?
        .filter(|_| launch.phase == "COMPLETED")
        .ok_or_else(|| unsupported("live resources require a completed managed launch"))?;
    let endpoint = Endpoint::load(&catalog.db, incarnation, boot)?;
    Ok((
        execution,
        endpoint,
        plan.machine,
        bound["active_operation_id"].as_str().map(str::to_owned),
    ))
}

pub(crate) fn query(catalog: &Catalog, boot: &str, request: &Request) -> Result<Value> {
    let (execution, endpoint, machine, active) = resources(catalog, boot, request)?;
    let inventory = endpoint.inventory()?;
    let running = inventory.source_disposition == "RUNNING";
    let guest = running
        .then(|| observations::capabilities(&endpoint).ok())
        .flatten();
    let has_guest = |want: &str| {
        guest
            .as_ref()
            .is_some_and(|set| set.iter().any(|entry| entry == want))
    };
    let cpus = if machine.live_compute_growth {
        running
            .then(|| observations::cpus(&endpoint).ok())
            .flatten()
    } else {
        Some(Cpus {
            created: machine.cpus,
            capacity: machine.cpus,
        })
    };
    let ram = (running && machine.live_compute_growth)
        .then(|| observations::ram(&endpoint).ok())
        .flatten();
    let online_cpu_ids = cpus
        .filter(|_| guest.is_some())
        .and_then(|shape| observations::online_cpu_ids(&endpoint, shape.created).ok());
    let balloon = running
        .then(|| observations::balloon(&endpoint).ok())
        .flatten();
    let balloon_installed = inventory
        .devices
        .iter()
        .any(|device| device["virtio_type"] == 5);
    let shrink = running
        && endpoint
            .command("CPU_SHRINK_CAPABILITIES")
            .is_ok_and(|r| r == "preserved-offline-cpu-slots-v1");
    let capability = |supported: bool, ready: bool, unavailable: &str| {
        let reason = if !supported {
            Some(unavailable)
        } else if !running {
            Some("execution is held")
        } else if active.is_some() {
            Some("another native operation owns the execution")
        } else if !ready {
            Some(unavailable)
        } else {
            None
        };
        json!({"supported":supported,"available_now":reason.is_none(),"reason":reason})
    };
    let secondary = machine.live_compute_growth || machine.cpus > 1;
    let current = active
        .as_deref()
        .map(|id| progress(&catalog.db, id))
        .transpose()?
        .flatten();
    let online: Option<u8> = catalog.db.query_row(
        "SELECT json_extract(r.observed_json,'$.online_cpus')
         FROM native_resource_changes r JOIN operations o USING(operation_id)
         WHERE o.expected_incarnation_id=? AND r.stage='completed' AND json_type(r.observed_json,'$.online_cpus')='integer'
         ORDER BY r.rowid DESC LIMIT 1",
        [&execution.incarnation_id], |row| row.get(0),
    ).optional()?;
    Ok(json!({
        "instance_id":execution.instance_id,
        "incarnation_id":execution.incarnation_id,
        "execution_epoch":execution.execution_epoch,
        "profile": if machine.live_compute_growth {"live-compute"} else {"parked-capture"},
        "capture_compatible":!machine.live_compute_growth,
        "capabilities":{
            "cpu_online": capability(secondary,has_guest(ONLINE_CPU_GROWTH_CAPABILITY),"no compatible Guest CPU online method or secondary CPU slots"),
            "cpu_offline": capability(secondary,cpus.is_some_and(|shape|shape.created > 1) && shrink && has_guest(OFFLINE_CPU_SHRINK_CAPABILITY),"no compatible Guest CPU offline method or secondary CPU slots"),
            "cpu_grow": capability(machine.live_compute_growth,
                cpus.is_some_and(|shape| shape.capacity>shape.created) && has_guest(ONLINE_CPU_GROWTH_CAPABILITY),
                if machine.live_compute_growth {"CPU growth capacity or Guest management is unavailable"} else {"the parked capture profile has no hot-add CPU topology"}),
            "memory_grow": capability(machine.live_compute_growth,
                ram.is_some_and(|shape| shape.driver && shape.mapped < shape.capacity) && has_guest(ONLINE_MEMORY_GROWTH_CAPABILITY),
                if machine.live_compute_growth {"RAM hot-add driver or Guest management is unavailable"} else {"the parked capture profile has no RAM hot-add device"}),
            "balloon": capability(balloon_installed, balloon.is_some(),"VMM balloon observation unavailable"),
        },
        "observed":{"cpus":cpus,"online_cpus":online_cpu_ids.as_ref().map(Vec::len),"online_cpu_ids":online_cpu_ids,
                    "last_confirmed_online_cpus":online_cpu_ids.as_ref().map(Vec::len).or(online.map(usize::from)),"ram":ram,"balloon":balloon,
                    "scope_memory_current_bytes":observations::memory_current(&execution).ok()},
        "pending":current,
    }))
}

fn require_guest(endpoint: &Endpoint, name: &str) -> Result<()> {
    if !observations::capabilities(endpoint)?
        .iter()
        .any(|entry| entry == name)
    {
        return Err(unsupported(
            "the running Guest Agent does not support the requested live resource change",
        ));
    }
    Ok(())
}

fn ram_target(ram: Ram, memory_mib: u32) -> Result<u64> {
    let target = memory_mib
        .checked_sub(ram.boot_mib)
        .map(|v| u64::from(v) * MIB)
        .ok_or_else(|| invalid("RAM cannot shrink below the boot capacity"))?;
    if target < ram.mapped || target > ram.capacity || !target.is_multiple_of(128 * MIB) {
        return Err(invalid(
            "RAM grows in 128 MiB increments within its VMM capacity",
        ));
    }
    Ok(target)
}

pub(crate) fn submit(catalog: &mut Catalog, boot: &str, request: &Request) -> Result<Operation> {
    let (id, _) = request.operation()?;
    let change: Change = request.payload()?;
    if let Some(old) = intent(&catalog.db, id)? {
        if old.change != change {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "native resize parameters changed",
            ));
        }
        return catalog.begin(request, KIND);
    }
    let (execution, endpoint, machine, active) = resources(catalog, boot, request)?;
    if active.is_some() || endpoint.inventory()?.source_disposition != "RUNNING" {
        return Err(Fault::new(
            "E_STATE_CONFLICT",
            "native resize requires an unheld running execution",
        ));
    }
    let cpus = if machine.live_compute_growth {
        observations::cpus(&endpoint)?
    } else {
        Cpus {
            created: machine.cpus,
            capacity: machine.cpus,
        }
    };
    let (mut cpu_budget, mut memory_budget) = (0, 0);
    let mut intent = Intent {
        change,
        hot: machine.live_compute_growth,
        cpus,
        ram: None,
        balloon: None,
        memory_current_before: None,
    };
    match intent.change {
        Change::CpuOnline { cpus: target } => {
            if target == 0 {
                return Err(invalid("a CPU resize must retain CPU0"));
            }
            if target > cpus.capacity {
                return Err(unsupported(
                    "the target exceeds this execution's created or hot-add CPU slots",
                ));
            }
            require_guest(&endpoint, ONLINE_CPU_GROWTH_CAPABILITY)?;
            cpu_budget = u64::from(target.max(cpus.created));
        }
        Change::CpuOffline { cpus: target } => {
            if target == 0 || target >= cpus.created {
                return Err(invalid(
                    "offline shrink must keep CPU0 and use fewer than the created CPU slots",
                ));
            }
            if endpoint.command("CPU_SHRINK_CAPABILITIES")? != "preserved-offline-cpu-slots-v1" {
                return Err(unsupported("the VMM cannot preserve offlined CPU slots"));
            }
            require_guest(&endpoint, OFFLINE_CPU_SHRINK_CAPABILITY)?;
        }
        Change::MemoryGrow { memory_mib } => {
            if !machine.live_compute_growth {
                return Err(unsupported(
                    "the parked capture profile has no RAM hot-add device",
                ));
            }
            require_guest(&endpoint, ONLINE_MEMORY_GROWTH_CAPABILITY)?;
            let ram = observations::ram(&endpoint)?;
            if !ram.driver {
                return Err(unsupported(
                    "the Guest has not taken the RAM hot-add device",
                ));
            }
            let target = ram_target(ram, memory_mib)?;
            observations::check_memory_budget(&execution, memory_mib, target - ram.mapped)?;
            memory_budget = u64::from(memory_mib);
            intent.ram = Some(ram);
        }
        Change::Balloon { target_mib } => {
            let previous = observations::balloon(&endpoint)?;
            if previous.target_mib != previous.actual_mib {
                return Err(pending("a previous balloon target has not settled"));
            }
            let current_mib = if machine.live_compute_growth {
                let ram = observations::ram(&endpoint)?;
                u64::from(ram.boot_mib) + ram.plugged / MIB
            } else {
                u64::from(machine.memory_mib)
            };
            if u64::from(target_mib) >= current_mib || target_mib > u32::MAX / 256 {
                return Err(invalid("balloon target must fit within active Guest RAM"));
            }
            intent.balloon = Some(previous);
            intent.memory_current_before = observations::memory_current(&execution).ok();
        }
    }
    let data = serde_json::to_string(&intent).map_err(invalid)?;
    catalog.begin_with(request, KIND, |tx| {
        crate::admission::reserve_live_growth(tx, &execution, cpu_budget, memory_budget)?;
        tx.execute(
            "INSERT INTO native_resource_changes(operation_id,intent_json,stage,deadline_ms)VALUES(?,?,'queued',?)",
            params![id,data,crate::lifecycle_controller::monotonic()?.saturating_add(BALLOON_WAIT_MS)],
        )?;
        Ok(())
    })
}

fn intent(db: &Connection, id: &str) -> Result<Option<Intent>> {
    let stored: Option<String> = db
        .query_row(
            "SELECT intent_json FROM native_resource_changes WHERE operation_id=?",
            [id],
            |row| row.get(0),
        )
        .optional()?;
    stored
        .map(|spec| serde_json::from_str(&spec).map_err(invalid))
        .transpose()
}

pub(crate) fn progress(db: &Connection, id: &str) -> Result<Option<Value>> {
    let Some(intent) = intent(db, id)? else {
        return Ok(None);
    };
    let values: (String, String, Option<String>, Option<String>) = db.query_row(
        "SELECT stage,observed_json,error_code,error FROM native_resource_changes WHERE operation_id=?",
        [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    )?;
    Ok(Some(
        json!({"operation_id":id,"change":intent.change,"stage":values.0,
        "observed":serde_json::from_str::<Value>(&values.1).map_err(invalid)?,
        "error_code":values.2,"error":values.3}),
    ))
}

struct Update {
    stage: &'static str,
    observed: Option<Value>,
    error: Option<Fault>,
}

impl Update {
    fn ok(stage: &'static str, observed: Value) -> Self {
        Self {
            stage,
            observed: Some(observed),
            error: None,
        }
    }

    fn failed(stage: &'static str, observed: Option<Value>, error: Fault) -> Self {
        Self {
            stage,
            observed,
            error: Some(error),
        }
    }
}

fn apply_change(
    endpoint: &Endpoint,
    execution: &Execution,
    intent: &Intent,
    deadline: i64,
    restoring: bool,
) -> Result<Update> {
    if endpoint.inventory()?.source_disposition != "RUNNING" {
        return Err(pending(
            "waiting for the originating execution to be running",
        ));
    }
    match intent.change {
        Change::CpuOnline { cpus: target } | Change::CpuOffline { cpus: target } => {
            let offline = matches!(intent.change, Change::CpuOffline { .. });
            let mut cpus = if intent.hot {
                observations::cpus(endpoint)?
            } else {
                intent.cpus
            };
            if !offline && cpus.created < target {
                endpoint.command_with_timeout(
                    &format!("PROTOTYPE_GROW_CPUS {target}"),
                    std::time::Duration::from_secs(10),
                )?;
                cpus = observations::cpus(endpoint)?;
            }
            if cpus.created < target || cpus.capacity != intent.cpus.capacity {
                return Err(pending(
                    "VMM CPU geometry has not reached the requested slots",
                ));
            }
            let request = if offline {
                AgentRequest::OfflineCpus {
                    target_count: target,
                }
            } else {
                AgentRequest::OnlineCpus {
                    target_count: target,
                }
            };
            if let Err(error) = observations::guest_complete(
                endpoint,
                &request,
                &[("online_cpus", u64::from(target))],
            ) {
                return Ok(Update::failed("waiting", Some(json!({"cpus":cpus})), error));
            }
            let online = observations::online_cpu_ids(endpoint, cpus.created)?;
            if online.iter().copied().ne(0..target) {
                return Ok(Update::failed(
                    "waiting",
                    Some(json!({"cpus":cpus,"online_cpu_ids":online})),
                    pending("Guest online CPU set still differs from the requested set"),
                ));
            }
            Ok(Update::ok("completed",
                json!({"cpus":cpus,"online_cpus":target,"online_cpu_ids":online})))
        }
        Change::MemoryGrow { memory_mib } => {
            let original = intent
                .ram
                .ok_or_else(|| invalid("missing admitted RAM geometry"))?;
            let current = observations::ram(endpoint)?;
            if current.base != original.base
                || current.boot_mib != original.boot_mib
                || current.capacity != original.capacity
                || !current.driver
            {
                return Err(pending(
                    "RAM geometry or Guest driver differs from the admitted operation",
                ));
            }
            let target = ram_target(current, memory_mib)?;
            if target > current.mapped {
                observations::check_memory_budget(execution, memory_mib, target - current.mapped)?;
                endpoint.command_with_timeout(
                    &format!("PROTOTYPE_GROW_MEMORY {}", target / MIB),
                    std::time::Duration::from_secs(10),
                )?;
            }
            let mapped = observations::ram(endpoint)?;
            if mapped.mapped != target {
                return Err(pending("VMM has not registered the requested RAM range"));
            }
            if target == 0 {
                return Ok(Update::ok(
                    "completed",
                    json!({"memory_mib":memory_mib,"ram":mapped}),
                ));
            }
            if let Err(error) = observations::guest_complete(
                endpoint,
                &AgentRequest::OnlineMemory {
                    start_address: original.base,
                    length_bytes: target,
                },
                &[("start_address", original.base), ("online_bytes", target)],
            ) {
                return Ok(Update::failed(
                    "waiting",
                    Some(json!({"ram":mapped})),
                    error,
                ));
            }
            let plugged = observations::ram(endpoint)?;
            if plugged.plugged != target
                || plugged.mapped != target
                || plugged.base != original.base
            {
                return Ok(Update::failed(
                    "waiting",
                    Some(json!({"ram":plugged})),
                    pending("Guest RAM plugging is incomplete"),
                ));
            }
            Ok(Update::ok(
                "completed",
                json!({"memory_mib":memory_mib,"ram":plugged}),
            ))
        }
        Change::Balloon { target_mib } => {
            let original = intent
                .balloon
                .ok_or_else(|| invalid("missing admitted balloon state"))?;
            let current = observations::balloon(endpoint)?;
            let now = crate::lifecycle_controller::monotonic()?;
            if !restoring && current.target_mib == target_mib && current.actual_mib == target_mib {
                return Ok(Update::ok(
                    "completed",
                    balloon_sample(execution, intent, current),
                ));
            }
            if !restoring && now < deadline {
                if current.target_mib != target_mib {
                    endpoint.command(&format!("BALLOON {target_mib}"))?;
                }
                return Ok(Update::ok(
                    "waiting",
                    balloon_sample(execution, intent, observations::balloon(endpoint)?),
                ));
            }
            // Persist the recovery choice before reverting the target so a
            // crash can only continue that recovery, never report it applied.
            if !restoring {
                return Ok(Update::failed(
                    "restoring",
                    Some(balloon_sample(execution, intent, current)),
                    Fault::new(
                        "E_BALLOON_UNRESPONSIVE",
                        "Guest balloon did not reach the requested target",
                    ),
                ));
            }
            if current.target_mib != original.target_mib {
                endpoint.command(&format!("BALLOON {}", original.target_mib))?;
            }
            let recovered = observations::balloon(endpoint)?;
            if recovered.target_mib == original.target_mib
                && recovered.actual_mib == original.actual_mib
            {
                return Ok(Update::failed(
                    "aborted",
                    Some(balloon_sample(execution, intent, recovered)),
                    Fault::new(
                        "E_BALLOON_UNRESPONSIVE",
                        "Guest balloon did not respond and the previous target was restored",
                    ),
                ));
            }
            Ok(Update::failed(
                "restoring",
                Some(balloon_sample(execution, intent, recovered)),
                Fault::new(
                    "E_BALLOON_UNRESPONSIVE",
                    "waiting for the Guest balloon to return to the previous target",
                ),
            ))
        }
    }
}

fn balloon_sample(execution: &Execution, intent: &Intent, state: Balloon) -> Value {
    json!({"balloon":state,"scope_memory_before_bytes":intent.memory_current_before,
        "scope_memory_current_bytes":observations::memory_current(execution).ok()})
}

#[derive(Default)]
pub(crate) struct Controller {
    active: Option<(String, JoinHandle<Result<Update>>)>,
}

impl Controller {
    pub(crate) fn tick(&mut self, catalog: &mut Catalog, boot: &str) -> Result<()> {
        if self
            .active
            .as_ref()
            .is_some_and(|(_, worker)| worker.is_finished())
        {
            let (id, worker) = self.active.take().expect("finished resize");
            let update = worker.join().unwrap_or_else(|_| {
                Err(pending(
                    "native resize worker exited before returning evidence",
                ))
            });
            commit_update(catalog, &id, update)?;
        }
        if self.active.is_some() {
            return Ok(());
        }
        let item: Option<(String,String,String,i64)> = catalog.db.query_row(
            "SELECT o.operation_id,e.incarnation_id,r.stage,r.deadline_ms
             FROM native_resource_changes r JOIN operations o USING(operation_id)
             JOIN executions e ON e.incarnation_id=o.expected_incarnation_id
             JOIN instance_bindings b ON b.active_operation_id=o.operation_id AND b.incarnation_id=e.incarnation_id
             WHERE o.phase='NEW' AND r.next_ms<=? AND e.phase='registered' AND e.host_boot_id=?
             ORDER BY r.next_ms,r.rowid LIMIT 1",
            params![crate::lifecycle_controller::monotonic()?,boot],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        let Some((id, incarnation, stage, deadline)) = item else {
            return Ok(());
        };
        let execution = catalog.execution(&incarnation)?;
        let endpoint = Endpoint::load(&catalog.db, &incarnation, boot)?;
        let intent =
            intent(&catalog.db, &id)?.ok_or_else(|| invalid("missing native resize intent"))?;
        let handle = thread::Builder::new()
            .name("native-resource-change".into())
            .spawn(move || {
                apply_change(
                    &endpoint,
                    &execution,
                    &intent,
                    deadline,
                    stage == "restoring",
                )
            })
            .map_err(invalid)?;
        self.active = Some((id, handle));
        Ok(())
    }
}

fn commit_update(catalog: &mut Catalog, id: &str, update: Result<Update>) -> Result<()> {
    let tx = catalog.db.transaction()?;
    let stage:Option<String>=tx.query_row(
        "SELECT r.stage FROM native_resource_changes r JOIN operations o USING(operation_id)
         JOIN instance_bindings b ON b.active_operation_id=o.operation_id AND b.incarnation_id=o.expected_incarnation_id
         WHERE o.operation_id=? AND o.phase='NEW' AND b.execution_epoch=o.expected_execution_epoch",
        [id],|r|r.get(0)
    ).optional()?;
    let Some(stage) = stage else { return Ok(()) };
    let outcome = update.unwrap_or_else(|fault| {
        Update::failed(
            if stage == "restoring" {
                "restoring"
            } else {
                "waiting"
            },
            None,
            fault,
        )
    });
    let data = outcome
        .observed
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(invalid)?;
    tx.execute(
        "UPDATE native_resource_changes SET stage=?,observed_json=coalesce(?,observed_json),error_code=?,error=?,next_ms=? WHERE operation_id=?",
        params![outcome.stage,data,outcome.error.as_ref().map(|f|f.code),outcome.error.as_ref().map(|f|&f.message),
                crate::lifecycle_controller::monotonic()?.saturating_add(1_000),id],
    )?;
    if matches!(outcome.stage, "completed" | "aborted") {
        if outcome.stage == "completed" {
            tx.execute(
                "UPDATE managed_launches SET
                   vcpus=coalesce(json_extract(?1,'$.cpus.created'),vcpus),
                   memory_mib=coalesce(json_extract(?1,'$.memory_mib'),memory_mib)
                 WHERE incarnation_id=(SELECT expected_incarnation_id FROM operations WHERE operation_id=?2)",
                params![data,id],
            )?;
        }
        finish(&tx, id, outcome.stage == "aborted")?;
    }
    tx.commit()?;
    Ok(())
}

fn finish(tx: &Transaction<'_>, id: &str, aborted: bool) -> Result<()> {
    tx.execute(
        "UPDATE operations SET phase=?,decision=?,revision=revision+1 WHERE operation_id=? AND phase='NEW'",
        params![if aborted {"ABORTED"} else {"COMPLETED"},if aborted {"ABORT"} else {"NONE"},id],
    )?;
    tx.execute(
        "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
        [id],
    )?;
    Ok(())
}

pub(crate) fn execution_exited(tx: &Transaction<'_>, incarnation: &str) -> Result<()> {
    let id:Option<String>=tx.query_row(
        "SELECT o.operation_id FROM operations o JOIN native_resource_changes r USING(operation_id)
         WHERE o.expected_incarnation_id=? AND o.phase='NEW'",
        [incarnation],|r|r.get(0)
    ).optional()?;
    if let Some(id) = id {
        tx.execute("UPDATE native_resource_changes SET stage='aborted',error_code='E_EXECUTION_EXITED',
                    error='the original execution exited before the live change was confirmed' WHERE operation_id=?",[&id])?;
        finish(tx, &id, true)?;
    }
    Ok(())
}
