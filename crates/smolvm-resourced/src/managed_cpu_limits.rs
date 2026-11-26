//! Authoritative bandwidth of a Worker-managed execution's own systemd scope.

use super::{pid_exited, pid_start, stale_execution, Worker};
use crate::catalog::{Catalog, Execution, Operation};
use crate::ipc::{Fault, Request, Result};
use crate::worker_scope;
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use smolvm_runtime_protocol::{cpu_quota, managed_scope_name};
use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

const KIND: &str = "managed_cpu_limit";
const REJECTED: &str = "E_CPU_QUOTA_REJECTED";
const UNCERTAIN: &str = "E_CPU_QUOTA_UNCERTAIN";
const UNAVAILABLE: &str = "E_CPU_QUOTA_UNAVAILABLE";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    millicpus: Value,
}

fn request_millicpus(request: &Request) -> Result<Option<u32>> {
    let input: Input = request.payload()?;
    if input.millicpus.is_null() {
        return Ok(None);
    }
    input
        .millicpus
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .map(Some)
        .ok_or_else(|| Fault::invalid("millicpus must be a positive u32 or null"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bandwidth {
    quota_usec: Option<i64>,
    period_usec: i64,
}

impl Bandwidth {
    fn parse(raw: &str) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid cpu.max response");
        let mut fields = raw.split_whitespace();
        let quota_usec = match fields.next().ok_or_else(invalid)? {
            "max" => None,
            value => Some(
                value
                    .parse::<i64>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(invalid)?,
            ),
        };
        let period_usec = fields
            .next()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|n| (1_000..=1_000_000).contains(n))
            .ok_or_else(invalid)?;
        if fields.next().is_some() {
            return Err(invalid());
        }
        Ok(Self {
            quota_usec,
            period_usec,
        })
    }

    fn matches(self, millicpus: u64) -> bool {
        self.quota_usec.is_some_and(|quota| {
            i128::from(quota) * 1_000 == i128::from(millicpus) * i128::from(self.period_usec)
        })
    }
}

#[derive(Serialize)]
struct Receipt<'a> {
    instance_id: &'a str,
    incarnation_id: &'a str,
    execution_epoch: i64,
    requested_millicpus: Option<u32>,
    quota_usec: Option<i64>,
    period_usec: i64,
}

fn receipt(
    instance_id: &str,
    incarnation_id: &str,
    execution_epoch: i64,
    requested_millicpus: Option<u32>,
    actual: Bandwidth,
) -> Value {
    json!(Receipt {
        instance_id,
        incarnation_id,
        execution_epoch,
        requested_millicpus,
        quota_usec: actual.quota_usec,
        period_usec: actual.period_usec,
    })
}

struct ManagedScope {
    serve: String,
    machine: String,
    vcpus: u32,
}

impl ManagedScope {
    fn from_launch(catalog: &Catalog, operation_id: &str) -> Result<Option<Self>> {
        Ok(catalog
            .db
            .query_row(
                "SELECT serve_instance,machine_name,vcpus FROM managed_launches WHERE operation_id=?",
                [operation_id],
                |row| {
                    Ok(Self {
                        serve: row.get(0)?,
                        machine: row.get(1)?,
                        vcpus: row.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    fn effective_millicpus(&self, millicpus: Option<u32>) -> u64 {
        let allocated = u64::from(self.vcpus) * 1_000;
        millicpus.map_or(allocated, |value| u64::from(value).min(allocated))
    }
}

fn open_at(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_scope(owner: &ManagedScope) -> io::Result<File> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open("/sys/fs/cgroup")?;
    let slice_name = CString::new(worker_scope::configured_slice()?)?;
    let slice = open_at(&root, &slice_name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let scope_name = CString::new(managed_scope_name(&owner.serve, &owner.machine))?;
    let scope = open_at(&slice, &scope_name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(scope.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    if stats.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(io::Error::other("managed scope is outside cgroup v2"));
    }
    Ok(scope)
}

/// Keep the kernel scope and its only process pinned across actuation.
struct PinnedScope<'a> {
    owner: &'a ManagedScope,
    dir: File,
    pid: i32,
    start: i64,
    pidfd: &'a OwnedFd,
}

impl<'a> PinnedScope<'a> {
    fn open(owner: &'a ManagedScope, pid: i32, start: i64, pidfd: &'a OwnedFd) -> Result<Self> {
        let scope = Self {
            owner,
            dir: open_scope(owner).map_err(unavailable)?,
            pid,
            start,
            pidfd,
        };
        scope.verify().map_err(unavailable)?;
        Ok(scope)
    }

    fn verify(&self) -> io::Result<()> {
        let same_process = pid_start(self.pid)? == self.start
            && worker_scope::contains_process(self.pid, &self.owner.serve, &self.owner.machine)?
            && !pid_exited(self.pidfd)?;
        let pinned = self.dir.metadata()?;
        let current = open_scope(self.owner)?.metadata()?;
        if !same_process || pinned.dev() != current.dev() || pinned.ino() != current.ino() {
            return Err(io::Error::other("managed scope or execution changed"));
        }
        let mut processes = String::new();
        open_at(&self.dir, c"cgroup.procs", libc::O_RDONLY)?.read_to_string(&mut processes)?;
        let mut pids = processes.split_whitespace();
        if pids.next().and_then(|pid| pid.parse().ok()) != Some(self.pid) || pids.next().is_some() {
            return Err(io::Error::other(
                "managed scope has another process or no VMM",
            ));
        }
        Ok(())
    }

    fn read(&self) -> io::Result<Bandwidth> {
        self.verify()?;
        let mut raw = String::new();
        open_at(&self.dir, c"cpu.max", libc::O_RDONLY)?.read_to_string(&mut raw)?;
        let actual = Bandwidth::parse(&raw)?;
        self.verify()?;
        Ok(actual)
    }

    fn apply(&self, millicpus: u64, original: Option<Bandwidth>) -> Result<Bandwidth> {
        let before = self.read().map_err(unavailable)?;
        if before.matches(millicpus) {
            return Ok(before);
        }
        let limit = cpu_quota::cpu_max_millicpus_line(millicpus);
        let mut control = open_at(&self.dir, c"cpu.max", libc::O_WRONLY).map_err(unavailable)?;
        self.verify().map_err(unavailable)?;
        // A cgroup controller takes one complete record per write.
        let write = control.write(limit.as_bytes());
        let after = self.read().map_err(uncertain)?;
        if after.matches(millicpus) {
            return Ok(after);
        }
        if let Err(error) = write {
            eprintln!("resourced cpu.max write: {error}");
        }
        if Some(after) == original {
            return Err(Fault::new(
                REJECTED,
                "the CPU controller retained its previous bandwidth",
            ));
        }
        Err(Fault::new(
            UNCERTAIN,
            "the CPU controller's resulting bandwidth could not be confirmed",
        ))
    }
}

fn unavailable(error: io::Error) -> Fault {
    eprintln!("resourced managed CPU scope: {error}");
    Fault::new(
        UNAVAILABLE,
        "could not verify the managed VMM CPU controller",
    )
}

fn uncertain(error: io::Error) -> Fault {
    eprintln!("resourced managed CPU quota readback: {error}");
    Fault::new(
        UNCERTAIN,
        "the CPU controller's resulting bandwidth could not be confirmed",
    )
}

fn desired(catalog: &Catalog, instance_id: &str) -> Result<Option<u32>> {
    Ok(catalog
        .db
        .query_row(
            "SELECT millicpus FROM managed_cpu_limits WHERE instance_id=?",
            [instance_id],
            |r| r.get(0),
        )
        .optional()?)
}

struct Recorded {
    millicpus: Option<u32>,
    original: Bandwidth,
    actual: Option<Bandwidth>,
    rejection: Option<String>,
}

fn recorded(catalog: &Catalog, operation_id: &str) -> Result<Recorded> {
    Ok(catalog.db.query_row(
        "SELECT millicpus,quota_usec,period_usec,rejection,previous_quota_usec,previous_period_usec
        FROM managed_cpu_limit_operations WHERE operation_id=?",
        [operation_id],
        |r| {
            let quota_usec = r.get(1)?;
            let period_usec: Option<i64> = r.get(2)?;
            Ok(Recorded {
                millicpus: r.get(0)?,
                actual: period_usec.map(|period_usec| Bandwidth {
                    quota_usec,
                    period_usec,
                }),
                rejection: r.get(3)?,
                original: Bandwidth {
                    quota_usec: r.get(4)?,
                    period_usec: r.get(5)?,
                },
            })
        },
    )?)
}

fn rejection(reason: &str) -> Fault {
    match reason {
        "execution_exited" => stale_execution(),
        _ => Fault::new(
            REJECTED,
            "the CPU controller retained its previous bandwidth",
        ),
    }
}

fn release_slot(tx: &Transaction<'_>, operation_id: &str) -> rusqlite::Result<()> {
    tx.execute(
        "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id=?",
        [operation_id],
    )?;
    Ok(())
}

pub(crate) fn abort_cpu_limits_for_exit(tx: &Transaction<'_>, incarnation: &str) -> Result<()> {
    tx.execute(
        "UPDATE managed_cpu_limit_operations SET rejection='execution_exited' WHERE operation_id IN (
            SELECT operation_id FROM operations WHERE kind='managed_cpu_limit' AND phase='NEW'
            AND expected_incarnation_id=?
        )",
        [incarnation],
    )?;
    tx.execute(
        "UPDATE instance_bindings SET active_operation_id=NULL WHERE active_operation_id IN (
            SELECT operation_id FROM operations WHERE kind='managed_cpu_limit' AND phase='NEW'
            AND expected_incarnation_id=?
        )",
        [incarnation],
    )?;
    tx.execute(
        "UPDATE operations SET phase='ABORTED',decision='ABORT',revision=revision+1
        WHERE kind='managed_cpu_limit' AND phase='NEW' AND expected_incarnation_id=?",
        [incarnation],
    )?;
    Ok(())
}

impl Worker {
    pub(super) fn set_managed_cpu_limit(&mut self, request: &Request) -> Result<Value> {
        let (route, _, expected) = request.scope()?;
        if route != "deep" {
            return Err(Fault::invalid("managed CPU limits require the deep route"));
        }
        let incarnation = expected
            .incarnation_id
            .as_deref()
            .ok_or_else(stale_execution)?;
        let millicpus = request_millicpus(request)?;
        let (id, _) = request.operation()?;
        let exists: bool = self.catalog.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id=?)",
            [id],
            |row| row.get(0),
        )?;
        let original = if exists {
            None
        } else {
            let execution = self.current_cpu_execution(request)?;
            let owner = self.cpu_scope_owner(&execution)?;
            if millicpus.is_some_and(|value| u64::from(value) > u64::from(owner.vcpus) * 1_000) {
                return Err(Fault::invalid(
                    "CPU limit exceeds the allocated vCPU bandwidth",
                ));
            }
            Some(
                self.pin_cpu_scope(&execution, &owner)?
                    .read()
                    .map_err(unavailable)?,
            )
        };
        let operation = self.catalog.begin_with(request, KIND, |tx| {
            let original = original.ok_or_else(|| Fault::new("E_CATALOG", "CPU operation lost its original bandwidth"))?;
            tx.execute(
                "INSERT INTO managed_cpu_limit_operations(operation_id,millicpus,previous_quota_usec,previous_period_usec)
                VALUES(?,?,?,?)",
                params![id, millicpus, original.quota_usec, original.period_usec],
            )?;
            Ok(())
        })?;
        let row = recorded(&self.catalog, id)?;
        if row.millicpus != millicpus {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "requested CPU limit changed",
            ));
        }
        if let Some(actual) = row.actual {
            return Ok(receipt(
                &operation.instance_id,
                incarnation,
                operation.expected_execution_epoch,
                millicpus,
                actual,
            ));
        }
        if let Some(reason) = row.rejection {
            return Err(rejection(&reason));
        }
        self.catalog.active_operation(request)?;
        let execution = self.current_cpu_execution(request)?;
        self.apply_cpu_limit(&operation, &execution, &row)
    }

    pub(super) fn query_managed_cpu_limit(&self, request: &Request) -> Result<Value> {
        let execution = self.current_cpu_execution(request)?;
        let owner = self.cpu_scope_owner(&execution)?;
        let actual = self
            .pin_cpu_scope(&execution, &owner)?
            .read()
            .map_err(unavailable)?;
        Ok(receipt(
            &execution.instance_id,
            &execution.incarnation_id,
            execution.execution_epoch,
            desired(&self.catalog, &execution.instance_id)?,
            actual,
        ))
    }

    fn current_cpu_execution(&self, request: &Request) -> Result<Execution> {
        let (route, _, expected) = request.scope()?;
        if route != "deep" {
            return Err(Fault::invalid("managed CPU limits require the deep route"));
        }
        let (current, _) = crate::lifecycle_controller::binding(&self.catalog, request)?;
        if &current != expected {
            return Err(stale_execution());
        }
        let execution = self.scoped_execution(request)?;
        self.verify_live_execution(&execution)?;
        Ok(execution)
    }

    fn cpu_scope_owner(&self, execution: &Execution) -> Result<ManagedScope> {
        ManagedScope::from_launch(&self.catalog, &execution.last_operation_id)?.ok_or_else(|| {
            Fault::new(
                "E_CAPABILITY_UNSUPPORTED",
                "execution has no Worker-managed systemd scope",
            )
        })
    }

    fn pin_cpu_scope<'a>(
        &'a self,
        execution: &Execution,
        owner: &'a ManagedScope,
    ) -> Result<PinnedScope<'a>> {
        let pidfd = self
            .executions
            .get(&execution.incarnation_id)
            .ok_or_else(stale_execution)?;
        PinnedScope::open(owner, execution.pid, execution.pid_start_time, pidfd)
    }

    fn apply_cpu_limit(
        &mut self,
        operation: &Operation,
        execution: &Execution,
        entry: &Recorded,
    ) -> Result<Value> {
        let owner = self.cpu_scope_owner(execution)?;
        let millicpus = entry.millicpus;
        let result = self
            .pin_cpu_scope(execution, &owner)?
            .apply(owner.effective_millicpus(millicpus), Some(entry.original));
        let id = &operation.operation_id;
        if let Err(fault) = &result {
            if fault.code == REJECTED {
                let tx = self.catalog.db.transaction()?;
                tx.execute("UPDATE managed_cpu_limit_operations SET rejection='controller_rejected' WHERE operation_id=?", [id])?;
                tx.execute("UPDATE operations SET phase='ABORTED',decision='ABORT',revision=revision+1 WHERE operation_id=?", [id])?;
                release_slot(&tx, id)?;
                tx.commit()?;
            }
        }
        let actual = result?;
        let tx = self.catalog.db.transaction()?;
        if let Some(value) = millicpus {
            tx.execute(
                "INSERT INTO managed_cpu_limits(instance_id,millicpus) VALUES(?,?)
                ON CONFLICT(instance_id) DO UPDATE SET millicpus=excluded.millicpus",
                params![execution.instance_id, value],
            )?;
        } else {
            tx.execute(
                "DELETE FROM managed_cpu_limits WHERE instance_id=?",
                [&execution.instance_id],
            )?;
        }
        tx.execute(
            "UPDATE managed_cpu_limit_operations SET quota_usec=?,period_usec=? WHERE operation_id=?",
            params![actual.quota_usec, actual.period_usec, id],
        )?;
        tx.execute(
            "UPDATE operations SET phase='COMPLETED',revision=revision+1 WHERE operation_id=?",
            [id],
        )?;
        release_slot(&tx, id)?;
        tx.commit()?;
        Ok(receipt(
            &execution.instance_id,
            &execution.incarnation_id,
            execution.execution_epoch,
            millicpus,
            actual,
        ))
    }

    pub(super) fn restore_managed_cpu_limit(
        &self,
        launch: &Operation,
        pid: i32,
        start: i64,
        pidfd: &OwnedFd,
    ) -> Result<()> {
        if launch.route_id != "deep" {
            return Ok(());
        }
        let Some(millicpus) = desired(&self.catalog, &launch.instance_id)? else {
            return Ok(());
        };
        let owner =
            ManagedScope::from_launch(&self.catalog, &launch.operation_id)?.ok_or_else(|| {
                Fault::new(
                    UNAVAILABLE,
                    "stored CPU limit requires a Worker-managed launch",
                )
            })?;
        // RegisterExecution must succeed before the child constructs its VMM.
        PinnedScope::open(&owner, pid, start, pidfd)?
            .apply(owner.effective_millicpus(Some(millicpus)), None)?;
        Ok(())
    }

    pub(super) fn reconcile_managed_cpu_limits(&mut self) -> Result<()> {
        let pending = {
            let mut query = self.catalog.db.prepare(
                "SELECT p.operation_id,o.expected_incarnation_id
                FROM managed_cpu_limit_operations p JOIN operations o USING(operation_id)
                JOIN instance_bindings b ON b.active_operation_id=p.operation_id WHERE o.phase='NEW'",
            )?;
            let rows =
                query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (id, incarnation) in pending {
            let execution = self.catalog.execution(&incarnation)?;
            let old_process_gone = match pid_start(execution.pid) {
                Ok(start) => start != execution.pid_start_time,
                Err(error) => error.kind() == io::ErrorKind::NotFound,
            };
            if execution.host_boot_id != self.boot
                || execution.phase == "exited"
                || old_process_gone
            {
                let tx = self.catalog.db.transaction()?;
                abort_cpu_limits_for_exit(&tx, &incarnation)?;
                tx.commit()?;
                continue;
            }
            if self.verify_live_execution(&execution).is_ok() {
                let operation = self.catalog.operation(&id)?;
                let entry = recorded(&self.catalog, &id)?;
                if let Err(fault) = self.apply_cpu_limit(&operation, &execution, &entry) {
                    eprintln!("resourced managed CPU limit {id}: {fault}");
                }
            }
        }
        Ok(())
    }
}
