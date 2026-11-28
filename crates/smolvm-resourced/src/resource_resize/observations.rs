//! Read actual resources from the authenticated VMM, Guest Agent, and cgroup.
use crate::{
    catalog::Execution,
    ipc::{Fault, Result},
    native_control::Endpoint,
};
use serde::{Deserialize, Serialize};
use smolvm_protocol::{AgentRequest, AgentResponse};
use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) const MIB: u64 = 1 << 20;

fn native(detail: impl ToString) -> Fault {
    Fault::new("E_NATIVE_UNAVAILABLE", detail.to_string())
}

fn guest(detail: impl ToString) -> Fault {
    Fault::new("E_GUEST_MANAGEMENT_UNAVAILABLE", detail.to_string())
}

pub(crate) fn agent(endpoint: &Endpoint, request: &AgentRequest) -> Result<AgentResponse> {
    let mut stream = UnixStream::from(endpoint.connect_guest_agent().map_err(guest)?);
    let seconds = if matches!(request, AgentRequest::Ping | AgentRequest::VmExec { .. }) {
        2
    } else {
        12
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(seconds)))
        .map_err(guest)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(guest)?;
    stream
        .write_all(&smolvm_protocol::encode_message(request).map_err(guest)?)
        .map_err(guest)?;
    let mut size = [0; 4];
    stream.read_exact(&mut size).map_err(guest)?;
    let size = u32::from_be_bytes(size) as usize;
    let max = if matches!(request, AgentRequest::CaptureSavedFileMounts) { 128 << 10 } else { 64 << 10 };
    if size == 0 || size > max {
        return Err(guest("unexpected Guest resource reply size"));
    }
    let mut bytes = vec![0u8; size];
    stream.read_exact(&mut bytes).map_err(guest)?;
    serde_json::from_slice(&bytes).map_err(guest)
}

pub(super) fn capabilities(endpoint: &Endpoint) -> Result<Vec<String>> {
    match agent(endpoint, &AgentRequest::Ping)? {
        AgentResponse::Pong {
            version,
            capabilities,
        } if version == smolvm_protocol::PROTOCOL_VERSION => Ok(capabilities),
        _ => Err(guest(
            "Guest Agent protocol for live resources is unavailable",
        )),
    }
}

pub(super) fn online_cpu_ids(endpoint: &Endpoint, created: u8) -> Result<Vec<u8>> {
    let request = AgentRequest::VmExec {
        command: vec!["/bin/cat".into(), "/sys/devices/system/cpu/online".into()],
        env: Vec::new(),
        workdir: None,
        timeout_ms: Some(1000),
        interactive: false,
        tty: false,
        background: false,
        stdin_data: None,
    };
    let AgentResponse::Completed {
        exit_code: 0,
        stdout,
        ..
    } = agent(endpoint, &request)?
    else {
        return Err(guest("Guest did not report its online CPU set"));
    };
    let input = std::str::from_utf8(&stdout).map_err(guest)?;
    let mut online = Vec::new();
    for part in input.trim().split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start = start.parse::<u8>().map_err(guest)?;
        let end = end.parse::<u8>().map_err(guest)?;
        if start > end || end >= created || online.last().is_some_and(|prior| *prior >= start) {
            return Err(guest("Guest reported an invalid online CPU set"));
        }
        online.extend(start..=end);
    }
    if online.first() != Some(&0) {
        return Err(guest("Guest online CPU set omitted CPU0"));
    }
    Ok(online)
}

pub(super) fn guest_complete(
    endpoint: &Endpoint,
    request: &AgentRequest,
    expected: &[(&str, u64)],
) -> Result<()> {
    match agent(endpoint, request)? {
        AgentResponse::Ok { data: Some(data) }
            if expected
                .iter()
                .all(|(field, value)| data[*field].as_u64() == Some(*value)) =>
        {
            Ok(())
        }
        AgentResponse::Error { message, .. } => {
            Err(guest(message.chars().take(240).collect::<String>()))
        }
        _ => Err(guest("Guest did not verify the requested resources")),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct Cpus {
    pub created: u8,
    pub capacity: u8,
}

pub(super) fn cpus(endpoint: &Endpoint) -> Result<Cpus> {
    let reply = endpoint.command("PROTOTYPE_CPU_STATUS")?;
    let words: Vec<_> = reply.split_ascii_whitespace().collect();
    let ["created", created, "capacity", capacity] = words.as_slice() else {
        return Err(native("VMM did not report created CPU slots"));
    };
    let created = created.parse::<u8>().map_err(native)?;
    let capacity = capacity.parse::<u8>().map_err(native)?;
    if created == 0 || created > capacity {
        return Err(native("invalid VMM CPU geometry"));
    }
    Ok(Cpus { created, capacity })
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct Ram {
    pub boot_mib: u32,
    pub base: u64,
    pub mapped: u64,
    pub plugged: u64,
    pub capacity: u64,
    pub driver: bool,
}

pub(super) fn ram(endpoint: &Endpoint) -> Result<Ram> {
    let reply = endpoint.command("PROTOTYPE_MEMORY_INFO")?;
    let words: Vec<_> = reply.split_ascii_whitespace().collect();
    let ["boot_mib", boot, "base", base, "mapped", mapped, "plugged", plugged, "capacity", capacity, "driver", driver] =
        words.as_slice()
    else {
        return Err(native(
            "VMM did not report verified RAM geometry and driver state",
        ));
    };
    let ram = Ram {
        boot_mib: boot.parse().map_err(native)?,
        base: base.parse().map_err(native)?,
        mapped: mapped.parse().map_err(native)?,
        plugged: plugged.parse().map_err(native)?,
        capacity: capacity.parse().map_err(native)?,
        driver: match *driver {
            "0" => false,
            "1" => true,
            _ => return Err(native("invalid RAM driver state")),
        },
    };
    if ram.boot_mib == 0
        || ram.capacity == 0
        || ram.plugged > ram.mapped
        || ram.mapped > ram.capacity
        || !ram.base.is_multiple_of(128 * MIB)
        || !ram.mapped.is_multiple_of(128 * MIB)
        || !ram.capacity.is_multiple_of(128 * MIB)
        || !ram.plugged.is_multiple_of(2 * MIB)
        || ram.base.checked_add(ram.capacity).is_none()
    {
        return Err(native("invalid VMM RAM geometry"));
    }
    Ok(ram)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct Balloon {
    pub target_mib: u32,
    pub actual_mib: u32,
}

pub(super) fn balloon(endpoint: &Endpoint) -> Result<Balloon> {
    let reply = endpoint.command("BALLOON")?;
    let words: Vec<_> = reply.split_ascii_whitespace().collect();
    let [target, actual] = words.as_slice() else {
        return Err(native("VMM did not report balloon target and actual"));
    };
    let unrecognized = || native("invalid balloon observation");
    Ok(Balloon {
        target_mib: target
            .strip_prefix("target=")
            .ok_or_else(unrecognized)?
            .parse()
            .map_err(native)?,
        actual_mib: actual
            .strip_prefix("actual=")
            .ok_or_else(unrecognized)?
            .parse()
            .map_err(native)?,
    })
}

pub(super) fn scoped_cgroup(execution: &Execution, machine: &str) -> Result<PathBuf> {
    let serve = crate::managed::serve_id(&execution.instance_id, machine)?;
    if !crate::worker_scope::contains_process(execution.pid, &serve, machine).map_err(native)?
        || crate::worker::pid_start(execution.pid).ok() != Some(execution.pid_start_time)
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "VMM is outside its confirmed Serve and machine scope",
        ));
    }
    let name = smolvm_runtime_protocol::managed_scope_name(&serve, machine);
    Ok(crate::worker_scope::cgroup().map_err(native)?.join(name))
}

pub(super) fn memory_current(scope: &Path) -> Result<u64> {
    fs::read_to_string(scope.join("memory.current"))
        .map_err(native)?
        .trim()
        .parse()
        .map_err(native)
}

pub(super) fn check_memory_budget(scope: &Path, total_mib: u32, increment: u64) -> Result<()> {
    let root = Path::new("/sys/fs/cgroup");
    let planned = u64::from(total_mib) * MIB;
    let high = fs::read_to_string(scope.join("memory.high")).map_err(native)?;
    if high.trim() != "max" && high.trim().parse::<u64>().map_err(native)? < planned {
        return Err(Fault::new(
            "E_RESOURCE_LIMIT",
            "requested RAM exceeds the VMM scope's memory allowance",
        ));
    }
    for level in scope.ancestors().take_while(|directory| *directory != root) {
        let limit = fs::read_to_string(level.join("memory.max")).map_err(native)?;
        if limit.trim() == "max" {
            continue;
        }
        let limit = limit.trim().parse::<u64>().map_err(native)?;
        let resident = fs::read_to_string(level.join("memory.current"))
            .map_err(native)?
            .trim()
            .parse::<u64>()
            .map_err(native)?;
        if increment > limit.saturating_sub(resident) || level == scope && planned > limit {
            return Err(Fault::new(
                "E_RESOURCE_LIMIT",
                "requested RAM does not fit the effective VMM cgroup budget",
            ));
        }
    }
    Ok(())
}
