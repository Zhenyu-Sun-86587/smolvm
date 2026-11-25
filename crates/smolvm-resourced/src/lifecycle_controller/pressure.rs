//! Worker-scoped sampling and bounded cache reclaim. Reads kernel aggregate
//! counters once per sample so shared RAM is counted by its owning cgroup.
use super::*;
use std::{fs, io, path::Path, thread};
const MIB: u64 = 1 << 20;

#[derive(serde::Serialize, Deserialize)]
pub(super) struct Sample {
    pub headroom_bytes: u64,
    slice_name: String,
    pub slice_current: Option<u64>,
    slice_max: Option<u64>,
    memory_psi: Option<f64>,
    io_psi: Option<f64>,
    slice_memory_psi: Option<f64>,
    slice_io_psi: Option<f64>,
    memory_events: Option<String>,
    pub disk_available: u64,
}

fn configure(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| invalid(format!("invalid deployment setting {name}"))),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(invalid(e)),
    }
}
fn usage(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}
fn psi(path: &Path) -> Option<f64> {
    let raw = fs::read_to_string(path).ok()?;
    raw.lines()
        .find(|line| line.starts_with("some "))?
        .split_whitespace()
        .find_map(|v| v.strip_prefix("avg10="))?
        .parse()
        .ok()
}
fn measure(db: &Connection) -> Result<Sample> {
    let mem = fs::read_to_string("/proc/meminfo").map_err(invalid)?;
    let available = mem
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| invalid("Worker memory headroom is unavailable"))?
        .saturating_mul(1024);
    let group = crate::worker_scope::cgroup().map_err(invalid)?;
    let current = usage(&group.join("memory.current"));
    let max = usage(&group.join("memory.max"));
    let storage = crate::admission::unreserved_storage(db)?;
    Ok(Sample {
        headroom_bytes: current.zip(max).map_or(available, |(used, limit)| {
            available.min(limit.saturating_sub(used))
        }),
        slice_name: crate::worker_scope::configured_slice()
            .map_err(invalid)?
            .into(),
        slice_current: current,
        slice_max: max,
        memory_psi: psi(Path::new("/proc/pressure/memory")),
        io_psi: psi(Path::new("/proc/pressure/io")),
        slice_memory_psi: psi(&group.join("memory.pressure")),
        slice_io_psi: psi(&group.join("io.pressure")),
        memory_events: fs::read_to_string(group.join("memory.events")).ok(),
        disk_available: storage,
    })
}
pub(super) struct Pressure {
    pub eligible: bool,
    pub sample: Sample,
}
pub(super) type CacheReclaim = Option<thread::JoinHandle<io::Result<()>>>;

pub(super) fn refresh(db: &Connection, cache: &mut CacheReclaim) -> Result<Pressure> {
    if cache.as_ref().is_some_and(|reclaim| reclaim.is_finished()) {
        match cache.take().expect("finished cache reclaim").join() {
            Ok(Ok(())) => (),
            Ok(Err(error)) => eprintln!("Worker bounded cache reclaim: {error}"),
            Err(_) => eprintln!("Worker bounded cache reclaim thread exited unexpectedly"),
        }
    }
    let sample = measure(db)?;
    let enter = configure("SMOLVM_WORKER_PRESSURE_HIGH_HEADROOM_MIB", 256)?.saturating_mul(MIB);
    let leave = configure("SMOLVM_WORKER_PRESSURE_LOW_HEADROOM_MIB", 512)?.saturating_mul(MIB);
    let max_psi = configure("SMOLVM_WORKER_MEMORY_PSI_PERCENT", 20)? as f64;
    if enter >= leave || max_psi <= 0.0 || max_psi > 100.0 {
        return Err(invalid("invalid Worker pressure watermarks"));
    }
    let (old, changed, last): (bool, i64, Option<i64>) = db
        .query_row(
            "SELECT throttled,changed_at,reclaimed_at FROM lifecycle_pressure WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .unwrap_or((false, 0, None));
    let memory_psi = [sample.memory_psi, sample.slice_memory_psi]
        .into_iter()
        .flatten()
        .reduce(f64::max);
    let io_psi = [sample.io_psi, sample.slice_io_psi]
        .into_iter()
        .flatten()
        .reduce(f64::max);
    let high = sample.headroom_bytes <= enter || memory_psi.is_some_and(|v| v >= max_psi);
    let throttled = high
        || old && (sample.headroom_bytes < leave || memory_psi.is_some_and(|v| v > max_psi / 2.0));
    let now = monotonic()?;
    let since = if old != throttled || changed == 0 {
        now
    } else {
        changed
    };
    let mut reclaimed = if old != throttled { None } else { last };
    if throttled && cache.is_none() && reclaimed.is_none_or(|v| now.saturating_sub(v) > 60_000) {
        let bytes = configure("SMOLVM_WORKER_CACHE_RECLAIM_MIB", 32)?.min(128) * MIB;
        if bytes > 0 {
            let path = crate::worker_scope::cgroup()
                .map_err(invalid)?
                .join("memory.reclaim");
            *cache = Some(
                thread::Builder::new()
                    .name("worker-cache-reclaim".into())
                    .spawn(move || fs::write(path, bytes.to_string()))
                    .map_err(invalid)?,
            );
        }
        reclaimed = Some(now);
    }
    let eligible = throttled
        && now.saturating_sub(since) >= 5_000
        && cache.is_none()
        && io_psi.is_none_or(|v| v < 70.0)
        && reclaimed.is_some_and(|v| now > v + 1000);
    db.execute("INSERT INTO lifecycle_pressure VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET throttled=excluded.throttled,
        sample_json=excluded.sample_json,changed_at=excluded.changed_at,reclaimed_at=excluded.reclaimed_at",
        params![throttled,serde_json::to_string(&sample).map_err(invalid)?,since,reclaimed])?;
    Ok(Pressure { eligible, sample })
}
pub(crate) fn check_admission(tx: &Transaction<'_>, requested_mib: u64) -> Result<()> {
    // Sample as part of admission as well. A burst cannot consume the reserve
    // before the next periodic Worker sample.
    let sample = measure(tx)?;
    let held = tx
        .query_row(
            "SELECT throttled FROM lifecycle_pressure WHERE singleton=1",
            [],
            |r| r.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or(false);
    let reserve = configure("SMOLVM_WORKER_CONTROL_RESERVE_MIB", 64)?.saturating_mul(MIB);
    if held || sample.headroom_bytes < reserve.saturating_add(requested_mib.saturating_mul(MIB)) {
        return Err(Fault::new(
            "E_RESOURCE_LIMIT",
            "Worker memory admission is throttled",
        ));
    }
    Ok(())
}
