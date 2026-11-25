//! One Worker-wide ledger for managed execution and whole-batch reservations.
use crate::ipc::{Fault, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Copy, Clone, Debug, Serialize)]
pub(crate) struct Capacity {
    pub vcpus: u64,
    pub memory_mib: u64,
    pub storage_bytes: u64,
}

fn unavailable(e: impl ToString) -> Fault {
    Fault::new("E_RESOURCE_LIMIT", e.to_string())
}
fn override_limit(name: &str, physical: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map(|n| n.min(physical))
            .map_err(|_| unavailable(format!("invalid Worker budget {name}"))),
        Err(std::env::VarError::NotPresent) => Ok(physical),
        Err(e) => Err(unavailable(e)),
    }
}
fn limits(db: &Connection) -> Result<Capacity> {
    let cpus = std::thread::available_parallelism()
        .map_err(unavailable)?
        .get() as u64;
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_size <= 0 {
        return Err(unavailable("cannot measure physical memory"));
    }
    let mut memory = (pages as u64)
        .checked_mul(page_size as u64)
        .ok_or_else(|| unavailable("physical memory overflow"))?;
    if let Ok(groups) = fs::read_to_string("/proc/self/cgroup") {
        if let Some(group) = groups.lines().find_map(|g| g.strip_prefix("0::/")) {
            let root = Path::new("/sys/fs/cgroup");
            let own = root.join(group);
            for parent in own.ancestors().take_while(|p| p.starts_with(root)) {
                if let Ok(text) = fs::read_to_string(parent.join("memory.max")) {
                    if let Ok(bytes) = text.trim().parse::<u64>() {
                        memory = memory.min(bytes)
                    }
                }
            }
        }
    }
    let path = db
        .path()
        .and_then(|p| Path::new(p).parent())
        .ok_or_else(|| unavailable("missing catalog filesystem"))?;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(unavailable)?;
    let mut stat = std::mem::MaybeUninit::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(unavailable(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    let free = stat.f_bavail.saturating_mul(stat.f_frsize);
    Ok(Capacity {
        vcpus: override_limit("SMOLVM_WORKER_VCPU_BUDGET", cpus)?,
        memory_mib: override_limit("SMOLVM_WORKER_MEMORY_BUDGET_MIB", memory >> 20)?,
        storage_bytes: override_limit("SMOLVM_WORKER_STORAGE_BUDGET_BYTES", free)?,
    })
}
fn used(db: &Connection) -> Result<Capacity> {
    Ok(db.query_row("SELECT COALESCE(SUM(vcpus),0),COALESCE(SUM(memory_mib),0),COALESCE(SUM(storage_bytes),0) FROM managed_budget_holds WHERE state!='released'",[],
        |r|Ok(Capacity{vcpus:r.get::<_,i64>(0)? as u64,memory_mib:r.get::<_,i64>(1)? as u64,storage_bytes:r.get::<_,i64>(2)? as u64}))?)
}
pub(crate) fn status(db: &Connection) -> Result<serde_json::Value> {
    Ok(serde_json::json!({"capacity":limits(db)?,"allocated":used(db)?}))
}
/// The caller owns the immediate admission transaction, including all batch children.
pub(crate) fn reserve(
    db: &rusqlite::Transaction<'_>,
    operation: &str,
    instance: &str,
    request: Capacity,
) -> Result<()> {
    let limit = limits(db)?;
    let allocated = used(db)?;
    for (dimension, cap, held, need) in [
        ("vcpus", limit.vcpus, allocated.vcpus, request.vcpus),
        (
            "memory_mib",
            limit.memory_mib,
            allocated.memory_mib,
            request.memory_mib,
        ),
        (
            "storage_bytes",
            limit.storage_bytes,
            allocated.storage_bytes,
            request.storage_bytes,
        ),
    ] {
        if need > cap.saturating_sub(held) {
            return Err(unavailable(format!(
                "{dimension} requires {need}, allocated {held}, capacity {cap}"
            )));
        }
    }
    db.execute("INSERT INTO managed_budget_holds(operation_id,instance_id,vcpus,memory_mib,storage_bytes,state)VALUES(?,?,?,?,?,'reserved')",
        params![operation,instance,i64::try_from(request.vcpus).map_err(unavailable)?,i64::try_from(request.memory_mib).map_err(unavailable)?,i64::try_from(request.storage_bytes).map_err(unavailable)?])?;
    Ok(())
}
