//! Worker-owned read-only process backing for an immutable captured RAM cut.

use crate::catalog::{Catalog, Execution};
use crate::ipc::{self, Fault, Result};
use crate::worker::{observe_pid, pid_exited, pid_start, process_fd, verify_executable};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use smolvm_runtime_protocol::kernel_cow::{packed_size, Region, PROFILE};
use socket2::{Domain, SockAddr, Socket, Type};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "kernel_mm_anchor_tests.rs"]
mod tests;

// Immediately above the reserved deep execution range.
pub(super) const ANCHOR_UID: u32 = 202_000_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Init {
    pub directory: PathBuf,
    pub capture_id: String,
    pub helper_id: String,
    pub bundle_digest: String,
    pub executable_digest: String,
    pub regions: Vec<Region>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Receipt {
    pub regions: Vec<Region>,
    pub layout_digest: String,
}

struct Record {
    capture_id: String,
    operation_id: String,
    source_incarnation: String,
    source_epoch: i64,
    source_session: u32,
    host_boot_id: String,
    receipt: Receipt,
    helper_id: String,
    pid: i32,
    start: i64,
    exe: (u64, u64),
    resource_state: Option<String>,
    failed: bool,
}

fn unavailable(error: impl ToString) -> Fault {
    Fault::new("E_KERNEL_ANCHOR_UNAVAILABLE", error.to_string())
}

fn lost() -> Fault {
    Fault::new(
        "E_CAPTURE_LOST",
        "this capture no longer has its original kernel CoW RAM anchor",
    )
}

fn pending() -> Fault {
    Fault::new(
        "E_OPERATION_IN_PROGRESS",
        "kernel CoW RAM anchor is starting",
    )
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn lookup(c: &Catalog, id: &str) -> Result<Option<Record>> {
    Ok(c.db.query_row(
        "SELECT a.capture_id,a.operation_id,a.source_incarnation,a.source_epoch,a.source_session,
          a.host_boot_id,a.regions_json,a.layout_digest,a.helper_id,a.helper_pid,a.helper_start,
          a.executable_dev,a.executable_ino,r.state,a.failure IS NOT NULL
         FROM kernel_mm_anchors a LEFT JOIN resources r ON r.resource_id=a.resource_id
         WHERE a.capture_id=?",
        [id],
        |row| {
            let regions: String = row.get(6)?;
            let regions = serde_json::from_str(&regions).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6, rusqlite::types::Type::Text, Box::new(error),
                )
            })?;
            Ok(Record {
                capture_id: row.get(0)?,
                operation_id: row.get(1)?,
                source_incarnation: row.get(2)?,
                source_epoch: row.get(3)?,
                source_session: row.get(4)?,
                host_boot_id: row.get(5)?,
                receipt: Receipt { regions, layout_digest: row.get(7)? },
                helper_id: row.get(8)?,
                pid: row.get(9)?,
                start: row.get(10)?,
                exe: (row.get::<_, i64>(11)? as u64, row.get::<_, i64>(12)? as u64),
                resource_state: row.get(13)?,
                failed: row.get(14)?,
            })
        },
    ).optional()?)
}

fn boot_id(c: &Catalog) -> Result<String> {
    Ok(c.db
        .query_row("SELECT host_boot_id FROM worker_state", [], |row| {
            row.get(0)
        })?)
}

fn directory(c: &Catalog) -> Result<PathBuf> {
    let parent =
        c.db.path()
            .and_then(|path| Path::new(path).parent())
            .ok_or_else(|| unavailable("missing Worker state directory"))?;
    Ok(fs::canonicalize(parent)
        .map_err(unavailable)?
        .join("kernel-mm-anchors"))
}

fn valid_helper_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn scope_name(id: &str) -> String {
    format!("smolvmdeep-anchor-{id}.scope")
}

pub(super) fn in_scope(pid: i32, id: &str) -> io::Result<bool> {
    if !valid_helper_id(id) {
        return Ok(false);
    }
    let slice = crate::worker_scope::configured_slice()?;
    let expected = format!("0::/{slice}/{}", scope_name(id));
    let groups = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    Ok(groups.lines().any(|line| line == expected))
}

pub(super) fn command_address(dir: &Path, id: &str) -> io::Result<(File, SockAddr)> {
    if !valid_helper_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid kernel CoW helper ID",
        ));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    let meta = directory.metadata()?;
    if meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "anchor directory must be private",
        ));
    }
    // Refer to the opened directory so long state paths fit in sockaddr_un.
    let address = SockAddr::unix(format!("/proc/self/fd/{}/{id}.sock", directory.as_raw_fd()))?;
    Ok((directory, address))
}

fn enter_scope(pid: i32, id: &str, slice: &str) -> Result<()> {
    let name = scope_name(id);
    let pid_str = pid.to_string();
    let result = Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--timeout=4s",
            "call",
            "org.freedesktop.systemd1",
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager",
            "StartTransientUnit",
            "ssa(sv)a(sa(sv))",
            &name,
            "fail",
            "5",
            "PIDs",
            "au",
            "1",
            &pid_str,
            "Slice",
            "s",
            slice,
            "Description",
            "s",
            "smolvm kernel CoW RAM anchor",
            "TasksMax",
            "t",
            "1",
            "CollectMode",
            "s",
            "inactive-or-failed",
            "0",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .map_err(unavailable)?;
    if !result.status.success() {
        return Err(unavailable(format!(
            "could not admit the RAM anchor scope: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while !in_scope(pid, id).map_err(unavailable)? {
        if Instant::now() >= deadline {
            return Err(unavailable(
                "kernel CoW anchor never entered its Worker scope",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn launch(
    c: &Catalog,
    capture: &str,
    op: &str,
    source: &Execution,
    session: u32,
    donor: OwnedFd,
    receipt: &Receipt,
) -> Result<()> {
    if !cfg!(target_arch = "x86_64") || unsafe { libc::geteuid() } != 0 {
        return Err(unavailable(
            "kernel CoW anchor requires a privileged Linux/x86-64 Worker",
        ));
    }
    let source_fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", donor.as_raw_fd()))
        .map_err(unavailable)?;
    let fd_pid = source_fdinfo.lines().find_map(|line| {
        line.strip_prefix("Pid:")
            .and_then(|number| number.trim().parse::<i32>().ok())
    });
    if fd_pid != Some(source.pid)
        || pid_exited(&donor).map_err(unavailable)?
        || pid_start(source.pid).ok() != Some(source.pid_start_time)
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "source pidfd no longer identifies the held execution",
        ));
    }
    let executable_digest = c.bundle(&source.bundle_digest)?;
    let exe = verify_executable(
        source.pid,
        source.pid_start_time,
        &donor,
        &executable_digest,
    )?;
    let file = File::open(format!("/proc/{}/exe", source.pid)).map_err(unavailable)?;
    let meta = file.metadata().map_err(unavailable)?;
    if (meta.dev(), meta.ino()) != exe
        || !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
    {
        return Err(unavailable(
            "registered source does not use a trusted executable",
        ));
    }
    let path = directory(c)?;
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        result => result.map_err(unavailable)?,
    }
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(unavailable)?;
    let helper_id = hex::encode(nonce);
    let _ = command_address(&path, &helper_id).map_err(unavailable)?;
    let slice = crate::worker_scope::configured_slice().map_err(unavailable)?;
    let (parent, child_socket) =
        Socket::pair(Domain::UNIX, Type::SEQPACKET, None).map_err(unavailable)?;
    ipc::set_timeout(&parent).map_err(unavailable)?;
    let mut child = Command::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .arg("_worker-kernel-mm-anchor")
        .env_clear()
        .env("SMOLVM_WORKER_SLICE_NAME", slice)
        .stdin(Stdio::from(OwnedFd::from(child_socket)))
        .stdout(Stdio::null())
        .spawn()
        .map_err(unavailable)?;
    let pid = child.id() as i32;
    let start = (|| {
        let (start, _pidfd) = observe_pid(pid)?;
        enter_scope(pid, &helper_id, slice)?;
        let regions = serde_json::to_string(&receipt.regions).map_err(unavailable)?;
        c.db.execute("INSERT INTO kernel_mm_anchors(
            capture_id,operation_id,source_incarnation,source_epoch,source_session,host_boot_id,
            regions_json,layout_digest,helper_id,helper_pid,helper_start,executable_dev,executable_ino)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            params![capture,op,source.incarnation_id,source.execution_epoch,session,source.host_boot_id,
                regions,receipt.layout_digest,helper_id,pid,start,exe.0 as i64,exe.1 as i64])?;
        // The journal precedes the only transfer of the live source pidfd.
        let init = Init {
            directory: path,
            capture_id: capture.to_owned(),
            helper_id,
            bundle_digest: source.bundle_digest.clone(),
            executable_digest,
            regions: receipt.regions.clone(),
        };
        let body = serde_json::to_vec(&init).map_err(unavailable)?;
        ipc::send_packet(&parent, &body, &[donor]).map_err(unavailable)
    })();
    if start.is_err() {
        drop(parent);
        let _ = child.kill();
        let _ = child.wait();
    }
    start
}

fn reap(pidfd: &OwnedFd) {
    // SAFETY: waitid uses the exact pidfd. ECHILD (after reconnect) is harmless.
    unsafe {
        let mut info = std::mem::zeroed::<libc::siginfo_t>();
        libc::waitid(
            libc::P_PIDFD,
            pidfd.as_raw_fd() as _,
            &mut info,
            libc::WEXITED | libc::WNOHANG,
        );
    }
}

fn process(record: &Record, boot: &str) -> Result<Option<OwnedFd>> {
    if record.host_boot_id != boot {
        return Ok(None);
    }
    match pid_start(record.pid) {
        Ok(start) if start != record.start => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unavailable(error)),
        Ok(_) => {}
    }
    let pidfd = match process_fd(record.pid) {
        Ok(pidfd) => pidfd,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
        Err(error) => return Err(unavailable(error)),
    };
    if pid_exited(&pidfd).map_err(unavailable)? {
        reap(&pidfd);
        return Ok(None);
    }
    match pid_start(record.pid) {
        Ok(start) if start == record.start => Ok(Some(pidfd)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(unavailable(error)),
    }
}

fn connect(c: &Catalog, record: &Record, pidfd: &OwnedFd, command: u8) -> Result<UnixStream> {
    let (_dir, address) =
        command_address(&directory(c)?, &record.helper_id).map_err(unavailable)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(unavailable)?;
    if let Err(error) = socket.connect_timeout(&address, Duration::from_secs(2)) {
        if record.resource_state.is_none()
            && matches!(
                error.kind(),
                io::ErrorKind::NotFound
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::TimedOut
            )
        {
            return Err(pending());
        }
        return Err(unavailable(error));
    }
    ipc::set_timeout(&socket).map_err(unavailable)?;
    let peer = ipc::peer(&socket).map_err(unavailable)?;
    let exe = fs::metadata(format!("/proc/{}/exe", record.pid)).map_err(unavailable)?;
    if peer.pid != record.pid
        || peer.uid != ANCHOR_UID
        || peer.gid != ANCHOR_UID
        || (exe.dev(), exe.ino()) != record.exe
        || !in_scope(record.pid, &record.helper_id).map_err(unavailable)?
        || pid_start(record.pid).ok() != Some(record.start)
        || pid_exited(pidfd).map_err(unavailable)?
    {
        return Err(unavailable(
            "kernel CoW helper identity could not be authenticated",
        ));
    }
    let mut stream = UnixStream::from(OwnedFd::from(socket));
    stream.write_all(&[command]).map_err(unavailable)?;
    let mut ready = [0];
    stream.read_exact(&mut ready).map_err(unavailable)?;
    if ready != [b'+'] {
        return Err(unavailable("invalid kernel CoW helper response"));
    }
    Ok(stream)
}

fn mark_lost(c: &Catalog, record: &Record) -> Result<()> {
    let tx = Transaction::new_unchecked(&c.db, TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE kernel_mm_anchors SET failure='original anchor process exited' WHERE capture_id=? AND failure IS NULL",
        [&record.capture_id],
    )?;
    tx.execute(
        "UPDATE resources SET state='lost',revision=revision+1 WHERE state='available'
         AND resource_id=(SELECT resource_id FROM kernel_mm_anchors WHERE capture_id=?)",
        [&record.capture_id],
    )?;
    tx.execute(
        "UPDATE root_refs SET state='dropped',revision=revision+1 WHERE resource_id=?
         AND owner_kind='kernel_anchor_export' AND state='active'",
        [&record.capture_id],
    )?;
    if record.resource_state.is_some() {
        // The batch cannot retry this cut. Each dispatched child keeps its
        // own operation references until its separate launch resolves.
        tx.execute(
            "UPDATE root_refs SET state='dropped',revision=revision+1
             WHERE owner_kind='fork_capture' AND owner_id=? AND state='active'",
            [&record.operation_id],
        )?;
    }
    tx.commit()?;
    remove_socket(c, record)
}

fn remove_socket(c: &Catalog, record: &Record) -> Result<()> {
    if !valid_helper_id(&record.helper_id) {
        return Err(unavailable("invalid recorded helper identity"));
    }
    let path = directory(c)?.join(format!("{}.sock", record.helper_id));
    match fs::remove_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result.map_err(unavailable),
    }
}

fn stopped_or_live(c: &Catalog, record: &Record) -> Result<OwnedFd> {
    if record.failed
        || record
            .resource_state
            .as_deref()
            .is_some_and(|state| state != "available")
    {
        return Err(lost());
    }
    let Some(fd) = process(record, &boot_id(c)?)? else {
        mark_lost(c, record)?;
        return Err(lost());
    };
    Ok(fd)
}

pub(crate) fn register(
    c: &Catalog,
    operation_id: &str,
    capture_id: &str,
    source: &Execution,
    source_pidfd: OwnedFd,
    layout: &[Region],
) -> Result<Receipt> {
    let packed = packed_size(layout).map_err(Fault::invalid)?;
    let (session, kind, memory_mib): (u32, String, u32) =
        c.db.query_row(
            "SELECT b.session,o.kind,json_extract(b.template,'$.memory_mib')
         FROM managed_fork_batches b JOIN operations o USING(operation_id)
         WHERE b.capture_id=? AND b.operation_id=? AND b.source_incarnation=?
          AND b.stage IN ('exporting','durable_hold','checkpoint_export')
          AND b.selected_memory_fork_backend='kernel_cow' AND o.bundle_digest=?
          AND o.expected_execution_epoch=? AND o.phase='NEW'",
            params![
                capture_id,
                operation_id,
                source.incarnation_id,
                source.bundle_digest,
                source.execution_epoch
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| {
            Fault::new(
                "E_STALE_EXECUTION",
                "kernel CoW anchor is outside the admitted capture",
            )
        })?;
    let ram_limit =
        crate::admission::kernel_capture_ram_mib(memory_mib.into()).saturating_mul(1 << 20);
    if packed > ram_limit || source.host_boot_id != boot_id(c)? {
        return Err(Fault::invalid(
            "kernel CoW RAM differs from the admitted size or boot",
        ));
    }
    let layout_digest = digest(
        &serde_json::to_vec(&json!({"profile":PROFILE, "regions":layout})).map_err(unavailable)?,
    );
    let record = match lookup(c, capture_id)? {
        Some(record) => record,
        None => {
            if source.phase != "registered"
                || c.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM resources WHERE resource_id=?)",
                    [capture_id],
                    |row| row.get::<_, bool>(0),
                )?
            {
                return Err(Fault::new(
                    "E_STATE_CONFLICT",
                    "anchor ID or current execution is unavailable",
                ));
            }
            launch(
                c,
                capture_id,
                operation_id,
                source,
                session,
                source_pidfd,
                &Receipt {
                    regions: layout.to_vec(),
                    layout_digest: layout_digest.clone(),
                },
            )?;
            lookup(c, capture_id)?.ok_or_else(pending)?
        }
    };
    if record.operation_id != operation_id
        || record.source_incarnation != source.incarnation_id
        || record.source_epoch != source.execution_epoch
        || record.source_session != session
        || record.receipt.layout_digest != layout_digest
        || record.receipt.regions != layout
    {
        return Err(Fault::new(
            "E_IDEMPOTENCY_CONFLICT",
            "kernel CoW capture binding changed",
        ));
    }
    let pidfd = stopped_or_live(c, &record)?;
    connect(c, &record, &pidfd, b'Q')?;
    if record.resource_state.is_none() {
        let owner = if matches!(kind.as_str(), "independent_fork" | "fork_batch") {
            "fork_capture"
        } else {
            "kernel_anchor_export"
        };
        let descriptor = json!({
            "schema": "KernelMmAnchor/1", "capture_id": capture_id, "profile": PROFILE,
            "layout_digest": layout_digest, "regions": layout, "source_incarnation": source.incarnation_id,
            "source_epoch": source.execution_epoch, "source_session": session, "memory_bytes": packed,
        }).to_string();
        let tx = Transaction::new_unchecked(&c.db, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO resources VALUES(?,'descriptor','available','volatile',1,?,?,?,1)",
            params![
                capture_id,
                descriptor,
                digest(descriptor.as_bytes()),
                operation_id
            ],
        )?;
        tx.execute(
            "INSERT INTO root_refs VALUES(?,?,?,'active',1,?)",
            params![owner, operation_id, capture_id, operation_id],
        )?;
        tx.execute(
            "UPDATE kernel_mm_anchors SET resource_id=? WHERE capture_id=?",
            params![capture_id, capture_id],
        )?;
        tx.commit()?;
    }
    Ok(record.receipt)
}

fn pinned(c: &Catalog, operation_id: &str, capture_id: &str) -> Result<Record> {
    let record = lookup(c, capture_id)?.ok_or_else(lost)?;
    if record.operation_id != operation_id {
        return Err(Fault::new(
            "E_NOT_FOUND",
            "kernel CoW anchor belongs to another capture operation",
        ));
    }
    if record.resource_state.as_deref() != Some("available")
        || !c.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM root_refs WHERE resource_id=? AND state='active')",
            [capture_id],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(lost());
    }
    Ok(record)
}

pub(crate) fn acquire(
    c: &Catalog,
    operation_id: &str,
    capture_id: &str,
) -> Result<(Receipt, OwnedFd)> {
    let record = pinned(c, operation_id, capture_id)?;
    let pidfd = stopped_or_live(c, &record)?;
    connect(c, &record, &pidfd, b'Q')?;
    Ok((record.receipt, pidfd))
}

pub(crate) struct RamReader {
    stream: UnixStream,
    remaining: u64,
}

impl Read for RamReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.remaining.min(output.len() as u64) as usize;
        if count == 0 {
            return Ok(0);
        }
        self.stream.read_exact(&mut output[..count])?;
        self.remaining -= count as u64;
        if self.remaining == 0 {
            let mut marker = [0];
            self.stream.read_exact(&mut marker)?;
            if marker != [b'+'] {
                return Err(io::Error::other(
                    "kernel CoW anchor export did not complete",
                ));
            }
        }
        Ok(count)
    }
}

pub(crate) fn open_export(
    c: &Catalog,
    operation: &str,
    capture: &str,
) -> Result<(Receipt, RamReader)> {
    let record = pinned(c, operation, capture)?;
    let pidfd = stopped_or_live(c, &record)?;
    let stream = connect(c, &record, &pidfd, b'R')?;
    stream
        .set_read_timeout(Some(Duration::from_secs(90)))
        .map_err(unavailable)?;
    let remaining = packed_size(&record.receipt.regions).map_err(Fault::invalid)?;
    Ok((record.receipt, RamReader { stream, remaining }))
}

pub(crate) fn require_volatile_export(c: &Catalog, capture: &str) -> Result<()> {
    if let Some(record) = lookup(c, capture)? {
        let _pidfd = stopped_or_live(c, &record)?;
    }
    Ok(())
}

/// Before abandoning the held source, prove that any helper which was given
/// its donor pidfd either completed the import or has exited.
pub(crate) fn quiesce_unpublished(c: &Catalog, operation: &str, capture: &str) -> Result<()> {
    if let Some(record) = lookup(c, capture)? {
        if record.operation_id != operation {
            return Err(Fault::new(
                "E_NOT_FOUND",
                "kernel CoW anchor belongs to another capture operation",
            ));
        }
        if record.resource_state.is_none() && !record.failed {
            if let Some(pidfd) = process(&record, &boot_id(c)?)? {
                terminate(&record, &pidfd)?;
                return Err(pending());
            }
            mark_lost(c, &record)?;
        }
    }
    Ok(())
}

pub(crate) fn release_export(tx: &Transaction<'_>, operation: &str, capture: &str) -> Result<()> {
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1
        WHERE resource_id=? AND owner_kind='kernel_anchor_export' AND owner_id=? AND state='active'",
        params![capture,operation])?;
    Ok(())
}

fn terminate(record: &Record, pidfd: &OwnedFd) -> Result<()> {
    let executable = fs::metadata(format!("/proc/{}/exe", record.pid));
    if pid_exited(pidfd).map_err(unavailable)? {
        return Ok(());
    }
    let executable = executable.map_err(unavailable)?;
    if (executable.dev(), executable.ino()) != record.exe
        || !in_scope(record.pid, &record.helper_id).map_err(unavailable)?
        || pid_start(record.pid).ok() != Some(record.start)
    {
        return Err(unavailable("kernel CoW helper exit cannot be fenced"));
    }
    // SAFETY: the pidfd identifies only the authenticated helper.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(unavailable(error));
        }
    }
    Ok(())
}

pub(crate) fn collect(c: &Catalog, resource: &str) -> Result<()> {
    let Some(record) = lookup(c, resource)?.filter(|record| record.resource_state.is_some()) else {
        return Ok(());
    };
    if let Some(pidfd) = process(&record, &boot_id(c)?)? {
        terminate(&record, &pidfd)?;
        return Err(Fault::new(
            "E_OPERATION_IN_PROGRESS",
            "waiting for the RAM anchor to exit",
        ));
    }
    remove_socket(c, &record)
}

pub(crate) fn reconcile(c: &Catalog) -> Result<()> {
    let boot = boot_id(c)?;
    let mut query = c.db.prepare(
        "SELECT a.capture_id,o.phase='NEW'
        FROM kernel_mm_anchors a JOIN operations o USING(operation_id)
        LEFT JOIN resources r ON r.resource_id=a.resource_id
        WHERE a.failure IS NULL AND (r.state IS NULL OR r.state IN ('available','lost'))",
    )?;
    let rows = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(query);
    for (id, active) in rows {
        let Some(record) = lookup(c, &id)? else {
            continue;
        };
        let Some(pidfd) = process(&record, &boot)? else {
            mark_lost(c, &record)?;
            continue;
        };
        if record.resource_state.is_none() && !active {
            terminate(&record, &pidfd)?;
        }
    }
    // Mark only anchors that have no references. Existing Worker GC reaps
    // the helper after the deletion fence and confirms its actual exit.
    c.db.execute("UPDATE resources SET state='deleting',revision=revision+1
        WHERE state='available' AND EXISTS(SELECT 1 FROM kernel_mm_anchors a WHERE a.resource_id=resources.resource_id)
         AND EXISTS(SELECT 1 FROM operations o WHERE o.operation_id=resources.created_by_operation
           AND o.phase IN ('COMPLETED','ABORTED'))
         AND NOT EXISTS(SELECT 1 FROM root_refs p WHERE p.resource_id=resources.resource_id AND p.state='active')
         AND NOT EXISTS(SELECT 1 FROM resource_edges e WHERE e.child_resource_id=resources.resource_id)
         AND NOT EXISTS(SELECT 1 FROM fd_leases f WHERE f.resource_id=resources.resource_id AND f.state<>'released')
         AND NOT EXISTS(SELECT 1 FROM writer_reservations w WHERE w.head_resource_id=resources.resource_id)", [])?;
    Ok(())
}
