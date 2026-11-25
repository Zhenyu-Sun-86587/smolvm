//! Observe and drive the live VMM over a process-authenticated native socket.
use crate::catalog::{Catalog, Execution};
use crate::ipc::{self, Fault, Result};
use crate::worker::{observe_pid, pid_exited, pid_start, verify_executable};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use socket2::{Domain, SockAddr, Socket, Type};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub control_socket: PathBuf,
}

pub(crate) struct Endpoint {
    path: PathBuf,
    pid: i32,
    uid: u32,
    start: i64,
    dev: u64,
    ino: u64,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Inventory {
    protocol: String,
    pub source_disposition: String,
    pub last_session: u32,
    pub guest_gate: String,
    pub measured_helper: bool,
    pub devices: Vec<Value>,
}

fn unavailable(error: impl std::fmt::Display) -> Fault {
    Fault::new(
        "E_NATIVE_UNAVAILABLE",
        format!("native VMM control: {error}"),
    )
}
fn stale() -> Fault {
    Fault::new(
        "E_STALE_EXECUTION",
        "native control no longer belongs to the registered VMM",
    )
}

impl Endpoint {
    pub fn bind(
        catalog: &Catalog,
        execution: &Execution,
        path: &Path,
        boot: &str,
    ) -> Result<Inventory> {
        if execution.host_boot_id != boot || execution.phase != "registered" || !path.is_absolute()
        {
            return Err(stale());
        }
        // Pin the actual running executable before accepting this path. The
        // kernel supplies the server credentials separately on every connect.
        let (start, pidfd) = observe_pid(execution.pid)?;
        if start != execution.pid_start_time {
            return Err(stale());
        }
        let (dev, ino) = verify_executable(
            execution.pid,
            start,
            &pidfd,
            &catalog.bundle(&execution.bundle_digest)?,
        )?;
        let endpoint = Self {
            path: path.into(),
            pid: execution.pid,
            uid: execution.uid,
            start,
            dev,
            ino,
        };
        let inventory = endpoint.inventory()?;
        let path = path
            .to_str()
            .ok_or_else(|| Fault::invalid("native control path must be UTF-8"))?;
        let changed=catalog.db.execute("INSERT INTO native_endpoints(incarnation_id,control_socket,executable_dev,executable_ino)
            VALUES(?,?,?,?) ON CONFLICT(incarnation_id) DO UPDATE SET control_socket=excluded.control_socket
            WHERE control_socket=excluded.control_socket AND executable_dev=excluded.executable_dev AND executable_ino=excluded.executable_ino",
            params![execution.incarnation_id,path,endpoint.dev as i64,endpoint.ino as i64])?;
        if changed == 0 {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "native VMM endpoint already bound",
            ));
        }
        Ok(inventory)
    }
    pub fn load(db: &rusqlite::Connection, incarnation: &str, boot: &str) -> Result<Self> {
        Self::load_phase(db, incarnation, boot, "registered")
    }
    fn load_phase(
        db: &rusqlite::Connection,
        incarnation: &str,
        boot: &str,
        phase: &str,
    ) -> Result<Self> {
        db.query_row(
            "SELECT c.control_socket,e.pid,e.uid,e.pid_start_time,c.executable_dev,c.executable_ino
            FROM native_endpoints c JOIN executions e USING(incarnation_id)
            JOIN instance_bindings b ON b.route_id=e.route_id AND b.instance_id=e.instance_id
              AND b.incarnation_id=e.incarnation_id AND b.execution_epoch=e.execution_epoch
            WHERE e.incarnation_id=? AND e.host_boot_id=? AND e.phase=?",
            params![incarnation, boot, phase],
            |r| {
                Ok(Self {
                    path: PathBuf::from(r.get::<_, String>(0)?),
                    pid: r.get(1)?,
                    uid: r.get(2)?,
                    start: r.get(3)?,
                    dev: r.get::<_, i64>(4)? as u64,
                    ino: r.get::<_, i64>(5)? as u64,
                })
            },
        )
        .optional()?
        .ok_or_else(|| {
            Fault::new(
                "E_NATIVE_UNBOUND",
                "current execution has no reconciled native endpoint",
            )
        })
    }
    pub(crate) fn recovery_peer(
        db: &rusqlite::Connection,
        id: &str,
        boot: &str,
    ) -> Result<libc::ucred> {
        let endpoint = Self::load_phase(db, id, boot, "unknown")?;
        let (socket, _pidfd) = endpoint.connect()?;
        ipc::peer(&socket).map_err(unavailable)
    }
    fn connect(&self) -> Result<(Socket, OwnedFd)> {
        let (start, pidfd) = observe_pid(self.pid)?;
        if start != self.start {
            return Err(stale());
        }
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None).map_err(unavailable)?;
        socket
            .connect_timeout(
                &SockAddr::unix(&self.path).map_err(unavailable)?,
                Duration::from_secs(2),
            )
            .map_err(unavailable)?;
        ipc::set_timeout(&socket).map_err(unavailable)?;
        let peer = ipc::peer(&socket).map_err(unavailable)?;
        let meta = fs::metadata(format!("/proc/{}/exe", self.pid)).map_err(unavailable)?;
        if peer.pid != self.pid
            || peer.uid != self.uid
            || meta.dev() != self.dev
            || meta.ino() != self.ino
            || pid_start(self.pid).ok() != Some(self.start)
            || pid_exited(&pidfd).map_err(unavailable)?
        {
            return Err(stale());
        }
        Ok((socket, pidfd))
    }
    pub fn command(&self, line: &str) -> Result<String> {
        let (socket, pidfd) = self.connect()?;
        let mut stream = std::os::unix::net::UnixStream::from(OwnedFd::from(socket));
        writeln!(stream, "{line}").map_err(unavailable)?;
        let mut response = String::new();
        let mut reader = BufReader::new(stream).take(65537);
        reader.read_line(&mut response).map_err(unavailable)?;
        if !response.ends_with('\n') || response.len() > 65536 {
            return Err(unavailable("incomplete or oversized reply"));
        }
        if pid_exited(&pidfd).map_err(unavailable)? {
            return Err(stale());
        }
        let answer = response.trim_end();
        if let Some(detail) = answer.strip_prefix("ERR ") {
            return Err(Fault::new(
                "E_NATIVE_REFUSED",
                detail.chars().take(384).collect::<String>(),
            ));
        }
        answer
            .strip_prefix("OK ")
            .map(str::to_owned)
            .ok_or_else(|| unavailable("invalid native response"))
    }
    pub fn inventory(&self) -> Result<Inventory> {
        let result: Inventory = serde_json::from_str(&self.command("CAPTURE_INVENTORY")?)
            .map_err(|_| unavailable("unrecognized native inventory format"))?;
        if result.protocol != "CaptureControl/1" || result.devices.is_empty() {
            return Err(unavailable("incomplete native inventory"));
        }
        Ok(result)
    }
}

pub(crate) fn actor_db(path: &Path) -> io::Result<rusqlite::Connection> {
    let db = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(io::Error::other)?;
    db.busy_timeout(Duration::from_secs(2))
        .map_err(io::Error::other)?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL")
        .map_err(io::Error::other)?;
    Ok(db)
}
