use crate::catalog::{Catalog, Execution, NewExecution, VolumeHead};
use crate::escrow::Escrow;
use crate::ipc::{self, valid_digest, valid_id, Expected, Fault, Request, Result, PROTOCOL};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socket2::{SockAddr, Socket};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        socket_gid: Option<u32>,
        #[arg(long)]
        admin_uid: Option<u32>,
    },
    Call {
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    executable_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    abort: bool,
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    pid: i32,
    uid: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    launch_permit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    broker_session_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    resource_id: String,
    durability: String,
    descriptor: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceId {
    resource_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edge {
    owner_resource_id: String,
    child_resource_id: String,
    role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    owner_kind: String,
    owner_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootRef {
    owner_kind: String,
    owner_id: String,
    resource_id: String,
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Gc {
    resource_id: String,
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Heads {
    heads: Vec<VolumeHead>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    expected_revision: i64,
}

struct Permit {
    operation: String,
    expected: Expected,
    uid: u32,
    pid: i32,
    start: i64,
    pidfd: OwnedFd,
    expires: Instant,
}

struct Worker {
    catalog: Catalog,
    objects: File,
    boot: String,
    admin_uid: u32,
    permits: HashMap<String, Permit>,
    executions: HashMap<String, OwnedFd>,
    reserved: HashMap<String, Vec<File>>,
    escrow: Escrow,
}

struct Reply {
    result: Value,
    table: Vec<ipc::FdEntry>,
    descriptors: Vec<OwnedFd>,
    delivered: Option<(String, usize)>,
}

impl From<Value> for Reply {
    fn from(result: Value) -> Self {
        Self {
            result,
            table: Vec::new(),
            descriptors: Vec::new(),
            delivered: None,
        }
    }
}

fn idempotency_fault() -> Fault {
    Fault::new(
        "E_IDEMPOTENCY_CONFLICT",
        "writer reservation already has a different head set",
    )
}

fn stale_execution() -> Fault {
    Fault::new(
        "E_STALE_EXECUTION",
        "execution ID, epoch or process identity changed",
    )
}

fn unsafe_fence() -> Fault {
    Fault::new(
        "E_FENCE_UNPROVEN",
        "execution exit has not been established",
    )
}

fn broker_error(error: io::Error) -> Fault {
    eprintln!("resourced host error: {error}");
    Fault::new("E_HOST_IO", "worker host operation failed")
}

fn token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| Fault::new("E_HOST_IO", "could not generate random worker credentials"))?;
    Ok(hex::encode(bytes))
}

fn pid_start(pid: i32) -> io::Result<i64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|token| token.parse::<i64>().ok())
        .filter(|start| *start > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))
}

fn pid_exited(pidfd: &OwnedFd) -> io::Result<bool> {
    let mut entry = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut entry, 1, 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else if entry.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
        Err(io::Error::other("invalid pidfd"))
    } else {
        Ok(entry.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }
}

fn observe_pid(pid: i32) -> Result<(i64, OwnedFd)> {
    if pid <= 0 {
        return Err(Fault::invalid("pid must be positive"));
    }
    let before = pid_start(pid).map_err(|_| stale_execution())?;
    // pidfd_open yields an owned kernel reference that survives numeric PID reuse.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if raw < 0 {
        return Err(broker_error(io::Error::last_os_error()));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    if pid_start(pid).ok() != Some(before) || pid_exited(&pidfd).map_err(broker_error)? {
        return Err(stale_execution());
    }
    Ok((before, pidfd))
}

fn verify_executable(pid: i32, start: i64, pidfd: &OwnedFd, wanted: &str) -> Result<()> {
    let path = format!("/proc/{pid}/exe");
    let mut file = File::open(&path).map_err(broker_error)?;
    let original = file.metadata().map_err(broker_error)?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest).map_err(broker_error)?;
    let current = fs::metadata(path).map_err(broker_error)?;
    if original.dev() != current.dev()
        || original.ino() != current.ino()
        || pid_start(pid).ok() != Some(start)
        || pid_exited(pidfd).map_err(broker_error)?
    {
        return Err(stale_execution());
    }
    if format!("sha256:{:x}", digest.finalize()) != wanted {
        return Err(Fault::new(
            "E_BUNDLE_UNAVAILABLE",
            "peer executable does not match registered bundle",
        ));
    }
    Ok(())
}

fn openat(parent: &File, name: &str, flags: i32) -> io::Result<File> {
    let name = CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn ofd_lock(file: &File) -> Result<()> {
    let lock = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) } < 0 {
        let error = io::Error::last_os_error();
        return Err(
            if matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EACCES)) {
                Fault::new(
                    "E_VOLUME_WRITER_CONFLICT",
                    "an open file description already locks this backing",
                )
            } else {
                broker_error(error)
            },
        );
    }
    Ok(())
}

impl Worker {
    fn packet(
        &mut self,
        request: &Request,
        peer: libc::ucred,
        descriptors: Vec<OwnedFd>,
    ) -> Result<Reply> {
        request.check()?;
        if request.method != "RegisterGenerationBatch"
            && (!descriptors.is_empty() || !request.fd_table.is_empty())
        {
            return Err(Fault::new(
                "E_CAPABILITY_UNSUPPORTED",
                "this method does not accept descriptors",
            ));
        }
        let result = match request.method.as_str() {
            "RegisterGenerationBegin"
            | "RegisterGenerationBatch"
            | "RegisterGenerationCommit"
            | "AbortGenerationTransfer"
            | "AcquireResourceLease"
            | "AckAttached"
            | "ReleaseResourceLease" => {
                let execution = self.authenticated_execution(request, peer)?;
                match request.method.as_str() {
                    "RegisterGenerationBegin" => {
                        self.escrow.begin(&self.catalog, request, &execution)
                    }
                    "RegisterGenerationBatch" => {
                        self.escrow
                            .batch(&self.catalog, request, &execution, descriptors)
                    }
                    "RegisterGenerationCommit" => {
                        self.escrow.commit(&mut self.catalog, request, &execution)
                    }
                    "AbortGenerationTransfer" => {
                        self.escrow.abort(&self.catalog, request, &execution)
                    }
                    "AcquireResourceLease" => {
                        let lease = self
                            .escrow
                            .acquire(&mut self.catalog, request, &execution)?;
                        return Ok(Reply {
                            result: lease.result,
                            table: lease.fd_table,
                            descriptors: lease.fds,
                            delivered: Some(lease.delivered),
                        });
                    }
                    _ => self.escrow.update_lease(
                        &mut self.catalog,
                        request,
                        &execution,
                        request.method == "ReleaseResourceLease",
                    ),
                }
            }
            _ => self.handle(request, peer),
        }?;
        Ok(result.into())
    }

    fn handle(&mut self, request: &Request, peer: libc::ucred) -> Result<Value> {
        match request.method.as_str() {
            "RegisterExecution" => return self.register_execution(request, peer),
            "ReconcileExecution" => return self.reconcile_execution(request, peer),
            _ => {}
        }
        if peer.uid != self.admin_uid && peer.uid != unsafe { libc::geteuid() } {
            return Err(Fault::new(
                "E_PERMISSION_DENIED",
                "registered worker control UID required",
            ));
        }
        match request.method.as_str() {
            "Health" => self.catalog.health(),
            "RegisterBundle" => {
                let bundle = request
                    .bundle_digest
                    .as_deref()
                    .ok_or_else(|| Fault::invalid("bundle_digest is required"))?;
                let info: Bundle = request.payload()?;
                if !valid_digest(&info.executable_sha256) {
                    return Err(Fault::invalid("invalid executable digest"));
                }
                self.catalog
                    .register_bundle(bundle, &info.executable_sha256)
            }
            "BeginOperation" => {
                let data: Begin = request.payload()?;
                if !matches!(
                    data.kind.as_str(),
                    "catalog" | "launch" | "writer_reservation" | "generation" | "resource_lease"
                ) {
                    return Err(Fault::new(
                        "E_CAPABILITY_UNSUPPORTED",
                        "operation kind is unavailable",
                    ));
                }
                Ok(json!(self.catalog.begin(request, &data.kind)?))
            }
            "QueryOperation" => {
                let route = request
                    .route_id
                    .as_deref()
                    .ok_or_else(|| Fault::invalid("route_id is required"))?;
                let bundle = request
                    .bundle_digest
                    .as_deref()
                    .ok_or_else(|| Fault::invalid("bundle_digest is required"))?;
                let operation = self.catalog.operation(required_operation_id(request)?)?;
                if operation.route_id != route || operation.bundle_digest != bundle {
                    return Err(Fault::new(
                        "E_NOT_FOUND",
                        "operation does not exist in this runtime route and bundle",
                    ));
                }
                Ok(json!(operation))
            }
            "FinishOperation" => {
                let outcome: Finish = request.payload()?;
                let operation =
                    self.catalog
                        .finish(request, outcome.abort, outcome.expected_revision)?;
                self.permits
                    .retain(|_, permit| permit.operation != operation.operation_id);
                Ok(json!(operation))
            }
            "IssueLaunchPermit" => self.issue_permit(request),
            "QueryExecution" => Ok(json!(self.scoped_execution(request)?)),
            "FinalizeExecutionExit" => self.finalize_execution(request),
            "CompleteRecovery" => {
                let session: Session = request.payload()?;
                self.catalog.complete_recovery(&session.broker_session_id)
            }
            "RegisterResource" => {
                let data: Resource = request.payload()?;
                self.catalog.register_resource(
                    request,
                    &data.resource_id,
                    &data.durability,
                    data.descriptor,
                )
            }
            "QueryResource" => {
                let data: ResourceId = request.payload()?;
                self.catalog.resource(&data.resource_id)
            }
            "AddResourceEdge" => {
                let data: Edge = request.payload()?;
                self.catalog.add_edge(
                    request,
                    &data.owner_resource_id,
                    &data.child_resource_id,
                    &data.role,
                )
            }
            "AddOwnerRef" | "DropOwnerRef" => {
                let data: RootRef = request.payload()?;
                self.catalog.set_ref(
                    request,
                    &data.owner_kind,
                    &data.owner_id,
                    &data.resource_id,
                    data.expected_revision,
                    request.method == "AddOwnerRef",
                )
            }
            "QueryOwnerClosure" => {
                let data: Owner = request.payload()?;
                self.catalog.closure(&data.owner_kind, &data.owner_id)
            }
            "MarkResourceForGC" | "CollectResource" => {
                let data: Gc = request.payload()?;
                let collect = request.method == "CollectResource";
                let result = self
                    .catalog
                    .gc(&data.resource_id, data.expected_revision, collect)?;
                if collect {
                    self.escrow.collect(&data.resource_id);
                }
                Ok(result)
            }
            "RegisterVolumeHead" => {
                self.catalog.ready()?;
                let head: VolumeHead = request.payload()?;
                let (_, identity) = self.open_backing(&head.head_resource_id)?;
                self.catalog.register_volume(request, &head, &identity)
            }
            "ReserveWriterSet" => self.reserve(request),
            "QueryWriterSet" => self.writer_status(required_operation_id(request)?),
            "ReleaseWriterReservation" => {
                let operation = self.catalog.matching_operation(request)?;
                let (_, _, expected) = request.scope()?;
                let revision: Revision = request.payload()?;
                if operation.expected_execution_epoch != expected.execution_epoch
                    || operation.expected_incarnation_id != expected.incarnation_id
                {
                    return Err(stale_execution());
                }
                self.catalog
                    .release_reservation(&operation.operation_id, revision.expected_revision)?;
                self.reserved.remove(&operation.operation_id);
                self.writer_status(&operation.operation_id)
            }
            _ => Err(Fault::new(
                "E_CAPABILITY_UNSUPPORTED",
                "worker resource method is unavailable",
            )),
        }
    }

    fn issue_permit(&mut self, r: &Request) -> Result<Value> {
        let (_, bundle, expected) = r.scope()?;
        let op = self.catalog.matching_operation(r)?;
        if op.kind != "launch" {
            return Err(Fault::invalid("launch permits require a launch operation"));
        }
        self.catalog.verify_launch(&op, expected)?;
        let target: Target = r.payload()?;
        self.permits.retain(|_, p| p.expires > Instant::now());
        if let Some((credential, prior)) = self
            .permits
            .iter()
            .find(|(_, permit)| permit.operation == op.operation_id)
        {
            if prior.expected != *expected || prior.uid != target.uid || prior.pid != target.pid {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "launch permit already names a different target",
                ));
            }
            return Ok(json!({"launch_permit":credential, "pid_start_time":prior.start}));
        }
        if self.permits.len() >= 256 {
            return Err(Fault::new(
                "E_RESOURCE_LIMIT",
                "too many pending launch permits",
            ));
        }
        let (start, pidfd) = observe_pid(target.pid)?;
        verify_executable(target.pid, start, &pidfd, &self.catalog.bundle(bundle)?)?;
        let credential = token()?;
        self.permits.insert(
            credential.clone(),
            Permit {
                operation: op.operation_id,
                expected: expected.clone(),
                uid: target.uid,
                pid: target.pid,
                start,
                pidfd,
                expires: Instant::now() + Duration::from_secs(60),
            },
        );
        Ok(json!({"launch_permit":credential, "pid_start_time":start}))
    }

    fn register_execution(&mut self, r: &Request, peer: libc::ucred) -> Result<Value> {
        let (route, bundle, expected) = r.scope()?;
        let op = self.catalog.matching_operation(r)?;
        let supplied: Token = r.payload()?;
        let permit_digest = format!(
            "sha256:{:x}",
            Sha256::digest(supplied.launch_permit.as_bytes())
        );
        let id = expected
            .incarnation_id
            .as_deref()
            .ok_or_else(stale_execution)?;
        if let Some(execution) = self.catalog.execution_by_permit(id, &permit_digest)? {
            if !execution.matches(route, bundle, expected)
                || execution.last_operation_id != op.operation_id
            {
                return Err(stale_execution());
            }
            let execution = self.confirm_execution_identity(execution, peer)?;
            return Ok(
                json!({"execution":execution,"network_state":"closed","network_enforcement_observed":false}),
            );
        }
        let permit = self
            .permits
            .get(&supplied.launch_permit)
            .filter(|p| {
                p.operation == op.operation_id
                    && p.expected == *expected
                    && p.pid == peer.pid
                    && p.uid == peer.uid
                    && p.expires > Instant::now()
            })
            .ok_or_else(|| {
                Fault::new(
                    "E_LAUNCH_PERMIT",
                    "valid launch permit and matching peer required",
                )
            })?;
        verify_executable(
            peer.pid,
            permit.start,
            &permit.pidfd,
            &self.catalog.bundle(bundle)?,
        )?;
        let execution = self.catalog.register_execution(
            &op,
            NewExecution {
                route,
                bundle,
                expected,
                boot: &self.boot,
                pid: peer.pid,
                start: permit.start,
                uid: peer.uid,
                permit_digest: &permit_digest,
            },
        )?;
        let permit = self
            .permits
            .remove(&supplied.launch_permit)
            .expect("validated permit exists");
        self.executions
            .insert(execution.incarnation_id.clone(), permit.pidfd);
        Ok(
            json!({"execution":execution,"network_state":"closed","network_enforcement_observed":false}),
        )
    }

    fn scoped_execution(&self, r: &Request) -> Result<Execution> {
        let (route, bundle, expected) = r.scope()?;
        let id = expected
            .incarnation_id
            .as_deref()
            .ok_or_else(stale_execution)?;
        let execution = self.catalog.execution(id)?;
        if !execution.matches(route, bundle, expected) {
            return Err(stale_execution());
        }
        Ok(execution)
    }

    fn authenticated_execution(&self, request: &Request, peer: libc::ucred) -> Result<Execution> {
        let execution = self.scoped_execution(request)?;
        if execution.phase != "registered"
            || execution.host_boot_id != self.boot
            || execution.pid != peer.pid
            || execution.uid != peer.uid
        {
            return Err(Fault::new(
                "E_PERMISSION_DENIED",
                "descriptor operation requires the recorded execution peer",
            ));
        }
        let pidfd = self
            .executions
            .get(&execution.incarnation_id)
            .ok_or_else(stale_execution)?;
        verify_executable(
            peer.pid,
            execution.pid_start_time,
            pidfd,
            &self.catalog.bundle(&execution.bundle_digest)?,
        )?;
        Ok(execution)
    }

    fn reconcile_execution(&mut self, r: &Request, peer: libc::ucred) -> Result<Value> {
        let execution = self.scoped_execution(r)?;
        Ok(json!(self.confirm_execution_identity(execution, peer)?))
    }

    fn confirm_execution_identity(
        &mut self,
        execution: Execution,
        peer: libc::ucred,
    ) -> Result<Execution> {
        if execution.phase == "exited"
            || execution.host_boot_id != self.boot
            || execution.pid != peer.pid
            || execution.uid != peer.uid
        {
            return Err(stale_execution());
        }
        let (start, pidfd) = observe_pid(peer.pid)?;
        if start != execution.pid_start_time {
            return Err(stale_execution());
        }
        verify_executable(
            peer.pid,
            start,
            &pidfd,
            &self.catalog.bundle(&execution.bundle_digest)?,
        )?;
        let result = self
            .catalog
            .reconcile_execution(&execution.incarnation_id)?;
        self.executions.insert(execution.incarnation_id, pidfd);
        Ok(result)
    }

    fn finalize_execution(&mut self, r: &Request) -> Result<Value> {
        let execution = self.scoped_execution(r)?;
        if execution.phase == "exited" {
            return Ok(json!(execution));
        }
        if execution.host_boot_id == self.boot {
            let dead = match self.executions.get(&execution.incarnation_id) {
                Some(pidfd) => pid_exited(pidfd).map_err(broker_error)?,
                None => match pid_start(execution.pid) {
                    Ok(start) => start != execution.pid_start_time,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                    Err(error) => return Err(broker_error(error)),
                },
            };
            if !dead {
                return Err(unsafe_fence());
            }
        }
        let result = self.catalog.finalize_execution(&execution)?;
        self.executions.remove(&execution.incarnation_id);
        self.escrow.forget_execution(&execution.incarnation_id);
        Ok(json!(result))
    }

    fn open_backing(&self, resource: &str) -> Result<(File, String)> {
        if !valid_id(resource) {
            return Err(Fault::invalid("invalid head resource identifier"));
        }
        let directory = openat(&self.objects, resource, libc::O_RDONLY | libc::O_DIRECTORY)
            .map_err(broker_error)?;
        let file =
            openat(&directory, "data", libc::O_RDWR | libc::O_NONBLOCK).map_err(broker_error)?;
        let metadata = file.metadata().map_err(broker_error)?;
        if !metadata.is_file() {
            return Err(Fault::invalid(
                "volume backing must be a managed regular file",
            ));
        }
        Ok((file, format!("inode:{}:{}", metadata.dev(), metadata.ino())))
    }

    fn reserve(&mut self, r: &Request) -> Result<Value> {
        let op = self.catalog.active_operation(r)?;
        if op.kind != "writer_reservation" {
            return Err(Fault::invalid(
                "writer reservation requires a writer_reservation operation",
            ));
        }
        let Heads { mut heads } = r.payload()?;
        if heads.is_empty() || heads.len() > 64 {
            return Err(Fault::invalid(
                "writer reservation must contain 1 to 64 heads",
            ));
        }
        heads.sort();
        if heads
            .windows(2)
            .any(|pair| pair[0].volume_id == pair[1].volume_id)
        {
            return Err(Fault::invalid("duplicate volume in writer reservation"));
        }
        if let Some(prior) = self.catalog.writer_set(&op.operation_id)? {
            if prior.heads == heads {
                return self.writer_status(&op.operation_id);
            }
            return Err(idempotency_fault());
        }
        self.catalog.ready()?;
        let execution = self.scoped_execution(r)?;
        let live = self
            .executions
            .get(&execution.incarnation_id)
            .ok_or_else(stale_execution)?;
        if execution.phase != "registered" || pid_exited(live).map_err(broker_error)? {
            return Err(stale_execution());
        }
        let mut locks = Vec::with_capacity(heads.len());
        let mut registered = Vec::with_capacity(heads.len());
        for head in heads {
            let wanted = self.catalog.volume_identity(&head)?;
            let (file, identity) = self.open_backing(&head.head_resource_id)?;
            if identity != wanted {
                return Err(Fault::new(
                    "E_STALE_REVISION",
                    "volume backing identity changed",
                ));
            }
            ofd_lock(&file)?;
            locks.push(file);
            registered.push((head, identity));
        }
        self.catalog.reserve_writers(&op, &execution, &registered)?;
        self.reserved.insert(op.operation_id.clone(), locks);
        self.writer_status(&op.operation_id)
    }

    fn writer_status(&self, id: &str) -> Result<Value> {
        let Some(set) = self.catalog.writer_set(id)? else {
            return Ok(
                json!({"operation_id":id,"heads":[],"state":"absent","revision":0,"writer_authority":false}),
            );
        };
        let state = if set.state == "reserved" && !self.reserved.contains_key(id) {
            "unknown"
        } else {
            &set.state
        };
        Ok(
            json!({"operation_id":id,"heads":set.heads,"state":state,"revision":set.revision,"writer_authority":false}),
        )
    }
}

fn required_operation_id(r: &Request) -> Result<&str> {
    r.operation_id
        .as_deref()
        .ok_or_else(|| Fault::invalid("operation_id is required"))
}

fn private_dir(path: &Path) -> io::Result<()> {
    if !path.exists() {
        DirBuilder::new().mode(0o700).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "catalog directory must be private and owned by the broker",
        ));
    }
    Ok(())
}

fn process_lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "lock file is not a private broker file",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn check_socket_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket parent must be broker-controlled",
        ));
    }
    Ok(())
}

fn check_socket_path(path: &Path) -> io::Result<()> {
    if let Ok(existing) = fs::symlink_metadata(path) {
        if !existing.file_type().is_socket() || existing.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path has a foreign entry",
            ));
        }
        match ipc::connect(path) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path)?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "worker control socket already in use",
                ))
            }
        }
    }
    Ok(())
}

fn serve(
    state: &Path,
    socket_path: &Path,
    socket_gid: Option<u32>,
    admin_uid: Option<u32>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    check_socket_parent(socket_path)?;
    let address = SockAddr::unix(socket_path)?;
    let control_path = socket_path.with_extension("resourced.lock");
    if control_path == socket_path {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid socket filename").into());
    }
    let _socket_lock = process_lock(&control_path)?;
    check_socket_path(socket_path)?;
    private_dir(state)?;
    let _catalog_lock = process_lock(&state.join("catalog.lock"))?;
    let objects = state.join("objects");
    private_dir(&objects)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    if boot.is_empty() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "Linux host boot ID is empty").into(),
        );
    }
    let session = token()?;
    let mut worker = Worker {
        catalog: Catalog::open(&state.join("catalog.sqlite"), &boot, &session)?,
        objects: File::open(objects)?,
        boot,
        admin_uid: admin_uid.unwrap_or_else(|| unsafe { libc::geteuid() }),
        permits: HashMap::new(),
        executions: HashMap::new(),
        reserved: HashMap::new(),
        escrow: Escrow::default(),
    };

    let socket = ipc::new_socket()?;
    // Restrict the initial filesystem socket before applying an optional group.
    let previous = unsafe { libc::umask(0o177) };
    let bound = socket.bind(&address);
    unsafe { libc::umask(previous) };
    bound?;
    if let Some(gid) = socket_gid {
        std::os::unix::fs::chown(socket_path, None, Some(gid))?;
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    }
    socket.listen(32)?;
    loop {
        let (client, _) = match socket.accept() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if let Err(error) = serve_packet(&mut worker, &client) {
            eprintln!("resourced connection: {error}");
        }
    }
}

fn serve_packet(worker: &mut Worker, socket: &Socket) -> io::Result<()> {
    let peer = ipc::peer(socket)?;
    ipc::set_timeout(socket)?;
    let response = match ipc::receive_packet(socket).and_then(|packet| {
        serde_json::from_slice::<Request>(&packet.body)
            .map(|request| (request, packet.descriptors))
            .map_err(|e| Fault::invalid(e.to_string()))
    }) {
        Ok((request, descriptors)) => match worker.packet(&request, peer, descriptors) {
            Ok(reply) => {
                let mut message = json!({"protocol":PROTOCOL,"request_id":request.request_id,"result":reply.result});
                if !reply.table.is_empty() {
                    message["fd_table"] = json!(reply.table);
                }
                let serialized = message.to_string();
                if serialized.len() <= ipc::MAX_PACKET {
                    ipc::send_packet(socket, serialized.as_bytes(), &reply.descriptors)?;
                    if let Some((id, count)) = reply.delivered {
                        worker
                            .catalog
                            .delivered(&id, count)
                            .map_err(io::Error::other)?;
                    }
                    return Ok(());
                }
                Fault::new("E_RESOURCE_LIMIT", "response exceeds transport limit")
                    .response(Some(&request.request_id))
            }
            Err(error) => error.response(Some(&request.request_id)),
        },
        Err(error) => error.response(None),
    };
    let serialized = response.to_string();
    if serialized.len() > ipc::MAX_PACKET {
        return ipc::send(
            socket,
            Fault::new("E_RESOURCE_LIMIT", "response exceeds transport limit")
                .response(response["request_id"].as_str())
                .to_string()
                .as_bytes(),
        );
    }
    ipc::send(socket, serialized.as_bytes())
}

pub fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Serve {
            state_dir,
            socket,
            socket_gid,
            admin_uid,
        } => serve(&state_dir, &socket, socket_gid, admin_uid),
        Command::Call { socket } => {
            let mut bytes = Vec::new();
            io::stdin()
                .take((ipc::MAX_PACKET + 1) as u64)
                .read_to_end(&mut bytes)?;
            let client = ipc::connect(&socket)?;
            ipc::send(&client, &bytes)?;
            let response = ipc::receive(&client)?;
            println!("{}", std::str::from_utf8(&response)?);
            if let Some(error) = serde_json::from_slice::<Value>(&response)?.get("error") {
                return Err(io::Error::other(format!("worker returned {}", error["code"])).into());
            }
            Ok(())
        }
    }
}
