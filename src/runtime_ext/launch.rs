//! Bind an ordinary named deep VMM to the Worker before entering KVM.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use smolvm_resourced::client::{query_operation, QueryError};
use smolvm_resourced::native_client::{Client, ExecutionRef, Launch};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{net::UnixStream, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

const BOOT_FD: &str = "SMOLVM_DEEP_ENROLL_FD";
static WORKER: OnceLock<PathBuf> = OnceLock::new();
static PROFILE: OnceLock<Profile> = OnceLock::new();
static GUEST_GATE: OnceLock<Option<[u8; 32]>> = OnceLock::new();

fn failed(error: impl ToString) -> Error {
    Error::agent("enroll native VMM", error.to_string())
}
/// Enroll future named machine launches with this private Serve's Worker.
pub fn configure_native_launch_worker(socket: &Path) -> Result<()> {
    smolvm_resourced::client::verify_worker_slice(socket).map_err(failed)?;
    if WORKER.get_or_init(|| socket.to_owned()) != socket {
        return Err(failed("this Serve already uses another Worker"));
    }
    Ok(())
}
pub(super) fn instance_id(name: &str) -> std::result::Result<String, QueryError> {
    let instance = crate::deep_state::require_instance().map_err(|err| QueryError {
        code: "E_RESOURCED_UNAVAILABLE".into(),
        message: err.to_string(),
    })?;
    Ok(smolvm_resourced::managed::machine_id(&instance, name))
}
pub(super) fn require_own(instance_id: &str) -> std::result::Result<(), QueryError> {
    if crate::deep_state::instance_id().is_some_and(|ns| {
        instance_id
            .strip_prefix(&format!("i-{ns}-"))
            .is_some_and(|tail| tail.len() == 64 && tail.bytes().all(|c| c.is_ascii_hexdigit()))
    }) {
        Ok(())
    } else {
        Err(QueryError {
            code: "E_NOT_FOUND".into(),
            message: "unknown execution in this Serve".into(),
        })
    }
}
fn nonce() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(failed)?;
    Ok(hex::encode(bytes))
}
struct Profile {
    bundle: String,
    executable: String,
    helper: Option<[u8; 32]>,
}
fn profile() -> Result<&'static Profile> {
    if let Some(p) = PROFILE.get() {
        return Ok(p);
    }
    let (handshake, manifest, hash) = super::installed_profile().map_err(failed)?;
    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| failed("missing bundle artifacts"))?;
    let mut helpers = artifacts
        .iter()
        .filter(|a| a["path"] == "guest/identity-helper");
    let helper = helpers
        .next()
        .map(|a| {
            let hash = a["sha256"]
                .as_str()
                .ok_or_else(|| failed("missing identity helper digest"))?;
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(hash, &mut bytes).map_err(failed)?;
            Ok::<_, Error>(bytes)
        })
        .transpose()?;
    if helpers.next().is_some() {
        return Err(failed("ambiguous identity helper"));
    }
    Ok(PROFILE.get_or_init(|| Profile {
        bundle: handshake.bundle_digest,
        executable: format!("sha256:{hash}"),
        helper,
    }))
}

pub(super) fn worker_configured() -> bool {
    WORKER.get().is_some()
}

pub(super) fn worker_socket() -> Option<&'static Path> {
    WORKER.get().map(PathBuf::as_path)
}

pub(super) fn verified_client(socket: &Path) -> std::result::Result<Client<'_>, QueryError> {
    let profile = profile().map_err(|e| QueryError {
        code: "E_BUNDLE_UNAVAILABLE".into(),
        message: e.to_string(),
    })?;
    Ok(Client {
        socket,
        bundle: &profile.bundle,
    })
}
pub(super) fn ensure_binding(
    client: &Client<'_>,
    instance: &str,
) -> std::result::Result<smolvm_resourced::native_client::Binding, QueryError> {
    match client.binding(instance) {
        Err(e) if e.code == "E_BUNDLE_UNAVAILABLE" => {
            let profile = profile().map_err(|e| QueryError {
                code: "E_BUNDLE_UNAVAILABLE".into(),
                message: e.to_string(),
            })?;
            client.register_bundle(&profile.executable)?;
            client.binding(instance)
        }
        other => other,
    }
}
pub(super) fn measured_helper() -> Result<[u8; 32]> {
    profile()?
        .helper
        .ok_or_else(|| failed("managed boot requires an installed identity helper"))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ticket {
    socket: PathBuf,
    bundle: String,
    helper: Option<[u8; 32]>,
    launch: Launch,
    permit: String,
}

/// The only inherited data is a private socket descriptor. The permit is sent
/// after systemd adopts the exact PID; it never enters argv or the environment.
pub(crate) struct Enrollment {
    channel: UnixStream,
    inherited: Option<UnixStream>,
    profile: &'static Profile,
    socket: &'static Path,
    control: PathBuf,
    name: String,
    uid: u32,
    operation: Option<(Launch, i64)>,
}
impl Enrollment {
    pub fn prepare(
        cmd: &mut Command,
        name: &str,
        uid: Option<u32>,
        control: PathBuf,
    ) -> Result<Option<Self>> {
        cmd.env_remove(BOOT_FD);
        let Some(socket) = WORKER.get() else {
            return Ok(None);
        };
        let uid = uid
            .filter(|id| *id != 0)
            .ok_or_else(|| failed("expected a per-machine VMM UID"))?;
        let profile = profile()?;
        let (channel, child) = UnixStream::pair().map_err(failed)?;
        let fd = child.as_raw_fd();
        cmd.env(BOOT_FD, fd.to_string());
        // SAFETY: fcntl is async-signal-safe. The parent retains a CLOEXEC
        // descriptor; only the specified child inherits its own end.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        Ok(Some(Self {
            channel,
            inherited: Some(child),
            profile,
            socket,
            control,
            name: name.to_owned(),
            uid,
            operation: None,
        }))
    }
    fn client(&self) -> Client<'static> {
        Client {
            socket: self.socket,
            bundle: &self.profile.bundle,
        }
    }
    pub fn start(&mut self, pid: i32) -> Result<()> {
        self.inherited.take();
        let instance = instance_id(&self.name).map_err(failed)?;
        let client = self.client();
        let mut binding = ensure_binding(&client, &instance).map_err(failed)?;
        if binding.incarnation_id.is_some() {
            client.fence_exit(&binding.expected()).map_err(failed)?;
            binding = client.binding(&instance).map_err(failed)?;
        }
        if let Some(id) = &binding.active_operation_id {
            // The outer per-machine launch lock serializes starts. Discard a
            // predecessor's launch only after fencing its registered execution.
            let prior = query_operation(self.socket, &self.profile.bundle, id).map_err(failed)?;
            if prior.kind != "launch" || prior.instance_id != instance || prior.phase != "NEW" {
                return Err(failed(format!("machine has active operation {id}")));
            }
            let old = Launch {
                operation_id: prior.operation_id,
                request_digest: prior.request_digest,
                execution: binding.expected(),
            };
            client
                .finish_launch(&old, &binding.expected(), true, prior.revision)
                .map_err(failed)?;
        }
        let prior = binding.expected();
        let execution = ExecutionRef {
            instance_id: instance,
            incarnation_id: Some(nonce()?),
            execution_epoch: prior
                .execution_epoch
                .checked_add(1)
                .ok_or_else(|| failed("execution epoch exhausted"))?,
        };
        let operation_id = nonce()?;
        let intent = serde_json::to_vec(&(
            &operation_id,
            &self.profile.bundle,
            &prior,
            &execution,
            pid,
            self.uid,
        ))
        .map_err(failed)?;
        let launch = Launch {
            operation_id,
            request_digest: format!("sha256:{:x}", Sha256::digest(intent)),
            execution,
        };
        let op = client.begin_launch(&prior, &launch).map_err(failed)?;
        self.operation = Some((launch.clone(), op.revision));
        let ticket = Ticket {
            socket: self.socket.to_owned(),
            bundle: self.profile.bundle.clone(),
            helper: self.profile.helper,
            permit: client
                .issue_permit(&launch, pid, self.uid)
                .map_err(failed)?,
            launch,
        };
        self.channel
            .write_all(&serde_json::to_vec(&ticket).map_err(failed)?)
            .map_err(failed)?;
        self.channel.shutdown(Shutdown::Write).map_err(failed)
    }
    pub fn commit(&self) -> Result<()> {
        let (launch, rev) = self
            .operation
            .as_ref()
            .ok_or_else(|| failed("launch has no Worker intent"))?;
        let client = self.client();
        client.bind_control(launch, &self.control).map_err(failed)?;
        client
            .finish_launch(launch, &launch.execution, false, *rev)
            .map_err(failed)
    }
    pub fn abort_after_exit(&self) -> Result<()> {
        let Some((launch, rev)) = &self.operation else {
            return Ok(());
        };
        let client = self.client();
        let mut binding = client
            .binding(&launch.execution.instance_id)
            .map_err(failed)?;
        if binding.incarnation_id == launch.execution.incarnation_id {
            client.fence_exit(&launch.execution).map_err(failed)?;
            binding = client
                .binding(&launch.execution.instance_id)
                .map_err(failed)?;
        }
        client
            .finish_launch(launch, &binding.expected(), true, *rev)
            .map_err(failed)
    }
}

/// Called in the owned boot helper before scrubbing all inherited descriptors.
pub(crate) fn read_ticket() -> Result<Option<Ticket>> {
    let Some(raw) = std::env::var_os(BOOT_FD) else {
        return Ok(None);
    };
    std::env::remove_var(BOOT_FD);
    let fd = raw
        .to_str()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v >= 3)
        .ok_or_else(|| failed("invalid private launch channel"))?;
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(failed)?;
    let mut body = Vec::new();
    stream.take(8193).read_to_end(&mut body).map_err(failed)?;
    if body.len() > 8192 {
        return Err(failed("oversized launch ticket"));
    }
    serde_json::from_slice(&body).map(Some).map_err(failed)
}
impl Ticket {
    pub fn register(self) -> Result<()> {
        if unsafe { libc::geteuid() } == 0 {
            return Err(failed("registration requires the isolated VMM UID"));
        }
        Client {
            socket: &self.socket,
            bundle: &self.bundle,
        }
        .register(&self.launch, &self.permit)
        .map_err(failed)?;
        GUEST_GATE
            .set(self.helper)
            .map_err(|_| failed("guest gate already selected"))
    }
}
pub(crate) fn guest_gate() -> Option<&'static Option<[u8; 32]>> {
    GUEST_GATE.get()
}
