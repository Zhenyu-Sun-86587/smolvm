//! Dispatch persisted Worker launch intents independently of HTTP clients.
use crate::agent::KrunFunctions;
use crate::{deep_state, process, systemd_scope, Error, Result};
use smolvm_resourced::managed::Plan;
use smolvm_resourced::native_client::{Client, ExecutionRef};
use smolvm_resourced::network_client::WorkerNetworkScope;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

fn failed(e: impl ToString) -> Error {
    Error::agent("managed block launch", e.to_string())
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Boot {
    plan: Plan,
    worker: PathBuf,
    bundle: String,
    permit: String,
    control: PathBuf,
    helper: [u8; 32],
    uid: u32,
    gid: u32,
    scope: String,
    #[serde(default)]
    network: Option<WorkerNetworkScope>,
}
static DISPATCH: Once = Once::new();
pub(super) fn dispatch(socket: PathBuf) {
    DISPATCH.call_once(move||{
        thread::Builder::new().name("managed-launches".into()).spawn(move||{
            let running=Arc::new(Mutex::new(HashSet::new()));
            loop {
                if let Ok(serve)=deep_state::require_instance() {
                    if let Ok(client)=super::launch::verified_client(&socket) {
                        if let Ok(plans)=client.managed_pending(&serve) {
                            for plan in plans {
                                let id=plan.launch.operation_id.clone();
                                let mut active=running.lock().unwrap();
                                if active.len()>=8 || !active.insert(id.clone()) {continue}
                                drop(active);
                                let running=Arc::clone(&running);
                                let socket=socket.clone();
                                let bundle=client.bundle.to_string();
                                thread::spawn(move||{
                                    let client=Client{socket:&socket,bundle:&bundle};
                                    if let Err(e)=drive(&client,&plan) {
                                        tracing::warn!(operation_id=%id,error=%e,"Managed launch reconciliation");
                                    }
                                    running.lock().unwrap().remove(&id);
                                });
                            }
                        }
                    }
                }
                thread::sleep(Duration::from_millis(600));
            }
        }).expect("managed launch dispatcher");
    });
}

fn directory(path: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
    let created = match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(e.into()),
    };
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    if created && uid != 0 && unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let meta = fd.metadata()?;
    if meta.uid() != uid || meta.gid() != gid || meta.mode() & 0o022 != 0 {
        return Err(failed(
            "unexpected managed directory ownership or permissions",
        ));
    }
    Ok(())
}

fn logs_dir() -> Result<PathBuf> {
    let state = PathBuf::from(
        std::env::var_os("SMOLVM_DATA_DIR").ok_or_else(|| failed("missing state directory"))?,
    );
    let logs = state.join("managed");
    deep_state::require_private_path(&logs)?;
    directory(&logs, 0o700, 0, 0)?;
    Ok(logs)
}

fn paths(plan: &Plan, logs: &Path) -> Result<(PathBuf, PathBuf, u32, u32)> {
    let serve = deep_state::require_instance()?;
    let incarnation = plan
        .launch
        .execution
        .incarnation_id
        .as_deref()
        .ok_or_else(|| failed("missing incarnation"))?;
    if !incarnation
        .strip_prefix("vmm-")
        .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(failed("invalid registered incarnation identifier"));
    }
    // Long deployment state paths can exceed sockaddr_un. Each namespace gets
    // its own root-owned directory under /run; VMMs can only write their leaf.
    let top = Path::new("/run/smolvm-custom");
    directory(top, 0o755, 0, 0)?;
    let run = top.join("managed");
    directory(&run, 0o711, 0, 0)?;
    let ns = run.join(&serve);
    directory(&ns, 0o711, 0, 0)?;
    let work = ns.join(incarnation);
    let uid_key = logs.join(incarnation);
    directory(&uid_key, 0o700, 0, 0)?;
    deep_state::prepare_uid_registry()?;
    let (uid, gid) =
        process::vm_drop_ids(Path::new(deep_state::UID_REGISTRY), &uid_key, None, None)
            .ok_or_else(|| failed("a dedicated VMM UID is required"))??;
    if uid == 0 || gid == 0 {
        return Err(failed("invalid VMM UID"));
    }
    directory(&work, 0o700, uid, gid)?;
    Ok((
        work.join("c.sock"),
        logs.join(format!("{incarnation}.log")),
        uid,
        gid,
    ))
}

fn drive(client: &Client<'_>, plan: &Plan) -> Result<()> {
    let launch = &plan.launch;
    let logs = logs_dir()?;
    // Serialize the same scope across Serve processes and retry attempts.
    let scope = systemd_scope::scope_name(&plan.machine.name);
    let scope_lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(logs.join(format!("{scope}.lock")))?;
    if unsafe { libc::flock(scope_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(error.into());
    }
    let binding = client
        .binding(&launch.execution.instance_id)
        .map_err(failed)?;
    if binding.active_operation_id.as_deref() != Some(launch.operation_id.as_str()) {
        return Ok(());
    }
    if binding.incarnation_id.is_none()
        && binding.execution_epoch == launch.execution.execution_epoch
    {
        return abort_launch(client, plan, &binding.expected());
    }
    if binding.incarnation_id.is_none() {
        let prior = binding.expected();
        match client.managed_launch_claimed(launch) {
            Ok(true) => return Ok(()),
            Ok(false) => (),
            Err(error) if error.code == "E_CAPTURE_LOST" => {
                return abort_launch(client, plan, &prior);
            }
            Err(error) => return Err(failed(error)),
        }
        if plan.restore.as_ref().is_some_and(|restore| restore.durable.is_some())
            && !client.prepare_state_restore(launch, &prior).map_err(failed)?
        {
            return Ok(());
        }
    } else if binding.expected() != launch.execution {
        return Err(failed("active incarnation differs from pending launch"));
    }
    let (control, log, uid, gid) = paths(plan, &logs)?;
    let mut child = None;
    if binding.incarnation_id.is_none() {
        let prior = binding.expected();
        let network = match client.prepare_managed_network(&prior, plan) {
            Ok(network) => network,
            Err(error) => {
                if plan.restore.is_none() && matches!(
                    error.code.as_str(),
                    "E_RESOURCE_LIMIT"
                        | "E_INVALID_REQUEST"
                        | "E_NETWORK_ATTACHMENT_CONFLICT"
                        | "E_HOST_IO"
                ) {
                    abort_launch(client, plan, &prior)?;
                }
                return Err(failed(error));
            }
        };
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(log)?;
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.arg("_boot-managed")
            .stdin(Stdio::piped())
            .stdout(file.try_clone()?)
            .stderr(file)
            .env("SMOLVM_FORKABLE", "1");
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(|k| {
                k.starts_with("SMOLVM_RESTORE")
                    || k.starts_with("SMOLVM_SNAPSHOT")
                    || k == "SMOLVM_DEEP_ENROLL_FD"
            }) {
                cmd.env_remove(key);
            }
        }
        let mut proc = cmd.spawn()?;
        let setup = (|| -> Result<()> {
            let pid = proc.id() as i32;
            let mib = u64::from(plan.machine.memory_mib);
            let caps = systemd_scope::ScopeCaps {
                memory_max_bytes: Some((mib + 256) << 20),
                memory_high_bytes: Some((mib + 192) << 20),
                cpu_quota_usec_per_sec: Some(u64::from(plan.machine.cpus) * 1_000_000),
                tasks_max: Some(256),
            };
            systemd_scope::adopt_managed_scope(&plan.machine.name, pid, &caps)?;
            systemd_scope::wait_for_managed_adoption(&plan.machine.name, &mut proc)?;
            let permit = client.issue_permit(launch, pid, uid).map_err(failed)?;
            let boot = Boot {
                plan: plan.clone(),
                worker: client.socket.into(),
                bundle: client.bundle.into(),
                permit,
                control: control.clone(),
                helper: super::launch::measured_helper()?,
                uid,
                gid,
                scope,
                network,
            };
            let mut channel = proc
                .stdin
                .take()
                .ok_or_else(|| failed("lost launch channel"))?;
            channel.write_all(&serde_json::to_vec(&boot).map_err(failed)?)?;
            Ok(())
        })();
        if let Err(e) = setup {
            drop(proc.stdin.take());
            let _ = proc.kill();
            if proc.wait().is_ok() {
                repair_empty_scope(plan);
            }
            return Err(e);
        }
        child = Some(proc);
    }
    // Reconcile a surviving child through its credential-checked native endpoint.
    // Before registration a second process can never obtain the original claim.
    let result = confirm(client, plan, &control, &mut child);
    if let Some(mut proc) = child {
        thread::spawn(move || {
            let _ = proc.wait();
        });
    }
    result
}

fn confirm(
    client: &Client<'_>,
    plan: &Plan,
    control: &Path,
    child: &mut Option<Child>,
) -> Result<()> {
    let launch = &plan.launch;
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut bound = false;
    loop {
        if control.exists() {
            if !bound && client.bind_control(launch, control).is_ok() {
                bound = true;
            }
            if bound
                && (plan.restore.is_none()
                    || client.progress_fork_target(launch).map_err(failed)?)
            {
                let op = smolvm_resourced::client::query_operation(
                    client.socket,
                    client.bundle,
                    &launch.operation_id,
                )
                .map_err(failed)?;
                client
                    .finish_launch(launch, &launch.execution, false, op.revision)
                    .map_err(failed)?;
                return Ok(());
            }
        }
        let exited = child
            .as_mut()
            .map(|p| p.try_wait())
            .transpose()?
            .flatten()
            .is_some();
        // A restarted launcher has no Child handle. The previous VMM may
        // leave a Unix socket path behind after it has exited.
        if exited || (child.is_none() && (!bound || !control.exists())) {
            let binding = client
                .binding(&launch.execution.instance_id)
                .map_err(failed)?;
            if binding.expected() == launch.execution {
                if client.fence_exit(&launch.execution).is_err() && !exited {
                    thread::sleep(Duration::from_millis(150));
                    if Instant::now() < deadline {
                        continue;
                    }
                    return Err(failed("awaiting the registered native endpoint"));
                }
            }
            if exited || binding.expected() == launch.execution {
                let current = client
                    .binding(&launch.execution.instance_id)
                    .map_err(failed)?
                    .expected();
                if current.incarnation_id.is_some() {
                    return Err(failed("execution exit not yet fenced"));
                }
                return abort_launch(client, plan, &current);
            }
        }
        if Instant::now() >= deadline {
            return Err(failed("waiting for native control"));
        }
        thread::sleep(Duration::from_millis(120));
    }
}

fn abort_launch(client: &Client<'_>, plan: &Plan, expected: &ExecutionRef) -> Result<()> {
    client.fence_managed_network(plan).map_err(failed)?;
    let op = smolvm_resourced::client::query_operation(
        client.socket,
        client.bundle,
        &plan.launch.operation_id,
    )
    .map_err(failed)?;
    client
        .finish_launch(&plan.launch, expected, true, op.revision)
        .map_err(failed)?;
    repair_empty_scope(plan);
    Ok(())
}

fn repair_empty_scope(plan: &Plan) {
    if let Err(error) = systemd_scope::stop_empty_managed_scope(&plan.machine.name) {
        tracing::warn!(machine=%plan.machine.name, %error, "Empty managed scope cleanup");
    }
}

/// Internal VMM entry point. The parent sends the permit after systemd adopts this PID.
pub fn boot() -> Result<()> {
    let mut msg = Vec::new();
    std::io::stdin().take(131073).read_to_end(&mut msg)?;
    if msg.len() > 131072 {
        return Err(failed("oversize boot manifest"));
    }
    let boot: Boot = serde_json::from_slice(&msg).map_err(failed)?;
    if boot.uid == 0 || boot.gid == 0 {
        return Err(failed("per-VM identity required"));
    }
    systemd_scope::verify_boot_scope(&boot.scope)?;
    process::close_inherited_fds_from(3);
    // Guest RAM overlays need this VMM's own page map to capture private pages
    // on a recursive fork. Open it before dropping the execution identity.
    let pagemap = File::open("/proc/self/pagemap")?;
    std::env::set_var("KRUN_PAGEMAP_FD", pagemap.as_raw_fd().to_string());
    let null = File::open("/dev/null")?;
    if unsafe { libc::dup2(null.as_raw_fd(), 0) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    drop(null);
    let lib_dir = std::env::current_exe()?
        .parent()
        .ok_or_else(|| failed("missing installed bundle"))?
        .join("lib");
    let work = boot
        .control
        .parent()
        .ok_or_else(|| failed("missing control directory"))?;
    std::env::set_current_dir(work)?;
    let client = Client {
        socket: &boot.worker,
        bundle: &boot.bundle,
    };
    let kernel = boot.plan.machine.kernel_cow();
    let mut imported = None;
    if let Some(restore) = boot.plan.restore.as_ref().filter(|_| kernel) {
        if restore.durable.is_some() {
            return Err(failed("a durable checkpoint must use its portable RAM reader"));
        }
        let k = unsafe { KrunFunctions::load_managed_kernel_cow(&lib_dir) }.map_err(failed)?;
        let ctx = create_context(&k)?;
        let memory = client.kernel_fork_memory(&boot.plan.launch, restore, &boot.permit).map_err(failed)?;
        let start = Instant::now();
        if let Err(error) = k.import_managed_kernel_cow(ctx, memory, boot.uid, boot.gid) {
            unsafe { (k.free_ctx)(ctx) };
            return Err(failed(error));
        }
        tracing::info!(operation_id=%boot.plan.launch.operation_id, duration_us=start.elapsed().as_micros(),
            "Kernel CoW target RAM imported");
        imported = Some((k, ctx));
    } else {
        process::drop_privileges(boot.uid, boot.gid).map_err(failed)?;
    }
    if std::env::var("SMOLVM_LANDLOCK").as_deref() == Ok("enforce") {
        let mut read_exec: Vec<PathBuf> = ["/usr", "/lib", "/lib64", "/etc", "/proc", "/sys"]
            .iter()
            .map(PathBuf::from)
            .collect();
        read_exec.push(lib_dir.clone());
        let mut writable: Vec<PathBuf> = ["/dev/kvm", "/dev/null", "/dev/zero", "/dev/urandom"]
            .iter()
            .map(PathBuf::from)
            .collect();
        writable.push(work.to_owned());
        process::restrict_filesystem(&read_exec, &writable).map_err(failed)?;
    }
    client
        .register(&boot.plan.launch, &boot.permit)
        .map_err(failed)?;
    let (k, ctx) = match imported {
        Some(context) => context,
        None => {
            let k = unsafe { KrunFunctions::load(&lib_dir) }.map_err(failed)?;
            let ctx = create_context(&k)?;
            (k, ctx)
        }
    };
    let configured = (|| -> Result<()> {
        if kernel && boot.plan.restore.is_none() {
            k.enable_managed_kernel_cow(ctx).map_err(failed)?;
        }
        let (sets, files) = client.managed_disks(&boot.plan).map_err(failed)?;
        let network = boot
            .network
            .as_ref()
            .map(|scope| k.attach_prepared_worker_network(ctx, scope))
            .transpose()
            .map_err(failed)?;
        k.managed_boot(
            ctx,
            &boot.plan,
            &sets,
            &files,
            &boot.helper,
            &boot.control,
            &boot.worker,
            &boot.bundle,
            network.as_ref().map(|lease| &lease.attachment),
        )
        .map_err(failed)?;
        client
            .ack_managed_disks(&boot.plan.launch)
            .map_err(failed)?;
        if let Some(restore) = &boot.plan.restore {
            if let Some(durable) = &restore.durable {
                k.managed_statepoint(ctx, &boot.plan, restore, durable).map_err(failed)?;
                let authority = client.restore_authority(&boot.plan.launch, restore).map_err(failed)?;
                k.managed_target_authority(ctx, &boot.plan, restore, &authority).map_err(failed)?;
            } else if kernel {
                let authority = client.restore_authority(&boot.plan.launch, restore).map_err(failed)?;
                k.managed_target_authority(ctx, &boot.plan, restore, &authority).map_err(failed)?;
            } else {
                let memory = client.fork_memory(&boot.plan, restore).map_err(failed)?;
                k.managed_restore(ctx, &boot.plan, restore, &memory, work).map_err(failed)?;
            }
        }
        process::install_configured_seccomp_filter(false).map_err(failed)?;
        // A cold Guest starts with carrier. The restore path opens its TAP
        // only after the Worker records the Guest identity release.
        if boot.plan.restore.is_none() {
            if let Some((scope, lease)) = boot.network.as_ref().zip(network.as_ref()) {
                scope.publish_initial(lease).map_err(failed)?;
            }
        }
        Ok(())
    })();
    if let Err(e) = configured {
        unsafe { (k.free_ctx)(ctx) };
        return Err(e);
    }
    let rc = unsafe { (k.start_enter)(ctx) };
    if rc != 0 {
        return Err(failed(format!(
            "KVM returned {rc}: {}",
            k.last_error_message().unwrap_or_default()
        )));
    }
    Ok(())
}

fn create_context(k: &KrunFunctions) -> Result<u32> {
    let ctx = unsafe { (k.create_ctx)() };
    u32::try_from(ctx).map_err(|_| failed(format!("create VMM returned {ctx}")))
}
