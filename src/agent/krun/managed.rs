//! Configure the deep block ABI with the original Worker file descriptions.
use super::KrunFunctions;
use smolvm_resourced::managed::Plan;
use smolvm_resourced::network_client::AttachmentDescriptor;
use std::ffi::{c_char, CString};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::ptr;

#[repr(C)]
struct Layer {
    resource_id: *const c_char,
    fd: i32,
    format: u32,
}
#[repr(C)]
struct Block {
    size: u32,
    version: u32,
    attachment_id: *const c_char,
    device_id: *const c_char,
    role: *const c_char,
    volume_id: *const c_char,
    generation_id: *const c_char,
    writable_head_id: *const c_char,
    grant_id: *const c_char,
    execution_epoch: u64,
    capacity_bytes: u64,
    layers: *const Layer,
    layer_count: usize,
}
type BucketRange = unsafe extern "C" fn(u32, *const c_char, i32, u64) -> i32;
type Attach = unsafe extern "C" fn(u32, *const Block, usize) -> i32;
type Mount = unsafe extern "C" fn(u32, *const c_char, *const c_char, *const c_char) -> i32;
type Text = unsafe extern "C" fn(u32, *const c_char) -> i32;
type Toggle = unsafe extern "C" fn(u32, bool) -> i32;
type Config = unsafe extern "C" fn(u32, *const u8, usize) -> i32;

impl KrunFunctions {
    /// Configure a measured, block-root guest in one process and execution scope.
    pub(crate) fn managed_boot(
        &self,
        ctx: u32,
        plan: &Plan,
        disks: &smolvm_resourced::native_client::ManagedLaunchDisks,
        helper: &[u8; 32],
        control: &Path,
        worker: &Path,
        bundle: &str,
        network: Option<&AttachmentDescriptor>,
    ) -> Result<(), String> {
        let mut strings = Vec::new();
        let mut string = |value: &str| -> Result<*const c_char, String> {
            let owned = CString::new(value).map_err(|e| e.to_string())?;
            let pointer = owned.as_ptr();
            strings.push(owned);
            Ok(pointer)
        };
        let mut chains = Vec::new();
        let mut blocks = Vec::new();
        for set in &disks.sets {
            let mut layers = Vec::new();
            for object in &set.layers {
                let fd = disks.files
                    .get(&object.spec.resource_id)
                    .ok_or("missing Worker disk FD")?;
                let format = match object.format.as_str() {
                    "raw" => 0,
                    "qcow2" => 1,
                    _ => return Err("unsupported Worker disk format".into()),
                };
                layers.push(Layer {
                    resource_id: string(&object.spec.resource_id)?,
                    fd: fd.as_raw_fd(),
                    format,
                });
            }
            let dev = &set.device;
            let (head, grant) = match &dev.head_id {
                Some(id) => (string(id)?, string(&plan.grant_id)?),
                None => (ptr::null(), ptr::null()),
            };
            blocks.push(Block {
                size: std::mem::size_of::<Block>() as u32,
                version: 1,
                attachment_id: string(&dev.disk.attachment_id)?,
                device_id: string(&dev.disk.device_id)?,
                role: string(&dev.disk.role)?,
                volume_id: string(&dev.volume_id)?,
                generation_id: string(&dev.disk.generation_id)?,
                writable_head_id: head,
                grant_id: grant,
                execution_epoch: plan.launch.execution.execution_epoch as u64,
                capacity_bytes: dev.capacity_bytes,
                layers: layers.as_ptr(),
                layer_count: layers.len(),
            });
            chains.push(layers);
        }
        let check = |step: &str, result: i32| {
            if result == 0 {
                Ok(())
            } else {
                Err(format!(
                    "{step} returned {result}: {}",
                    self.last_error_message().unwrap_or_default()
                ))
            }
        };
        let cpath = CString::new(control.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let mut args = plan
            .machine
            .args
            .iter()
            .map(|arg| string(arg))
            .collect::<Result<Vec<_>, _>>()?;
        args.push(ptr::null());
        let mut env = vec![
            c"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".as_ptr(),
            c"HOME=/root".as_ptr(),
        ];
        let system = plan.machine.boot_profile == "system-debian-v1";
        if system {
            env.push(c"KRUN_INIT_PID1=1".as_ptr());
        }
        if let Some(attached) = network {
            env.push(string(&format!(
                "KRUN_STATIC_IPV4={}/{},{},{}",
                attached.guest_ipv4,
                attached.guest_prefix,
                attached.gateway_ipv4,
                attached.gateway_ipv4
            ))?);
        }
        env.push(ptr::null());
        let execution = &plan.launch.execution;
        let guest_relay = std::env::var_os("SMOLVM_GUEST_RELAY_DIR")
            .map(|dir| {
                let dir = PathBuf::from(dir);
                if !dir.is_absolute()
                    || dir
                        .components()
                        .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
                {
                    return Err("invalid Guest relay directory".to_owned());
                }
                let incarnation = execution
                    .incarnation_id
                    .as_deref()
                    .ok_or("missing Guest relay incarnation")?;
                let path = dir.join(format!("{incarnation}.sock"));
                let bytes = path.as_os_str().as_bytes();
                if bytes.len() >= 108 {
                    return Err("Guest relay path exceeds the Unix socket address".to_owned());
                }
                CString::new(bytes).map_err(|e| e.to_string())
            })
            .transpose()?;
        let pivot=serde_json::to_vec(&serde_json::json!({"socket":worker,"worker_uid":0,"bundle_digest":bundle,
            "instance_id":execution.instance_id,"incarnation_id":execution.incarnation_id,"execution_epoch":execution.execution_epoch})).map_err(|e|e.to_string())?;
        // The Library owns every function symbol and stays resident through start_enter.
        // Strings, layer arrays and descriptors outlive the entire attach call, which
        // duplicates the FDs. No filename is substituted for a Worker grant.
        unsafe {
            let attach = self
                ._handle
                .get::<Attach>(b"krun_attach_block_set_v1\0")
                .map_err(|e| e.to_string())?;
            let mount = self
                ._handle
                .get::<Mount>(b"krun_set_root_disk_remount\0")
                .map_err(|e| e.to_string())?;
            let kernel_console = self
                ._handle
                .get::<Text>(b"krun_set_kernel_console\0")
                .map_err(|e| e.to_string())?;
            let irq = self
                ._handle
                .get::<Toggle>(b"krun_split_irqchip\0")
                .map_err(|e| e.to_string())?;
            let configure_pivot = self
                ._handle
                .get::<Config>(b"krun_configure_worker_block_pivot_v1\0")
                .map_err(|e| e.to_string())?;
            if plan.machine.live_compute_growth && plan.restore.is_none() {
                let resize = self
                    .set_live_resize
                    .ok_or("the installed VMM lacks the requested live compute geometry")?;
                check("managed CPU and RAM hot-add", resize(ctx, 3))?;
            }
            if !disks.ranges.is_empty() {
                let range = self._handle.get::<BucketRange>(b"krun_set_managed_block_range_v1\0")
                    .map_err(|_| "installed libkrun lacks the managed Bucket range reader".to_owned())?;
                for (id, (bytes, fd)) in &disks.ranges {
                    check("managed Bucket base", range(ctx, string(id)?, fd.as_raw_fd(), *bytes))?;
                }
            }
            check("block set", attach(ctx, blocks.as_ptr(), blocks.len()))?;
            check(
                "VM resources",
                (self.set_vm_config)(ctx, plan.machine.cpus, plan.machine.memory_mib),
            )?;
            check("console", (self.add_virtio_console_default)(ctx, 0, 1, 2))?;
            check("kernel console", kernel_console(ctx, c"hvc0".as_ptr()))?;
            let root_flags = if plan.machine.disks[0].read_only {
                c"ro,noload"
            } else {
                c"rw"
            };
            check(
                "root disk",
                mount(
                    ctx,
                    c"/dev/vda".as_ptr(),
                    c"ext4".as_ptr(),
                    root_flags.as_ptr(),
                ),
            )?;
            if system || guest_relay.is_some() {
                check("managed vsock", (self.add_vsock)(ctx, 0))?;
            }
            if system {
                let path = control.with_file_name("agent.sock");
                let guest_socket =
                    CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
                check(
                    "System Guest Agent",
                    (self.add_vsock_port2)(ctx, 6000, guest_socket.as_ptr(), true),
                )?;
            }
            if let Some(path) = guest_relay.as_ref() {
                check(
                    "Guest management relay",
                    (self.add_vsock_port2)(ctx, 6001, path.as_ptr(), false),
                )?;
            }
            check("workdir", (self.set_workdir)(ctx, c"/".as_ptr()))?;
            check(
                "Guest executable",
                (self.set_exec)(
                    ctx,
                    string(&plan.machine.init)?,
                    args.as_ptr(),
                    env.as_ptr(),
                ),
            )?;
            check(
                "identity helper",
                self.set_guest_identity_helper
                    .ok_or("missing Guest identity ABI")?(
                    ctx, helper.as_ptr(), helper.len()
                ),
            )?;
            check(
                "native control",
                self.set_control_socket
                    .ok_or("missing native control ABI")?(ctx, cpath.as_ptr()),
            )?;
            check("interrupt controller", irq(ctx, false))?;
            check(
                "Worker block pivot",
                configure_pivot(ctx, pivot.as_ptr(), pivot.len()),
            )?;
        }
        Ok(())
    }
}

impl KrunFunctions {
    pub(crate) fn enable_managed_kernel_cow(&self, ctx: u32) -> Result<(), String> {
        unsafe {
            let enable = self._handle.get::<unsafe extern "C" fn(u32) -> i32>(
                b"krun_enable_worker_kernel_cow_v1\0",
            ).map_err(|error| error.to_string())?;
            self.check_managed_restore("Kernel CoW RAM profile", enable(ctx))
        }
    }

    pub(crate) fn import_managed_kernel_cow(
        &self,
        ctx: u32,
        memory: smolvm_resourced::native_client::KernelForkMemory,
        uid: u32,
        gid: u32,
    ) -> Result<(), String> {
        use smolvm_runtime_protocol::kernel_cow::Region;
        type Import = unsafe extern "C" fn(
            u32, i32, *const Region, usize, *const u8, usize, u32, u32, u32,
        ) -> i32;
        let kvm_group = crate::process::kvm_group_gid().unwrap_or(0);
        unsafe {
            let import = self._handle.get::<Import>(b"krun_import_worker_kernel_cow_v1\0")
                .map_err(|error| error.to_string())?;
            // The donor pidfd is transferred at entry, including when the
            // runtime rejects the import. This process never needs it again.
            let status = import(
                ctx,
                memory.donor.into_raw_fd(),
                memory.regions.as_ptr(),
                memory.regions.len(),
                memory.checkpoint.as_ptr(),
                memory.checkpoint.len(),
                uid,
                gid,
                kvm_group,
            );
            self.check_managed_restore("Kernel CoW RAM import", status)?;
            if libc::geteuid() != uid || libc::getegid() != gid {
                return Err("Kernel CoW bootstrap did not assume its execution credentials".into());
            }
        }
        Ok(())
    }

    pub(crate) fn managed_restore(
        &self,
        ctx: u32,
        plan: &Plan,
        restore: &smolvm_resourced::managed::Restore,
        memory: &smolvm_resourced::native_client::ForkMemory,
        directory: &Path,
    ) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        type Ram = unsafe extern "C" fn(u32, *const u8, usize, *const i32, usize) -> i32;
        let snapshot = directory.join("capture");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&snapshot)
            .map_err(|e| e.to_string())?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(snapshot.join("checkpoint.bin"))
            .map_err(|e| e.to_string())?;
        file.write_all(&memory.checkpoint)
            .map_err(|e| e.to_string())?;
        drop(file);
        let path = CString::new(snapshot.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let fds: Vec<_> = memory.ram.iter().map(AsRawFd::as_raw_fd).collect();
        let check = |op: &str, status: i32| {
            if status == 0 {
                Ok(())
            } else {
                Err(format!(
                    "{op} returned {status}: {}",
                    self.last_error_message().unwrap_or_default()
                ))
            }
        };
        unsafe {
            let import = self
                ._handle
                .get::<Ram>(b"krun_set_diskless_snapshot_ram_v1\0")
                .map_err(|e| e.to_string())?;
            check(
                "parked checkpoint",
                self.set_snapshot.ok_or("missing snapshot loader")?(ctx, path.as_ptr()),
            )?;
            check(
                "sealed RAM closure",
                import(
                    ctx,
                    memory.descriptor.as_ptr(),
                    memory.descriptor.len(),
                    fds.as_ptr(),
                    fds.len(),
                ),
            )?;
        }
        self.managed_target_authority(ctx, plan, restore, &memory.authority)
    }

    pub(crate) fn managed_statepoint(
        &self,
        ctx: u32,
        plan: &Plan,
        restore: &smolvm_resourced::managed::Restore,
        durable: &smolvm_resourced::managed_state_restore::Durable,
    ) -> Result<(), String> {
        let config = serde_json::to_vec(&serde_json::json!({
            "operation_id":plan.launch.operation_id,"request_digest":plan.launch.request_digest,
            "capture_id":restore.capture_id,"lease_id":durable.lease_id,"volume_restore_policy":durable.mode
        })).map_err(|e| e.to_string())?;
        unsafe {
            let attach = self
                ._handle
                .get::<Config>(b"krun_configure_worker_statepoint_restore_v1\0")
                .map_err(|e| e.to_string())?;
            self.check_managed_restore(
                "durable StatePoint",
                attach(ctx, config.as_ptr(), config.len()),
            )
        }
    }

    pub(crate) fn managed_target_authority(
        &self,
        ctx: u32,
        plan: &Plan,
        restore: &smolvm_resourced::managed::Restore,
        authority: &smolvm_resourced::native_client::TargetAuthority,
    ) -> Result<(), String> {
        type Authority = unsafe extern "C" fn(u32, i32, *const u8, *const u8, u64) -> i32;
        unsafe {
            let configure = self
                ._handle
                .get::<Authority>(b"krun_set_guest_target_authority_v1\0")
                .map_err(|e| e.to_string())?;
            self.check_managed_restore(
                "target identity authority",
                configure(
                    ctx,
                    authority.authority.as_raw_fd(),
                    authority.anchor.as_ptr(),
                    authority.context.as_ptr(),
                    plan.launch.execution.execution_epoch as u64,
                ),
            )?;
            if restore.source_pivot {
                let configure = self
                    ._handle
                    .get::<Config>(b"krun_configure_worker_block_restore_v1\0")
                    .map_err(|e| e.to_string())?;
                let proof=serde_json::to_vec(&serde_json::json!({"operation_id":plan.launch.operation_id,"request_digest":plan.launch.request_digest,
                    "source_pivot_id":restore.batch_id,"grant_id":plan.grant_id,"expected_revision":2})).map_err(|e| e.to_string())?;
                self.check_managed_restore(
                    "restored writer set",
                    configure(ctx, proof.as_ptr(), proof.len()),
                )?;
            }
        }
        Ok(())
    }

    fn check_managed_restore(&self, step: &str, status: i32) -> Result<(), String> {
        if status == 0 {
            Ok(())
        } else {
            let detail = self.last_error_message().unwrap_or_default();
            Err(format!("{step} returned {status}: {detail}"))
        }
    }
}
