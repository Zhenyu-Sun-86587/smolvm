//! Configure the deep block ABI with the original Worker file descriptions.
use super::KrunFunctions;
use smolvm_resourced::managed::{DiskSet, Plan};
use std::collections::BTreeMap;
use std::ffi::{c_char, CString};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
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
        layouts: &[DiskSet],
        files: &BTreeMap<String, OwnedFd>,
        helper: &[u8; 32],
        control: &Path,
        worker: &Path,
        bundle: &str,
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
        for set in layouts {
            let mut layers = Vec::new();
            for object in &set.layers {
                let fd = files
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
        env.push(ptr::null());
        let execution = &plan.launch.execution;
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
            if system {
                let path = control.with_file_name("agent.sock");
                let guest_socket =
                    CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
                check("System vsock", (self.add_vsock)(ctx, 0))?;
                check(
                    "System Guest Agent",
                    (self.add_vsock_port2)(ctx, 6000, guest_socket.as_ptr(), true),
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
