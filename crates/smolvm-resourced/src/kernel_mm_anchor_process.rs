//! Single-purpose process that holds one immutable kernel CoW RAM mapping.

use super::kernel_mm_anchor::{command_address, in_scope, Init, ANCHOR_UID};
use crate::ipc;
use sha2::{Digest, Sha256};
use smolvm_runtime_protocol::kernel_cow::{packed_size, Region};
use socket2::{Domain, Socket, Type};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type Import = unsafe extern "C" fn(libc::c_int, *const Region, usize, u32, u32) -> i32;
type Export = unsafe extern "C" fn(libc::c_int) -> i32;

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn trusted_file(root: &Path, relative: &str) -> io::Result<(PathBuf, File)> {
    let path = root.join(relative).canonicalize()?;
    if !path.starts_with(root) {
        return Err(invalid("kernel CoW library is outside its runtime bundle"));
    }
    for parent in path.ancestors().skip(1) {
        let meta = fs::metadata(parent)?;
        // A root-owned sticky directory cannot rename another root-owned entry.
        if !meta.is_dir()
            || meta.uid() != 0
            || (meta.mode() & 0o022 != 0 && meta.mode() & libc::S_ISVTX == 0)
        {
            return Err(invalid(
                "kernel CoW runtime directory is writable by another user",
            ));
        }
    }
    let file = File::open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(invalid(
            "kernel CoW runtime artifact is not root-owned and immutable",
        ));
    }
    Ok((path, file))
}

fn load_library(
    root: &Path,
    manifest: &serde_json::Value,
    artifact: &str,
    flags: libc::c_int,
) -> io::Result<*mut libc::c_void> {
    let mut entries = manifest["artifacts"]
        .as_array()
        .ok_or_else(|| invalid("bundle has no artifact list"))?
        .iter()
        .filter(|item| item["path"] == artifact);
    let entry = entries
        .next()
        .ok_or_else(|| invalid("missing kernel CoW runtime library"))?;
    if entries.next().is_some() {
        return Err(invalid(
            "kernel CoW runtime library occurs twice in the manifest",
        ));
    }
    let (path, mut file) = trusted_file(root, artifact)?;
    let mut hash = Sha256::new();
    let length = io::copy(&mut file, &mut hash)?;
    if entry["size"].as_u64() != Some(length)
        || entry["sha256"].as_str() != Some(&format!("{:x}", hash.finalize()))
    {
        return Err(invalid(
            "kernel CoW runtime library differs from the registered bundle",
        ));
    }
    // SAFETY: the approved, root-owned bundle path is a terminated C string.
    let path = CString::new(path.as_os_str().as_bytes())?;
    let handle = unsafe { libc::dlopen(path.as_ptr(), flags) };
    if handle.is_null() {
        return Err(invalid(
            "could not load the approved library for a kernel CoW anchor",
        ));
    }
    // Keep both library mappings for the life of this process.
    Ok(handle)
}

fn libraries(init: &Init) -> io::Result<(Import, Export)> {
    let executable = std::env::current_exe()?;
    let root = executable
        .parent()
        .ok_or_else(|| invalid("missing runtime bundle directory"))?;
    let (_, manifest_file) = trusted_file(root, "runtime-bundle.json")?;
    let mut manifest = Vec::new();
    manifest_file
        .take(1024 * 1024 + 1)
        .read_to_end(&mut manifest)?;
    if manifest.len() > 1024 * 1024 {
        return Err(invalid("oversized runtime bundle manifest"));
    }
    let manifest: serde_json::Value = serde_json::from_slice(&manifest)?;
    let executable_sha = init
        .executable_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("invalid approved executable measurement"))?;
    let validated =
        smolvm_runtime_protocol::handshake(manifest.clone(), executable_sha).map_err(invalid)?;
    if validated.bundle_digest != init.bundle_digest {
        return Err(invalid("kernel CoW anchor runtime bundle changed"));
    }
    load_library(
        root,
        &manifest,
        "lib/libkrunfw.so.5",
        libc::RTLD_LAZY | libc::RTLD_GLOBAL,
    )?;
    let handle = load_library(root, &manifest, "lib/libkrun.so.2", libc::RTLD_LAZY)?;
    // SAFETY: the bundle supplies the named, versioned C ABI.
    let import =
        unsafe { libc::dlsym(handle, c"krun_import_worker_kernel_cow_anchor_v1".as_ptr()) };
    let export = unsafe { libc::dlsym(handle, c"krun_write_worker_kernel_cow_anchor_v1".as_ptr()) };
    if import.is_null() || export.is_null() {
        return Err(invalid("runtime bundle lacks the kernel CoW anchor ABI"));
    }
    // SAFETY: the verified symbols implement the exact private signatures.
    Ok(unsafe {
        (
            std::mem::transmute::<_, Import>(import),
            std::mem::transmute::<_, Export>(export),
        )
    })
}

fn lockdown() -> io::Result<()> {
    const LD_ABS: u16 = 0x20;
    const EQ: u16 = 0x15;
    const RET: u16 = 0x06;
    const X86_64: u32 = 0xc000_003e;
    let instruction = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
    let mut filter = vec![
        instruction(LD_ABS, 4, 0, 0), // seccomp_data.arch
        instruction(EQ, X86_64, 1, 0),
        instruction(RET, libc::SECCOMP_RET_KILL_PROCESS, 0, 0),
        instruction(LD_ABS, 0, 0, 0), // seccomp_data.nr
    ];
    for allowed in [
        libc::SYS_accept4,
        libc::SYS_close,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_recvfrom,
        libc::SYS_sendto,
        libc::SYS_clock_gettime,
        libc::SYS_restart_syscall,
        libc::SYS_rt_sigreturn,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        filter.push(instruction(EQ, allowed as u32, 0, 1));
        filter.push(instruction(RET, libc::SECCOMP_RET_ALLOW, 0, 0));
    }
    // No mapping, cloning, opening files, CoW imports, or other peer creation.
    filter.push(instruction(RET, libc::SECCOMP_RET_KILL_PROCESS, 0, 0));
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: single-threaded and supplied the initialized cBPF vector.
    if unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0
    } {
        return Err(io::Error::last_os_error());
    }
    // libc may use munmap when destroying heap allocations. The process
    // holds this small buffer until exit together with the verified library.
    std::mem::forget(filter);
    Ok(())
}

fn serve(mut socket: Socket, export: Export) -> io::Result<()> {
    if ipc::peer(&socket)?.uid != 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(90)))?;
    let mut op = [0];
    socket.read_exact(&mut op)?;
    match op[0] {
        b'Q' => socket.write_all(b"+"),
        b'R' => {
            socket.write_all(b"+")?;
            // SAFETY: the root peer requested a stream and the fd stays open.
            let status = unsafe { export(socket.as_raw_fd()) };
            if status == 0 {
                socket.write_all(b"+")?;
            }
            Ok(())
        }
        _ => Err(invalid("unknown kernel CoW anchor request")),
    }
}

pub(super) fn run() -> io::Result<()> {
    // SAFETY: inherited standard input is the launch socket. Close any fds
    // other than this connection and standard output/error before loading.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let boot = Socket::from(unsafe { OwnedFd::from_raw_fd(0) });
    if ipc::peer(&boot)?.uid != 0 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    boot.set_read_timeout(Some(Duration::from_secs(15)))?;
    let packet = ipc::receive_packet_with_limit(&boot, 1)
        .map_err(|fault| io::Error::other(fault.message))?;
    let init: Init = serde_json::from_slice(&packet.body)?;
    let donor = packet
        .descriptors
        .into_iter()
        .next()
        .ok_or_else(|| invalid("missing donor pidfd"))?;
    if !in_scope(std::process::id() as i32, &init.helper_id)? {
        return Err(invalid("kernel CoW anchor is outside its Worker scope"));
    }
    let bytes = packed_size(&init.regions).map_err(invalid)?;
    let (dir, address) = command_address(&init.directory, &init.helper_id)?;
    let listener = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    listener.bind(&address)?;
    drop(dir);
    drop(boot);
    let (import, export) = libraries(&init)?;
    // SAFETY: this is the dedicated final helper process, with an authenticated
    // held donor, valid C layouts and no other threads.
    let started = Instant::now();
    let status = unsafe {
        import(
            donor.into_raw_fd(),
            init.regions.as_ptr(),
            init.regions.len(),
            ANCHOR_UID,
            ANCHOR_UID,
        )
    };
    eprintln!(
        "smolvm kernel CoW anchor capture={} import_bootstrap_us={} ram_bytes={} status={}",
        init.capture_id,
        started.elapsed().as_micros(),
        bytes,
        status,
    );
    if status != 0 {
        return Err(io::Error::from_raw_os_error(-status));
    }
    // SAFETY: these simple process attributes apply to the only thread.
    if unsafe {
        libc::geteuid() != ANCHOR_UID
            || libc::getegid() != ANCHOR_UID
            || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
    } {
        return Err(invalid("kernel CoW anchor credential lockdown failed"));
    }
    // Listen after the drop so SO_PEERCRED attests to the restricted identity.
    listener.listen(4)?;
    drop(init);
    // SAFETY: the listener has a different fd, and there is no required output
    // after readiness. Ignore SIGPIPE from interrupted durable exports.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        libc::close(1);
        libc::close(2);
    }
    lockdown()?;
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                let _ = serve(socket, export);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    const SANDBOX_TEST: &str = "SMOLVM_TEST_ONLY_ANCHOR_SECCOMP";

    #[test]
    fn restricts_mprotect_after_import_even_with_maywrite() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "kernel_mm_anchor_process::tests::sandbox_child",
                "--nocapture",
            ])
            .env(SANDBOX_TEST, "1")
            .output()
            .unwrap();
        assert_eq!(output.status.signal(), Some(libc::SIGSYS));
        assert!(output.stdout.windows(7).any(|bytes| bytes == b"locked\n"));
    }

    #[test]
    fn sandbox_child() {
        if std::env::var_os(SANDBOX_TEST).is_none() {
            return;
        }
        let byte = 4096;
        // SAFETY: use a dedicated read-only test mapping. Leave no core file.
        let page = unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0), 0);
            libc::mmap(
                std::ptr::null_mut(),
                byte,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        lockdown().unwrap();
        let marker = b"locked\n";
        // SAFETY: stdout is the test pipe and the mapping is valid. The
        // protection change is explicitly disallowed by the helper sandbox.
        unsafe {
            libc::write(1, marker.as_ptr().cast(), marker.len());
            libc::syscall(
                libc::SYS_mprotect,
                page,
                byte,
                libc::PROT_READ | libc::PROT_WRITE,
            );
            libc::_exit(66);
        }
    }
}
