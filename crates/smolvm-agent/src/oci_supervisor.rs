//! Keep the mounted OCI guest alive while its management service restarts.

use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Duration;

pub fn run(service: impl Fn()) -> ! {
    // Fork the initialized guest view before any per-Agent threads start.
    // A child must never inherit a mutex held by a disappeared boot thread.
    if !std::fs::read_dir("/proc/self/task").is_ok_and(|tasks| tasks.count() == 1) {
        tracing::error!("OCI init requires a single-threaded boot process");
        std::process::exit(1);
    }
    if let Err(error) = crate::workload::prepare_state() {
        tracing::error!(%error, "cannot initialize OCI workload state");
        std::process::exit(1);
    }
    // SAFETY: Linux consumes a NUL-terminated name and copies it immediately.
    unsafe { libc::prctl(libc::PR_SET_NAME, c"smolvm-oci-init".as_ptr()) };
    let log_reader = match crate::workload::prepare_log_pipe() {
        Ok(reader) => reader,
        Err(error) => {
            tracing::warn!(%error, "could not prepare workload logging");
            None
        }
    };
    let mut log_pid = log_reader.as_ref().map(start_log_relay);

    loop {
        // SAFETY: the supervisor remains single threaded. It preserves the
        // initial mount/configuration state and holds no application locks.
        let pid = unsafe { libc::fork() };
        match pid {
            -1 => {
                tracing::error!(error = %std::io::Error::last_os_error(), "cannot fork OCI Agent");
                std::process::exit(1);
            }
            0 => {
                drop(log_reader);
                // SAFETY: same process-name API as above.
                unsafe { libc::prctl(libc::PR_SET_NAME, c"smolvm-agent".as_ptr()) };
                service();
                std::process::exit(0);
            }
            _ => {}
        }

        let status = loop {
            let mut status = 0;
            // SAFETY: status is writable for the duration of the call. Reap
            // other exited children too if this supervisor is Guest PID 1.
            let child = unsafe { libc::waitpid(-1, &mut status, 0) };
            if child == pid {
                break ExitStatus::from_raw(status);
            }
            if child > 0 && log_pid == Some(child) {
                tracing::warn!(child, "workload log relay exited, restarting it");
                std::thread::sleep(Duration::from_millis(200));
                log_pid = log_reader.as_ref().map(start_log_relay);
            }
            if child < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    tracing::error!(%error, "cannot wait for OCI Agent");
                    std::process::exit(1);
                }
            }
        };
        tracing::warn!(pid, %status, "OCI Agent exited, restarting the management service");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn start_log_relay(reader: &OwnedFd) -> libc::pid_t {
    // SAFETY: only the single-threaded supervisor calls this, with its own
    // live pipe descriptor. The new reader process owns all log threads.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        tracing::error!(error = %std::io::Error::last_os_error(), "cannot fork workload log relay");
        std::process::exit(1);
    }
    if pid == 0 {
        // SAFETY: the NUL-terminated name is copied immediately by Linux.
        unsafe { libc::prctl(libc::PR_SET_NAME, c"smolvm-wl-logs".as_ptr()) };
        match reader.try_clone() {
            Ok(reader) => crate::workload::relay_logs(reader),
            Err(error) => {
                tracing::error!(%error, "cannot duplicate workload log pipe");
                std::process::exit(1);
            }
        }
    }
    pid
}
