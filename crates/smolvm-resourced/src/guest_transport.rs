//! The management relay proves its actual Unix peer with an accepted socket.

use crate::catalog::{Catalog, Execution};
use crate::ipc::{self, Fault, Result};
use socket2::{Domain, Socket, Type};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) fn verify(catalog: &Catalog, execution: &Execution, connection: OwnedFd) -> Result<()> {
    let socket = Socket::from(connection);
    let peer = ipc::peer(&socket).map_err(|_| denied())?;
    if socket.domain().ok() != Some(Domain::UNIX)
        || socket.r#type().ok() != Some(Type::STREAM)
        || socket.peer_addr().is_err()
        || peer.pid != execution.pid
        || peer.uid != execution.uid
    {
        return Err(denied());
    }
    let peer_pidfd = live_peer(&socket)?;
    if crate::worker::pid_exited(&peer_pidfd).map_err(|_| denied())? {
        return Err(denied());
    }
    let operation = catalog.operation(&execution.last_operation_id)?;
    if operation.phase != "COMPLETED" {
        return Err(denied());
    }
    match operation.kind.as_str() {
        "launch" => Ok(()),
        "restore_target" => {
            let activation = catalog.activation(&operation.operation_id)?;
            if activation.matches(execution)
                && activation.phase == "released"
                && activation.decision == "commit"
            {
                Ok(())
            } else {
                Err(denied())
            }
        }
        _ => Err(denied()),
    }
}

fn live_peer(socket: &Socket) -> Result<OwnedFd> {
    let mut fd = -1_i32;
    let mut size = std::mem::size_of::<i32>() as libc::socklen_t;
    // The kernel returns a new pidfd pinned to the original peer of this
    // connection. Numeric SO_PEERCRED alone could survive a reused PID.
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut i32).cast(),
            &mut size,
        )
    };
    if status < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOPROTOOPT) {
        return Err(Fault::new(
            "E_CAPABILITY_UNSUPPORTED",
            "Guest transport requires a kernel peer pidfd",
        ));
    }
    if status < 0 || fd < 0 {
        return Err(denied());
    }
    // SAFETY: SO_PEERPIDFD returned a newly owned close-on-exec descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    if size as usize != std::mem::size_of::<i32>() {
        return Err(denied());
    }
    Ok(pidfd)
}

fn denied() -> Fault {
    Fault::new(
        "E_PERMISSION_DENIED",
        "Guest relay peer is not the published execution",
    )
}
