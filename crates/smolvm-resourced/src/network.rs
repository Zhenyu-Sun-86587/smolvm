//! Creates a quiescent single-queue TAP in a dedicated Linux network namespace.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::zeroed;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::thread;

#[path = "network_topology.rs"]
pub mod topology;

pub const TAP_PORT_NAME: &str = "port0";
pub const TAP_MTU: u16 = 1500;
pub const TAP_VNET_HEADER_SIZE: u16 = 12;

/// A prepared TAP and its private namespace. The link starts down and has
/// no router link. Dropping the owner releases both kernel references.
pub struct PreparedTapPort {
    namespace: File,
    tap: File,
}

impl PreparedTapPort {
    pub fn namespace(&self) -> BorrowedFd<'_> {
        self.namespace.as_fd()
    }

    pub fn tap(&self) -> BorrowedFd<'_> {
        self.tap.as_fd()
    }
}

/// Creates the port on a fresh thread so the Worker never changes its own
/// network namespace. It is the caller's job to journal admission and retain
/// this owner until the attachment is connected or discarded.
pub fn prepare_tap_port() -> io::Result<PreparedTapPort> {
    thread::Builder::new()
        .name("prepare-network-port".to_owned())
        .spawn(prepare_in_new_namespace)?
        .join()
        .map_err(|_| io::Error::other("network port preparation thread panicked"))?
}

fn prepare_in_new_namespace() -> io::Result<PreparedTapPort> {
    let namespace = enter_private_namespace()?;
    let tap = prepare_tap()?;
    Ok(PreparedTapPort { namespace, tap })
}

fn enter_private_namespace() -> io::Result<File> {
    // SAFETY: the dedicated thread has no namespace-sensitive resources yet.
    errno(unsafe { libc::unshare(libc::CLONE_NEWNET) })?;
    let namespace = File::open("/proc/thread-self/ns/net")?;
    // Both settings are scoped to the new Linux network namespace.
    for scope in ["all", "default"] {
        fs::write(
            format!("/proc/sys/net/ipv6/conf/{scope}/disable_ipv6"),
            b"1\n",
        )?;
        fs::write(format!("/proc/sys/net/ipv4/conf/{scope}/rp_filter"), b"0\n")?;
    }
    Ok(namespace)
}

fn prepare_tap() -> io::Result<File> {
    let tap = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/net/tun")?;
    let mut request = port_request();
    request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as _;
    let header_size = libc::c_int::from(TAP_VNET_HEADER_SIZE);
    // SAFETY: these requests use a live TUN descriptor and initialized
    // arguments with the sizes required by the Linux UAPI.
    unsafe {
        errno(libc::ioctl(tap.as_raw_fd(), libc::TUNSETIFF, &mut request))?;
        errno(libc::ioctl(
            tap.as_raw_fd(),
            libc::TUNSETVNETHDRSZ,
            &header_size,
        ))?;
        errno(libc::ioctl(tap.as_raw_fd(), libc::TUNSETOFFLOAD, 0_u64))?;
    }
    let control = new_control_socket()?;
    let mut request = port_request();
    request.ifr_ifru.ifru_mtu = libc::c_int::from(TAP_MTU);
    // SAFETY: the socket and ifreq belong to this thread's isolated namespace.
    unsafe {
        errno(libc::ioctl(control.as_raw_fd(), libc::SIOCSIFMTU, &request))?;
        errno(libc::ioctl(
            control.as_raw_fd(),
            libc::SIOCGIFFLAGS,
            &mut request,
        ))?;
        if libc::c_int::from(request.ifr_ifru.ifru_flags) & libc::IFF_UP != 0 {
            return Err(io::Error::other("new TAP port is unexpectedly up"));
        }
    }
    Ok(tap)
}

fn port_request() -> libc::ifreq {
    // SAFETY: ifreq is a C POD type initialized with a NUL-terminated ifname.
    let mut request: libc::ifreq = unsafe { zeroed() };
    for (target, src) in request.ifr_name.iter_mut().zip(TAP_PORT_NAME.bytes()) {
        *target = src as libc::c_char;
    }
    request
}

fn new_control_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket returns a new descriptor on success.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    errno(fd)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn errno(result: libc::c_int) -> io::Result<()> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    #[test]
    #[ignore = "requires Linux CAP_SYS_ADMIN, CAP_NET_ADMIN and /dev/net/tun"]
    fn worker_creates_independent_down_tap_ports() {
        let host_namespace = fs::metadata("/proc/thread-self/ns/net").unwrap();
        let first = prepare_tap_port().unwrap();
        let second = prepare_tap_port().unwrap();
        let namespace_id = |fd: BorrowedFd<'_>| {
            fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                .unwrap()
                .ino()
        };
        assert_ne!(namespace_id(first.namespace()), host_namespace.ino());
        assert_ne!(
            namespace_id(first.namespace()),
            namespace_id(second.namespace())
        );
        assert_eq!(
            fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
            host_namespace.ino()
        );
        for port in [first, second] {
            let mut header = 0;
            assert_eq!(
                unsafe { libc::ioctl(port.tap().as_raw_fd(), libc::TUNGETVNETHDRSZ, &mut header) },
                0
            );
            assert_eq!(header, 12);
        }
    }
}
