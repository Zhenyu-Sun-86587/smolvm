//! Creates a quiescent single-queue TAP in a dedicated Linux network namespace.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::zeroed;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::thread;

#[path = "network_topology.rs"]
pub mod topology;

#[path = "network_overlay.rs"]
pub(crate) mod overlay;

pub const TAP_PORT_NAME: &str = "port0";
pub const TAP_MTU: u16 = 1500;
pub const TAP_VNET_HEADER_SIZE: u16 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct NamespaceIdentity {
    pub device: u64,
    pub inode: u64,
}

impl NamespaceIdentity {
    pub(crate) fn read(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let mut status = unsafe { zeroed::<libc::statfs>() };
        errno(unsafe { libc::fstatfs(fd.as_raw_fd(), &mut status) })?;
        if status.f_type as u64 != libc::NSFS_MAGIC as u64 {
            return Err(io::Error::other(
                "network descriptor is not an nsfs namespace",
            ));
        }
        let mut identity = unsafe { zeroed::<libc::stat>() };
        errno(unsafe { libc::fstat(fd.as_raw_fd(), &mut identity) })?;
        Ok(Self {
            device: identity.st_dev,
            inode: identity.st_ino,
        })
    }
}

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

    pub(crate) fn recover(
        pid: i32,
        process: BorrowedFd<'_>,
        expected: NamespaceIdentity,
    ) -> io::Result<Self> {
        let mut tap = None;
        for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
            let entry = entry?;
            let target = match fs::read_link(entry.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if target != Path::new("/dev/net/tun") {
                continue;
            }
            let number: libc::c_int = entry
                .file_name()
                .to_string_lossy()
                .parse()
                .map_err(|_| io::Error::other("invalid VMM TAP descriptor number"))?;
            // pidfd_getfd duplicates the live open file description. Opening
            // /proc/<pid>/fd/<n> would create a new, unrelated TUN queue.
            let duplicate =
                unsafe { libc::syscall(libc::SYS_pidfd_getfd, process.as_raw_fd(), number, 0) };
            if duplicate < 0 {
                return Err(io::Error::last_os_error());
            }
            let duplicate = unsafe { File::from_raw_fd(duplicate as libc::c_int) };
            let namespace = tap_network_namespace(duplicate.as_fd())?;
            if NamespaceIdentity::read(namespace.as_fd())? != expected {
                continue;
            }
            if tap.is_some() {
                return Err(io::Error::other(
                    "VMM has ambiguous descriptors for the recorded TAP",
                ));
            }
            tap = Some(Self {
                namespace,
                tap: duplicate,
            });
        }
        tap.ok_or_else(|| io::Error::other("VMM lacks the original published TAP"))
    }
}

fn tap_network_namespace(tap: BorrowedFd<'_>) -> io::Result<File> {
    let mut request = port_request();
    let mut header = 0_i32;
    let mut big_endian = 0_i32;
    // Check that the actual live descriptor is attached to the named,
    // nonpersistent, single-queue TAP with the negotiated virtio header.
    unsafe {
        let fd = tap.as_raw_fd();
        let status = libc::fcntl(fd, libc::F_GETFL);
        errno(status)?;
        errno(libc::ioctl(fd, libc::TUNGETIFF, &mut request))?;
        errno(libc::ioctl(fd, libc::TUNGETVNETHDRSZ, &mut header))?;
        if let Err(error) = errno(libc::ioctl(fd, libc::TUNGETVNETBE, &mut big_endian)) {
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
        }
        let name = request
            .ifr_name
            .iter()
            .copied()
            .take_while(|byte| *byte != 0);
        let flags = request.ifr_ifru.ifru_flags as u16;
        let required = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as u16;
        let excluded =
            (libc::IFF_TUN | libc::IFF_MULTI_QUEUE | libc::IFF_DETACH_QUEUE | libc::IFF_PERSIST)
                as u16;
        if !name.map(|byte| byte as u8).eq(TAP_PORT_NAME.bytes())
            || flags & required != required
            || flags & excluded != 0
            || header != i32::from(TAP_VNET_HEADER_SIZE)
            || big_endian != 0
            || status & (libc::O_ACCMODE | libc::O_NONBLOCK) != (libc::O_RDWR | libc::O_NONBLOCK)
        {
            return Err(io::Error::other(
                "live TAP framing or queue ownership changed",
            ));
        }
        let nsfd = libc::ioctl(fd, libc::TUNGETDEVNETNS);
        errno(nsfd)?;
        Ok(File::from_raw_fd(nsfd))
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
