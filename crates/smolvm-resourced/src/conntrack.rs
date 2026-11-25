//! Read original-direction IPv4 conntrack tuples inside a proven private router.
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "incomplete conntrack snapshot")
}
fn field(data: &[u8], kind: u16) -> io::Result<Option<&[u8]>> {
    let mut at = 0;
    while at < data.len() {
        let header = data.get(at..at + 4).ok_or_else(bad)?;
        let len = u16::from_ne_bytes([header[0], header[1]]) as usize;
        let typ = u16::from_ne_bytes([header[2], header[3]]) & 0x3fff;
        if len < 4 || at + len > data.len() {
            return Err(bad());
        }
        if typ == kind {
            return Ok(Some(&data[at + 4..at + len]));
        }
        at += (len + 3) & !3;
    }
    Ok(None)
}
pub(crate) fn counts(address: Ipv4Addr) -> io::Result<(u64, u64)> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    let mut req = [0u8; 20];
    req[..4].copy_from_slice(&20u32.to_ne_bytes());
    req[4..6].copy_from_slice(&0x101u16.to_ne_bytes());
    req[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    req[16] = libc::AF_INET as u8;
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&kernel) as _,
        )
    };
    if sent != req.len() as isize {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; 128 * 1024];
    let mut inbound = 0u64;
    let mut outbound = 0u64;
    let now = Instant::now();
    loop {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if now.elapsed().as_millis() > 500 || unsafe { libc::poll(&mut poll, 1, 100) } != 1 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let size = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if size <= 0 || size as usize > buf.len() {
            return Err(bad());
        }
        let packet = &buf[..size as usize];
        let mut at = 0;
        while at < packet.len() {
            let head = packet.get(at..at + 16).ok_or_else(bad)?;
            let n = u32::from_ne_bytes(head[..4].try_into().unwrap()) as usize;
            if n < 16 || at + n > packet.len() || head[8..12] != 1u32.to_ne_bytes() {
                return Err(bad());
            }
            let typ = u16::from_ne_bytes([head[4], head[5]]);
            let flags = u16::from_ne_bytes([head[6], head[7]]);
            if flags & 0x10 != 0 {
                return Err(bad());
            } // NLM_F_DUMP_INTR
            let body = &packet[at + 16..at + n];
            if typ == libc::NLMSG_DONE as u16 {
                if body.len() >= 4 && body[..4] != [0, 0, 0, 0] {
                    return Err(bad());
                }
                return Ok((inbound, outbound));
            }
            if typ == libc::NLMSG_ERROR as u16 || typ != 0x100 {
                return Err(bad());
            }
            let attrs = body.get(4..).ok_or_else(bad)?;
            let tuple = field(attrs, 1)?.ok_or_else(bad)?;
            let ip = field(tuple, 1)?.ok_or_else(bad)?;
            let src = field(ip, 1)?.ok_or_else(bad)?;
            let dest = field(ip, 2)?.ok_or_else(bad)?;
            // Closing TCP entries no longer represent an application session.
            let mut active = true;
            if let Some(info) = field(attrs, 4)? {
                if let Some(tcp) = field(info, 1)? {
                    if let Some(state) = field(tcp, 1)? {
                        active = !matches!(state.first(), Some(4..=9));
                    }
                }
            }
            if active {
                inbound += u64::from(dest == address.octets());
                outbound += u64::from(src == address.octets());
            }
            at += (n + 3) & !3;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read,Write};
    use std::net::{TcpListener,TcpStream};

    #[test]
    #[ignore = "needs an isolated Linux router namespace with conntrack enabled"]
    fn loopback_tcp_session() {
        let listener=TcpListener::bind(("127.0.0.2",0)).unwrap();
        let mut sender=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut receiver,_)=listener.accept().unwrap();
        sender.write_all(b"x").unwrap();receiver.read_exact(&mut [0]).unwrap();
        let (incoming,_)=counts("127.0.0.2".parse().unwrap()).unwrap();
        assert!(incoming>=1);
    }
}
