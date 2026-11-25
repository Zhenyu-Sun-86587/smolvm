use super::Transport;
use std::ffi::CStr;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(super) struct Packet {
    pub source: Ipv4Addr,
    pub target: Ipv4Addr,
    pub transport: Transport,
    pub port: u16,
    pub received_ns: i64,
}

pub(crate) fn open(interface: &CStr) -> io::Result<OwnedFd> {
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    for (level, option, value) in [
        (libc::SOL_PACKET, libc::PACKET_IGNORE_OUTGOING, 1),
        (libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, 1),
        (libc::SOL_SOCKET, libc::SO_RCVBUF, 8192),
    ] {
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                level,
                option,
                (&value as *const i32).cast(),
                size_of::<i32>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    address.sll_ifindex = index as i32;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_ll).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub(super) fn drain(socket: &OwnedFd) -> io::Result<Vec<Packet>> {
    let mut packets = Vec::new();
    // Read the longest IPv4 header and twenty transport bytes. No application data is retained.
    let mut header = [0u8; 80];
    for _ in 0..24 {
        let mut address: libc::sockaddr_ll = unsafe { zeroed() };
        let mut control: [libc::cmsghdr; 4] = unsafe { zeroed() };
        let mut iov = libc::iovec {
            iov_base: header.as_mut_ptr().cast(),
            iov_len: header.len(),
        };
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_name = (&mut address as *mut libc::sockaddr_ll).cast();
        message.msg_namelen = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of::<[libc::cmsghdr; 4]>();
        let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_TRUNC) };
        if len < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                break;
            }
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if address.sll_pkttype != libc::PACKET_HOST as u8 {
            continue;
        }
        if let Some(packet) = timestamp(&message).and_then(|received_ns| {
            classify(
                &header[..header.len().min(len as usize)],
                len as usize,
                received_ns,
            )
        }) {
            packets.push(packet);
        }
    }
    Ok(packets)
}

fn timestamp(message: &libc::msghdr) -> Option<i64> {
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return None;
    }
    // The kernel filled this aligned buffer with timestamp ancillary data.
    let mut hdr = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !hdr.is_null() {
        let value = unsafe { &*hdr };
        if value.cmsg_level == libc::SOL_SOCKET
            && value.cmsg_type == libc::SCM_TIMESTAMPNS
            && value.cmsg_len >= unsafe { libc::CMSG_LEN(size_of::<libc::timespec>() as u32) } as _
        {
            let ts = unsafe {
                libc::CMSG_DATA(hdr)
                    .cast::<libc::timespec>()
                    .read_unaligned()
            };
            return ts
                .tv_sec
                .checked_mul(1_000_000_000)?
                .checked_add(ts.tv_nsec);
        }
        hdr = unsafe { libc::CMSG_NXTHDR(message, hdr) };
    }
    None
}

fn classify(header: &[u8], frame_len: usize, received_ns: i64) -> Option<Packet> {
    let ip = header.get(..20)?;
    let ip_header = usize::from(ip[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
    let fragment = u16::from_be_bytes([ip[6], ip[7]]);
    if ip[0] >> 4 != 4 || ip_header < 20 || total > frame_len || fragment & 0x3fff != 0 {
        return None;
    }
    let transport_len = total.checked_sub(ip_header)?;
    let transport = match ip[9] {
        6 => {
            let tcp = header.get(ip_header..ip_header + 20)?;
            let tcp_header = usize::from(tcp[12] >> 4) * 4;
            // Only initial SYNs can express a new TCP connection.
            if tcp_header < 20 || tcp_header > transport_len || tcp[13] & 0x17 != 0x02 {
                return None;
            }
            Transport::Tcp
        }
        17 => {
            let udp = header.get(ip_header..ip_header + 8)?;
            if transport_len < 8
                || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != transport_len
            {
                return None;
            }
            Transport::Udp
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([header[ip_header + 2], header[ip_header + 3]]);
    if port == 0 || header[ip_header..ip_header + 2] == [0, 0] {
        return None;
    }
    Some(Packet {
        source: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        target: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        transport,
        port,
        received_ns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_new_ipv4_flow_is_a_wake_candidate() {
        let mut bytes = [0u8; 40];
        bytes[0] = 0x45;
        bytes[3] = 40;
        bytes[9] = 6;
        bytes[12..20].copy_from_slice(&[10, 2, 0, 2, 10, 2, 0, 3]);
        bytes[20..24].copy_from_slice(&[0x31, 0x12, 0x01, 0xbb]);
        bytes[32] = 0x50;
        bytes[33] = 0x02;
        let syn = classify(&bytes, bytes.len(), 42).unwrap();
        assert_eq!(syn.target, Ipv4Addr::new(10, 2, 0, 3));
        assert_eq!(syn.transport, Transport::Tcp);
        assert_eq!(syn.port, 443);
        bytes[33] = 0x12;
        assert!(classify(&bytes, bytes.len(), 42).is_none());
        bytes[33] = 0x02;
        bytes[6] = 0x20;
        assert!(classify(&bytes, bytes.len(), 42).is_none());
        bytes[6] = 0;
        bytes[3] = 36;
        bytes[9] = 17;
        bytes[25] = 16;
        assert_eq!(
            classify(&bytes[..28], 36, 42).unwrap().transport,
            Transport::Udp
        );
        assert!(classify(&bytes[..27], 36, 42).is_none());
        bytes[25] = 8;
        assert!(classify(&bytes[..28], 36, 42).is_none());
    }
}
