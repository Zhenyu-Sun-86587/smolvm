// SPDX-License-Identifier: Apache-2.0
//! Apply an IPv4 identity to the one registered uplink while ordinary traffic is closed.
use super::{errno, invalid};
use std::ffi::CStr;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const REQUEST: u16 = 1;
const ACK: u16 = 4;
const DUMP: u16 = 0x300;
const CREATE_EXCLUSIVE: u16 = 0x600;
const MAIN: u8 = 254;

struct LinkIdentity<'a> {
    name: &'a CStr,
    old_mac: [u8; 6],
    new_mac: [u8; 6],
    old: Address,
    new: Address,
    dns: Ipv4Addr,
}
#[derive(Clone, Copy, PartialEq)]
struct Address {
    ip: [u8; 4],
    prefix: u8,
    gateway: [u8; 4],
}

impl Address {
    fn check(self) -> bool {
        if self.prefix == 32 {
            return self.ip != self.gateway
                && [self.ip, self.gateway]
                    .into_iter()
                    .all(|v| Ipv4Addr::from(v).is_private());
        }
        if !(1..=30).contains(&self.prefix) {
            return false;
        }
        let mask = u32::MAX << (32 - self.prefix);
        let ip = u32::from_be_bytes(self.ip);
        let gw = u32::from_be_bytes(self.gateway);
        [self.ip, self.gateway].into_iter().all(|v| {
            let a = Ipv4Addr::from(v);
            let host = u32::from_be_bytes(v) & !mask;
            a.is_private() && host != 0 && host != !mask
        }) && ip != gw
            && ip & mask == gw & mask
    }
}

impl<'a> LinkIdentity<'a> {
    fn decode(b: &'a [u8; 64]) -> io::Result<Self> {
        let amount = b[40..56].iter().position(|&v| v == 0).ok_or_else(invalid)?;
        if &b[..4] != b"NET1"
            || !matches!(b[4], 1 | 2)
            || b[7] != 0
            || b[56..].iter().any(|&v| v != 0)
            || amount == 0
            || b[40 + amount..56].iter().any(|&v| v != 0)
            || !b[40..40 + amount]
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err(invalid());
        }
        let name = CStr::from_bytes_with_nul(&b[40..=40 + amount]).map_err(|_| invalid())?;
        let ident = Self {
            name,
            old_mac: b[8..14].try_into().unwrap(),
            new_mac: b[14..20].try_into().unwrap(),
            old: Address {
                ip: b[20..24].try_into().unwrap(),
                prefix: b[5],
                gateway: b[28..32].try_into().unwrap(),
            },
            new: Address {
                ip: b[24..28].try_into().unwrap(),
                prefix: b[6],
                gateway: b[32..36].try_into().unwrap(),
            },
            dns: Ipv4Addr::from(<[u8; 4]>::try_from(&b[36..40]).unwrap()),
        };
        if [ident.old_mac, ident.new_mac]
            .into_iter()
            .any(|m| m == [0; 6] || m[0] & 1 != 0)
            || !ident.old.check()
            || !ident.new.check()
            || ident.dns.is_unspecified()
            || ident.dns.is_multicast()
            || ident.dns.is_broadcast()
        {
            return Err(invalid());
        }
        Ok(ident)
    }
}

fn u16at(b: &[u8], p: usize) -> u16 {
    u16::from_ne_bytes(b[p..p + 2].try_into().unwrap())
}
fn u32at(b: &[u8], p: usize) -> u32 {
    u32::from_ne_bytes(b[p..p + 4].try_into().unwrap())
}
fn align(n: usize) -> usize {
    (n + 3) & !3
}

fn attribute(msg: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
    msg.extend_from_slice(&((bytes.len() + 4) as u16).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(bytes);
    msg.resize(align(msg.len()), 0)
}
fn attrs(mut body: &[u8], mut visit: impl FnMut(u16, &[u8])) -> io::Result<()> {
    while !body.is_empty() {
        if body.len() < 4 {
            return Err(invalid());
        }
        let n = u16at(body, 0) as usize;
        if n < 4 || align(n) > body.len() {
            return Err(invalid());
        }
        visit(u16at(body, 2), &body[4..n]);
        body = &body[align(n)..];
    }
    Ok(())
}
struct RouteSocket {
    socket: OwnedFd,
    seq: u32,
}
impl RouteSocket {
    fn open() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        errno(fd)?;
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as _;
        errno(unsafe {
            libc::connect(
                fd,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&kernel) as _,
            )
        })?;
        Ok(Self { socket, seq: 0 })
    }
    fn transact(
        &mut self,
        kind: u16,
        flags: u16,
        payload: &[u8],
        mut visit: impl FnMut(u16, &[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.seq += 1;
        let mut msg = Vec::with_capacity(16 + payload.len());
        msg.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&(REQUEST | flags).to_ne_bytes());
        msg.extend_from_slice(&self.seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(payload);
        let fd = self.socket.as_raw_fd();
        if unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) } != msg.len() as isize {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 32768];
        loop {
            let mut from: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of_val(&from) as libc::socklen_t;
            let bytes = unsafe {
                libc::recvfrom(
                    fd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_TRUNC,
                    (&mut from as *mut libc::sockaddr_nl).cast(),
                    &mut len,
                )
            };
            if bytes < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            if bytes == 0 || bytes as usize > buf.len() || from.nl_pid != 0 {
                return Err(invalid());
            }
            let mut incoming = &buf[..bytes as usize];
            while !incoming.is_empty() {
                if incoming.len() < 16 {
                    return Err(invalid());
                }
                let n = u32at(incoming, 0) as usize;
                if n < 16
                    || align(n) > incoming.len()
                    || u32at(incoming, 8) != self.seq
                    || u16at(incoming, 6) & 0x10 != 0
                {
                    return Err(invalid());
                }
                let data = &incoming[16..n];
                match u16at(incoming, 4) {
                    2 | 3 => {
                        if data.len() < 4 {
                            return Err(invalid());
                        }
                        let rc = i32::from_ne_bytes(data[..4].try_into().unwrap());
                        if rc < 0 {
                            return Err(io::Error::from_raw_os_error(-rc));
                        } else if rc != 0 {
                            return Err(invalid());
                        }
                        return Ok(());
                    }
                    kind => visit(kind, data)?,
                }
                incoming = &incoming[align(n)..];
            }
        }
    }
    fn change(&mut self, kind: u16, flags: u16, payload: &[u8]) -> io::Result<()> {
        self.transact(kind, flags | ACK, payload, |_, _| Err(invalid()))
    }

    fn verify(&mut self, idx: u32, mac: &[u8; 6], wanted: Address) -> io::Result<()> {
        let mut found = false;
        self.transact(libc::RTM_GETLINK, DUMP, &[0; 16], |kind, data| {
            if kind != libc::RTM_NEWLINK || data.len() < 16 {
                return Err(invalid());
            }
            if u32at(data, 4) == idx {
                if found || u16at(data, 2) != 1 || u32at(data, 8) & libc::IFF_UP as u32 == 0 {
                    return Err(invalid());
                }
                attrs(&data[16..], |ty, val| {
                    if ty == libc::IFLA_ADDRESS && val == mac {
                        found = true
                    }
                })?;
            }
            Ok(())
        })?;
        if !found {
            return Err(invalid());
        }
        let mut ips = Vec::new();
        self.transact(
            libc::RTM_GETADDR,
            DUMP,
            &[libc::AF_INET as u8, 0, 0, 0, 0, 0, 0, 0],
            |k, d| {
                if k != libc::RTM_NEWADDR || d.len() < 8 {
                    return Err(invalid());
                }
                if d[0] == libc::AF_INET as u8 && u32at(d, 4) == idx {
                    attrs(&d[8..], |ty, v| {
                        if ty == libc::IFA_LOCAL {
                            ips.push((d[1], v.to_vec()))
                        }
                    })?
                }
                Ok(())
            },
        )?;
        if ips != [(wanted.prefix, wanted.ip.to_vec())] {
            return Err(invalid());
        }
        let mut gateways = Vec::new();
        let mut gateway_host_route = false;
        self.transact(
            libc::RTM_GETROUTE,
            DUMP,
            &[libc::AF_INET as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            |k, d| {
                if k != libc::RTM_NEWROUTE || d.len() < 12 {
                    return Err(invalid());
                }
                if d[0] == libc::AF_INET as u8
                    && d[4] == MAIN
                    && d[7] == 1
                    && matches!(d[1], 0 | 32)
                {
                    let (mut out, mut via, mut destination, mut multi) = (None, None, None, false);
                    attrs(&d[12..], |ty, value| match ty {
                        libc::RTA_OIF if value.len() == 4 => out = Some(u32at(value, 0)),
                        libc::RTA_GATEWAY => via = Some(value.to_vec()),
                        libc::RTA_DST if value.len() == 4 => {
                            destination = Some(<[u8; 4]>::try_from(value).unwrap())
                        }
                        libc::RTA_MULTIPATH => multi = true,
                        _ => (),
                    })?;
                    if d[1] == 0 && multi {
                        return Err(invalid());
                    }
                    if out == Some(idx) {
                        if d[1] == 0 {
                            gateways.push(via);
                        } else if d[6] == libc::RT_SCOPE_LINK
                            && destination == Some(wanted.gateway)
                            && via.is_none()
                        {
                            gateway_host_route = true;
                        }
                    }
                }
                Ok(())
            },
        )?;
        if gateways != [Some(wanted.gateway.to_vec())]
            || (wanted.prefix == 32 && !gateway_host_route)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn set_mac(&mut self, idx: u32, mac: &[u8; 6]) -> io::Result<()> {
        // The managed virtio-net driver supports live MAC changes. Cycling the
        // link here would remove unrelated routes and modify workload state.
        let mut msg = vec![0; 16];
        msg[4..8].copy_from_slice(&idx.to_ne_bytes());
        attribute(&mut msg, libc::IFLA_ADDRESS, mac);
        self.change(libc::RTM_NEWLINK, 0, &msg)
    }

    fn reset_neighbors(&mut self, idx: u32) -> io::Result<()> {
        // Both Native and Fixed targets use a fresh Worker endpoint. A cached
        // gateway MAC can still look reachable to the restored TCP/IP stack.
        let mut query = [0; 12];
        query[0] = libc::AF_INET as u8;
        let mut addresses = Vec::new();
        self.transact(libc::RTM_GETNEIGH, DUMP, &query, |kind, data| {
            if kind != libc::RTM_NEWNEIGH || data.len() < 12 {
                return Err(invalid());
            }
            if data[0] == query[0] && u32at(data, 4) == idx && data[10] & libc::NTF_PROXY == 0 {
                attrs(&data[12..], |kind, value| {
                    if kind == libc::NDA_DST && value.len() == 4 {
                        addresses.push(<[u8; 4]>::try_from(value).unwrap());
                    }
                })?;
                if addresses.len() > 4096 {
                    return Err(io::Error::from_raw_os_error(libc::E2BIG));
                }
            }
            Ok(())
        })?;
        query[4..8].copy_from_slice(&idx.to_ne_bytes());
        for address in addresses {
            let mut msg = query.to_vec();
            attribute(&mut msg, libc::NDA_DST, &address);
            match self.change(libc::RTM_DELNEIGH, 0, &msg) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => (),
                result => result?,
            }
        }
        Ok(())
    }
    fn addr(&mut self, idx: u32, a: Address, add: bool) -> io::Result<()> {
        let mut msg = vec![libc::AF_INET as u8, a.prefix, 0, 0];
        msg.extend_from_slice(&idx.to_ne_bytes());
        attribute(&mut msg, libc::IFA_LOCAL, &a.ip);
        attribute(&mut msg, libc::IFA_ADDRESS, &a.ip);
        self.change(
            if add {
                libc::RTM_NEWADDR
            } else {
                libc::RTM_DELADDR
            },
            if add { CREATE_EXCLUSIVE } else { 0 },
            &msg,
        )
    }
    fn gateway_host_route(&mut self, idx: u32, address: Address, add: bool) -> io::Result<()> {
        let mut msg = vec![
            libc::AF_INET as u8,
            32,
            0,
            0,
            MAIN,
            if add { 4 } else { 0 },
            libc::RT_SCOPE_LINK,
            1,
            0,
            0,
            0,
            0,
        ];
        attribute(&mut msg, libc::RTA_DST, &address.gateway);
        attribute(&mut msg, libc::RTA_OIF, &idx.to_ne_bytes());
        self.change(
            if add {
                libc::RTM_NEWROUTE
            } else {
                libc::RTM_DELROUTE
            },
            if add { CREATE_EXCLUSIVE } else { 0 },
            &msg,
        )
    }

    fn route(&mut self, idx: u32, a: Address, add: bool) -> io::Result<()> {
        let mut msg = vec![
            libc::AF_INET as u8,
            0,
            0,
            0,
            MAIN,
            if add { 4 } else { 0 },
            0,
            1,
            0,
            0,
            0,
            0,
        ];
        attribute(&mut msg, libc::RTA_OIF, &idx.to_ne_bytes());
        attribute(&mut msg, libc::RTA_GATEWAY, &a.gateway);
        self.change(
            if add {
                libc::RTM_NEWROUTE
            } else {
                libc::RTM_DELROUTE
            },
            if add { CREATE_EXCLUSIVE } else { 0 },
            &msg,
        )
    }
}

pub(super) fn apply(frame: &[u8; 64], completed: &mut u32) -> io::Result<Ipv4Addr> {
    let plan = LinkIdentity::decode(frame)?;
    let idx = unsafe { libc::if_nametoindex(plan.name.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut net = RouteSocket::open()?;
    net.verify(idx, &plan.old_mac, plan.old)?;
    if plan.old_mac != plan.new_mac {
        net.set_mac(idx, &plan.new_mac)?;
    }
    if plan.old != plan.new {
        net.route(idx, plan.old, false)?;
        if plan.old.prefix == 32 {
            net.gateway_host_route(idx, plan.old, false)?;
        }
        if plan.old.ip != plan.new.ip || plan.old.prefix != plan.new.prefix {
            net.addr(idx, plan.old, false)?;
            net.addr(idx, plan.new, true)?;
        }
        if plan.new.prefix == 32 {
            net.gateway_host_route(idx, plan.new, true)?;
        }
        net.route(idx, plan.new, true)?;
    }
    net.reset_neighbors(idx)?;
    net.verify(idx, &plan.new_mac, plan.new)?;
    *completed |= 8 | 16;
    Ok(plan.dns)
}
