use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

pub const PROTOCOL: &str = "WorkerResource/1";
pub const MAX_PACKET: usize = 64 * 1024;
pub const MAX_FDS: usize = 64;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FdEntry {
    pub index: usize,
    pub resource_id: String,
    pub role: String,
}

pub struct Packet {
    pub body: Vec<u8>,
    pub descriptors: Vec<OwnedFd>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub instance_id: String,
    pub incarnation_id: Option<String>,
    pub execution_epoch: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    pub method: String,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub request_digest: Option<String>,
    pub route_id: Option<String>,
    pub bundle_digest: Option<String>,
    pub expected: Option<Expected>,
    #[serde(default)]
    pub fd_table: Vec<FdEntry>,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug)]
pub struct Fault {
    pub code: &'static str,
    pub message: String,
}

impl Fault {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("E_INVALID_REQUEST", message)
    }

    pub fn response(self, id: Option<&str>) -> Value {
        json!({"protocol":PROTOCOL, "request_id":id,
            "error":{"code":self.code, "message":self.message}})
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Fault {}

pub type Result<T> = std::result::Result<T, Fault>;

impl From<rusqlite::Error> for Fault {
    fn from(error: rusqlite::Error) -> Self {
        eprintln!("resourced catalog error: {error}");
        Self::new("E_CATALOG", "worker catalog operation failed")
    }
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && value.bytes().any(|b| b != b'0')
    })
}

impl Request {
    pub fn check(&self) -> Result<()> {
        if self.protocol != PROTOCOL {
            return Err(Fault::new(
                "E_PROTOCOL_UNSUPPORTED",
                "expected WorkerResource/1",
            ));
        }
        for id in [
            Some(self.request_id.as_str()),
            Some(self.method.as_str()),
            self.operation_id.as_deref(),
            self.route_id.as_deref(),
            self.expected.as_ref().map(|e| e.instance_id.as_str()),
            self.expected
                .as_ref()
                .and_then(|e| e.incarnation_id.as_deref()),
        ]
        .into_iter()
        .flatten()
        {
            if !valid_id(id) {
                return Err(Fault::invalid("invalid request identifier"));
            }
        }
        if self
            .request_digest
            .as_deref()
            .is_some_and(|d| !valid_digest(d))
            || self
                .bundle_digest
                .as_deref()
                .is_some_and(|d| !valid_digest(d))
        {
            return Err(Fault::invalid("invalid SHA-256 digest"));
        }
        if self.expected.as_ref().is_some_and(|e| {
            e.execution_epoch < 0 || (e.execution_epoch == 0 && e.incarnation_id.is_some())
        }) {
            return Err(Fault::invalid("invalid execution epoch"));
        }
        if self.fd_table.len() > MAX_FDS
            || self.fd_table.iter().enumerate().any(|(index, item)| {
                item.index != index || !valid_id(&item.resource_id) || !valid_id(&item.role)
            })
        {
            return Err(Fault::invalid("invalid descriptor table"));
        }
        Ok(())
    }

    pub fn payload<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_value(self.payload.clone()).map_err(|e| Fault::invalid(e.to_string()))
    }

    pub fn operation(&self) -> Result<(&str, &str)> {
        self.operation_id
            .as_deref()
            .zip(self.request_digest.as_deref())
            .ok_or_else(|| Fault::invalid("operation_id and request_digest are required"))
    }

    pub fn scope(&self) -> Result<(&str, &str, &Expected)> {
        match (
            self.route_id.as_deref(),
            self.bundle_digest.as_deref(),
            self.expected.as_ref(),
        ) {
            (Some(route), Some(bundle), Some(expected)) => Ok((route, bundle, expected)),
            _ => Err(Fault::invalid(
                "route_id, bundle_digest and expected execution are required",
            )),
        }
    }
}

pub fn new_socket() -> io::Result<Socket> {
    Socket::new(Domain::UNIX, Type::SEQPACKET, None)
}

pub fn connect(path: &Path) -> io::Result<Socket> {
    let socket = new_socket()?;
    socket.connect(&SockAddr::unix(path)?)?;
    set_timeout(&socket)?;
    Ok(socket)
}

pub fn set_timeout(socket: &Socket) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))
}

pub fn peer(socket: &Socket) -> io::Result<libc::ucred> {
    // SO_PEERCRED fills a struct ucred for the authenticated connection peer.
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status == 0 && length as usize == size_of::<libc::ucred>() {
        Ok(credentials)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn receive(socket: &Socket) -> Result<Vec<u8>> {
    let packet = receive_packet(socket)?;
    if !packet.descriptors.is_empty() {
        return Err(Fault::new(
            "E_PROTOCOL_UNSUPPORTED",
            "unexpected response descriptors",
        ));
    }
    Ok(packet.body)
}

pub fn receive_packet(socket: &Socket) -> Result<Packet> {
    let mut packet = vec![0; MAX_PACKET];
    let mut body = libc::iovec {
        iov_base: packet.as_mut_ptr().cast(),
        iov_len: packet.len(),
    };
    // usize storage keeps the ancillary data aligned for cmsghdr and SCM_RIGHTS.
    let space = unsafe { libc::CMSG_SPACE((MAX_FDS * size_of::<libc::c_int>()) as u32) } as usize;
    let mut control = vec![0usize; space.div_ceil(size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut body;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    let count = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count < 0 {
        return Err(Fault::new(
            "E_TRANSPORT",
            io::Error::last_os_error().to_string(),
        ));
    }
    let mut descriptors = Vec::new();
    let mut unknown = false;
    // The kernel constructs aligned control headers. Own every received descriptor before
    // rejecting a packet, including the part of a truncated control message that arrived.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            let message_len = (*header).cmsg_len;
            let minimum = libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && message_len >= minimum
            {
                let count = (message_len - minimum) / size_of::<libc::c_int>();
                let source = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(*source.add(index)));
                }
            } else {
                unknown = true;
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || descriptors.len() > MAX_FDS
    {
        return Err(Fault::new(
            "E_PACKET_TRUNCATED",
            "packet or descriptor list exceeded the transport limit",
        ));
    }
    if unknown {
        return Err(Fault::invalid("unknown ancillary data"));
    }
    if count == 0 {
        return Err(Fault::invalid("empty request packet"));
    }
    packet.truncate(count as usize);
    Ok(Packet {
        body: packet,
        descriptors,
    })
}

pub fn send(socket: &Socket, bytes: &[u8]) -> io::Result<()> {
    send_packet(socket, bytes, &[])
}

pub fn send_packet(socket: &Socket, bytes: &[u8], descriptors: &[OwnedFd]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET || descriptors.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet exceeds the transport limit",
        ));
    }
    let mut body = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut body;
    message.msg_iovlen = 1;
    let space =
        unsafe { libc::CMSG_SPACE((descriptors.len() * size_of::<libc::c_int>()) as u32) } as usize;
    let mut control = vec![0usize; space.div_ceil(size_of::<usize>())];
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space;
        // Aligned, initialized storage has space for this one SCM_RIGHTS header and its fd array.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN((descriptors.len() * size_of::<libc::c_int>()) as u32) as usize;
            let output = libc::CMSG_DATA(header).cast::<libc::c_int>();
            for (index, fd) in descriptors.iter().enumerate() {
                output.add(index).write(fd.as_raw_fd());
            }
        }
    }
    // A disconnect after a durable catalog commit must not terminate the daemon.
    let written = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else if written as usize != bytes.len() {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "incomplete sequenced packet",
        ))
    } else {
        Ok(())
    }
}
