//! Authoritative names for published IPv4 attachments in one private router.

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use smolvm_network::dns;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const DNS_PORT: u16 = 53;
const RESPONSE_TTL: u32 = 5;

pub(crate) fn valid_name(name: &str) -> bool {
    (3..=253).contains(&name.len())
        && name.contains('.')
        && name.split('.').all(|label| {
            let alnum = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
            label.len() <= 63
                && label.as_bytes().first().is_some_and(alnum)
                && label.as_bytes().last().is_some_and(alnum)
                && label.as_bytes().iter().all(|b| alnum(b) || *b == b'-')
        })
}

pub(crate) struct Resolver {
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Resolver {
    pub(crate) fn start(
        namespace: BorrowedFd<'_>,
        gateway: Ipv4Addr,
        catalog: &Path,
        network_id: &str,
    ) -> io::Result<Self> {
        let db = Connection::open_with_flags(
            catalog,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(io::Error::other)?;
        db.busy_timeout(Duration::from_millis(50))
            .map_err(io::Error::other)?;
        let socket = thread::scope(|threads| {
            threads
                .spawn(move || {
                    // Namespace changes are confined to the socket creation thread.
                    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    UdpSocket::bind((gateway, DNS_PORT))
                })
                .join()
                .map_err(|_| io::Error::other("private DNS socket setup panicked"))?
        })?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let network_id = network_id.to_owned();
        let running = Arc::new(AtomicBool::new(true));
        let active = running.clone();
        let thread = thread::Builder::new()
            .name("worker-private-dns".to_owned())
            .spawn(move || {
                let mut query = [0; 4096];
                while active.load(Ordering::Relaxed) {
                    match socket.recv_from(&mut query) {
                        Ok((n, peer)) => {
                            if let Some(reply) = answer(&db, &network_id, &query[..n]) {
                                let _ = socket.send_to(&reply, peer);
                            }
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
                            ) =>
                        {
                            ()
                        }
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            running,
            thread: Some(thread),
        })
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn answer(db: &Connection, network: &str, packet: &[u8]) -> Option<Vec<u8>> {
    if !dns::is_plain_query(packet) {
        return None;
    }
    let name = dns::normalize_hostname(&dns::question_name(packet)?)?;
    let address = lookup(db, network, &name);
    let mut reply = match address {
        Ok(Some(address)) => dns::addresses_response(packet, &[IpAddr::V4(address)], RESPONSE_TTL),
        Ok(None) => dns::error_response(packet, dns::DNS_RCODE_NXDOMAIN),
        Err(_) => dns::error_response(packet, dns::DNS_RCODE_SERVFAIL),
    };
    reply[2] |= 0x04; // authoritative answer
    reply[3] &= !0x80; // no recursion
    Some(reply)
}

fn lookup(db: &Connection, network: &str, name: &str) -> rusqlite::Result<Option<Ipv4Addr>> {
    let entry = db.query_row(
        "SELECT address.private_ipv4,e.pid,e.pid_start_time FROM network_dns_names dns
         JOIN network_attachments address USING(attachment_id)
         JOIN network_tap_leases tap ON tap.attachment_id=address.attachment_id AND tap.operation_id=address.operation_id
         JOIN executions e ON e.incarnation_id=tap.incarnation_id AND e.execution_epoch=tap.execution_epoch
         JOIN instance_bindings b ON b.route_id=tap.route_id AND b.instance_id=tap.instance_id
              AND b.incarnation_id=tap.incarnation_id AND b.execution_epoch=tap.execution_epoch
         JOIN operations o ON o.operation_id=tap.operation_id
         JOIN worker_state w ON w.singleton=1 AND w.host_boot_id=tap.host_boot_id AND w.broker_session_id=tap.broker_session_id
         WHERE dns.network_id=? AND dns.name=? AND address.state='reserved' AND e.phase='registered'
           AND tap.state='attached' AND w.recovering=0 AND o.phase='COMPLETED'
           AND (EXISTS(SELECT 1 FROM initial_network_activations i WHERE i.lease_id=tap.lease_id AND i.phase='open')
             OR EXISTS(SELECT 1 FROM target_activations a WHERE a.operation_id=tap.operation_id AND a.phase='released'
                AND a.decision='commit' AND a.incarnation_id=tap.incarnation_id AND a.execution_epoch=tap.execution_epoch
                AND json_extract(a.binding_json, '$.network.target.lease_id')=tap.lease_id))",
        [network, name],
        |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i32>(1)?, row.get::<_, i64>(2)?)),
    ).optional()?;
    Ok(entry.and_then(|(address, pid, start)| {
        crate::worker::observe_pid(pid)
            .ok()
            .filter(|(observed, _)| *observed == start)
            .map(|_| Ipv4Addr::from(address))
    }))
}
