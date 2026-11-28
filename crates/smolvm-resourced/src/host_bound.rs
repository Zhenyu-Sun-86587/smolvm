//! Selective DNS routing inside a private Worker router.

use crate::ipc::{Fault, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const ADDRESS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const IO_POLL: Duration = Duration::from_millis(250);
const MAX_STREAMS: usize = 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Apply {
    pub catalog_revision: i64,
    pub machine_revision: i64,
    pub hosts: Vec<String>,
    pub http_port: u16,
    pub https_port: u16,
    pub token: String,
    pub lease_seconds: u64,
}

impl Apply {
    pub(crate) fn validate(&self) -> Result<[u8; 32]> {
        if self.catalog_revision < 1 || self.machine_revision < 1 {
            return Err(Fault::invalid("invalid host-bound delivery revision"));
        }
        if self.hosts.is_empty() {
            return if self.http_port == 0
                && self.https_port == 0
                && self.token.is_empty()
                && self.lease_seconds == 0
            {
                Ok([0; 32])
            } else {
                Err(Fault::invalid(
                    "clearing host-bound delivery must have no relay endpoint",
                ))
            };
        }
        if self.hosts.len() > 32
            || !self.hosts.windows(2).all(|pair| pair[0] < pair[1])
            || !self.hosts.iter().all(|host| {
                crate::network_dns::valid_name(host)
                    && !host.ends_with(".private")
                    && host.parse::<std::net::IpAddr>().is_err()
            })
            || !(1..=900).contains(&self.lease_seconds)
            || self.http_port < 1024
            || self.https_port < 1024
            || self.http_port == self.https_port
        {
            return Err(Fault::invalid(
                "invalid host-bound delivery endpoint or DNS set",
            ));
        }
        let mut token = [0; 32];
        if hex::decode_to_slice(&self.token, &mut token).is_err() || token == [0; 32] {
            return Err(Fault::invalid("invalid host-bound relay authority"));
        }
        Ok(token)
    }
}

struct Route {
    catalog_revision: i64,
    machine_revision: i64,
    hosts: Vec<String>,
    http_port: u16,
    https_port: u16,
    token: [u8; 32],
    revoked: AtomicBool,
    expires: RwLock<Instant>,
}

impl Route {
    fn active(&self) -> bool {
        !self.revoked.load(Ordering::Relaxed)
            && self
                .expires
                .read()
                .is_ok_and(|expires| *expires > Instant::now())
    }
}
#[derive(Clone, Default)]
pub(crate) struct Routes(Arc<RwLock<HashMap<Ipv4Addr, Arc<Route>>>>);

impl Routes {
    pub(crate) fn covers(&self, source: Ipv4Addr, host: &str) -> bool {
        self.route(source).is_some_and(|route| {
            route
                .hosts
                .binary_search_by(|item| item.as_str().cmp(host))
                .is_ok()
        })
    }

    fn route(&self, source: Ipv4Addr) -> Option<Arc<Route>> {
        self.0
            .read()
            .ok()?
            .get(&source)
            .filter(|route| route.active())
            .cloned()
    }

    pub(crate) fn set(&self, source: Ipv4Addr, apply: Apply) -> Result<()> {
        let token = apply.validate()?;
        let mut routes = self
            .0
            .write()
            .map_err(|_| Fault::new("E_HOST_IO", "host-bound routing unavailable"))?;
        let expires = Instant::now() + Duration::from_secs(apply.lease_seconds);
        if let Some(prior) = routes.get(&source) {
            if prior.catalog_revision > apply.catalog_revision
                || prior.machine_revision > apply.machine_revision
            {
                return Err(Fault::new(
                    "E_STALE_REVISION",
                    "host-bound relay policy changed",
                ));
            }

            if prior.catalog_revision == apply.catalog_revision
                && prior.machine_revision == apply.machine_revision
                && prior.hosts == apply.hosts
                && prior.http_port == apply.http_port
                && prior.https_port == apply.https_port
                && prior.token == token
            {
                *prior
                    .expires
                    .write()
                    .map_err(|_| Fault::new("E_HOST_IO", "host-bound lease unavailable"))? =
                    expires;
                return Ok(());
            }
        }
        if let Some(prior) = routes.remove(&source) {
            prior.revoked.store(true, Ordering::Relaxed);
        }
        routes.insert(
            source,
            Arc::new(Route {
                catalog_revision: apply.catalog_revision,
                machine_revision: apply.machine_revision,
                hosts: apply.hosts,
                http_port: apply.http_port,
                https_port: apply.https_port,
                token,
                revoked: AtomicBool::new(false),
                expires: RwLock::new(expires),
            }),
        );
        Ok(())
    }

    pub(crate) fn remove(&self, source: Ipv4Addr) {
        if let Ok(mut routes) = self.0.write() {
            if let Some(prior) = routes.remove(&source) {
                prior.revoked.store(true, Ordering::Relaxed);
            }
        }
    }
}

pub(crate) struct Relay {
    stop: Arc<AtomicBool>,
    listener_threads: Vec<JoinHandle<()>>,
}

impl Relay {
    pub(crate) fn start(namespace: BorrowedFd<'_>, routes: Routes) -> io::Result<Self> {
        let sockets = thread::scope(|threads| {
            threads
                .spawn(move || {
                    // Only the listening sockets live in the private router's namespace.
                    if unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok([
                        TcpListener::bind((ADDRESS, 80))?,
                        TcpListener::bind((ADDRESS, 443))?,
                    ])
                })
                .join()
                .map_err(|_| io::Error::other("host-bound socket setup panicked"))?
        })?;
        for socket in &sockets {
            socket.set_nonblocking(true)?;
        }
        let mut relay = Self {
            stop: Arc::new(AtomicBool::new(false)),
            listener_threads: Vec::new(),
        };
        let active = Arc::new(AtomicUsize::new(0));
        for (socket, tls) in sockets.into_iter().zip([false, true]) {
            let stop = relay.stop.clone();
            let count = active.clone();
            let routes = routes.clone();
            relay.listener_threads.push(
                thread::Builder::new()
                    .name("worker-host-bound-listener".into())
                    .spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            match socket.accept() {
                                Ok((stream, SocketAddr::V4(peer))) => {
                                    let Some(route) = routes.route(*peer.ip()) else {
                                        continue;
                                    };
                                    if count.fetch_add(1, Ordering::Relaxed) >= MAX_STREAMS {
                                        count.fetch_sub(1, Ordering::Relaxed);
                                        continue;
                                    }
                                    let guard = StreamGuard(count.clone());
                                    let stop = stop.clone();
                                    let _ = thread::Builder::new()
                                        .name("worker-host-bound-stream".into())
                                        .spawn(move || {
                                            let _guard = guard;
                                            let _ = bridge(stream, route, tls, stop);
                                        });
                                }
                                Ok(_) => {}
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    thread::sleep(Duration::from_millis(25))
                                }
                                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                                Err(_) => break,
                            }
                        }
                    })?,
            );
        }
        Ok(relay)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.listener_threads.drain(..) {
            let _ = thread.join();
        }
    }
}

struct StreamGuard(Arc<AtomicUsize>);
impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn bridge(guest: TcpStream, route: Arc<Route>, tls: bool, stop: Arc<AtomicBool>) -> io::Result<()> {
    if !route.active() || stop.load(Ordering::Relaxed) {
        return Ok(());
    }
    let port = if tls {
        route.https_port
    } else {
        route.http_port
    };
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut host = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    for stream in [&host, &guest] {
        stream.set_read_timeout(Some(IO_POLL))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    }
    host.write_all(&route.token)?;
    let from_guest = guest.try_clone()?;
    let to_host = host.try_clone()?;
    let done = AtomicBool::new(false);
    thread::scope(|threads| {
        threads.spawn(|| transfer(&from_guest, &to_host, &route, &stop, &done));
        transfer(&host, &guest, &route, &stop, &done);
    });
    Ok(())
}

fn transfer(
    mut src: &TcpStream,
    mut dst: &TcpStream,
    route: &Route,
    stop: &AtomicBool,
    done: &AtomicBool,
) {
    let mut buffer = [0; 16 * 1024];
    while route.active() && !stop.load(Ordering::Relaxed) && !done.load(Ordering::Relaxed) {
        match src.read(&mut buffer) {
            Ok(0) => {
                let _ = dst.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                if dst.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = dst.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_exact_source_scoped_and_expire() {
        let routes = Routes::default();
        let source = Ipv4Addr::new(10, 0, 0, 2);
        let neighbor = Ipv4Addr::new(10, 0, 0, 3);
        let setup = || Apply {
            catalog_revision: 1,
            machine_revision: 1,
            hosts: vec!["approved.example".into()],
            http_port: 14001,
            https_port: 14002,
            token: "42".repeat(32),
            lease_seconds: 900,
        };
        routes.set(source, setup()).unwrap();
        assert!(routes.covers(source, "approved.example"));
        assert!(!routes.covers(source, "alt.approved.example"));
        assert!(!routes.covers(neighbor, "approved.example"));

        let mut stale = setup();
        stale.catalog_revision = 0;
        assert!(routes.set(source, stale).is_err());
        let flow = routes.route(source).unwrap();
        *flow.expires.write().unwrap() = Instant::now();
        assert!(!flow.active());
        assert!(!routes.covers(source, "approved.example"));
        routes.set(source, setup()).unwrap();
        assert!(flow.active());
        routes.remove(source);
        assert!(!flow.active());
        assert!(!routes.covers(source, "approved.example"));
    }
}
