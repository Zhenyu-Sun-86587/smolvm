//! Linux router and port namespaces for IPv4 Worker attachments.

use super::{enter_private_namespace, prepare_tap_port, PreparedTapPort, TAP_PORT_NAME};
use std::fs::File;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::process::{self, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const HOST_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
pub enum AttachmentMode {
    Native,
    FixedInternal {
        guest: Ipv4Addr,
        gateway: Ipv4Addr,
        prefix: u8,
    },
}

#[derive(Clone, Copy)]
pub struct PortPolicy {
    pub private_ipv4: Ipv4Addr,
    pub mac: [u8; 6],
    pub mode: AttachmentMode,
}

#[derive(Clone)]
pub struct PrivateRouter {
    namespace: Arc<File>,
    gateway: Ipv4Addr,
    mask: u32,
}

pub struct QuarantinedPort {
    router_link: RouterLink,
    tap: PreparedTapPort,
    guest_ipv4: Ipv4Addr,
    gateway_ipv4: Ipv4Addr,
    guest_prefix: u8,
}

struct RouterLink {
    router: PrivateRouter,
    name: String,
    attached: bool,
}

impl RouterLink {
    fn fence(&mut self) -> io::Result<()> {
        if self.attached {
            ip(
                self.router.namespace(),
                &format!("link del {}\n", self.name),
            )?;
            self.attached = false;
        }
        Ok(())
    }
}

impl Drop for RouterLink {
    fn drop(&mut self) {
        if let Err(error) = self.fence() {
            eprintln!("unable to delete private router link: {error}");
        }
    }
}

impl PrivateRouter {
    /// Create a router with loopback and managed ports only.
    pub fn new(gateway: Ipv4Addr, prefix: u8) -> io::Result<Self> {
        let mask = mask(prefix)?;
        if !gateway.is_private() {
            return Err(invalid("router gateway must be private IPv4"));
        }
        let namespace = thread::Builder::new()
            .name("prepare-network-router".to_owned())
            .spawn(|| {
                let namespace = enter_private_namespace()?;
                std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n")?;
                Ok::<_, io::Error>(namespace)
            })?
            .join()
            .map_err(|_| io::Error::other("router preparation thread panicked"))??;
        let router = Self {
            namespace: Arc::new(namespace),
            gateway,
            mask,
        };
        ip(
            router.namespace(),
            &format!("link set lo up\naddr add {gateway}/32 dev lo\n"),
        )?;
        Ok(router)
    }

    pub fn namespace(&self) -> BorrowedFd<'_> {
        self.namespace.as_ref().as_fd()
    }

    pub(crate) fn idle(&self) -> bool {
        Arc::strong_count(&self.namespace) == 1
    }

    /// Connect a TAP through private Linux namespaces. The guest-facing link
    /// stays down and its ingress chain independently drops every packet.
    pub fn prepare(&self, policy: PortPolicy) -> io::Result<QuarantinedPort> {
        let private = u32::from(policy.private_ipv4);
        let gate = u32::from(self.gateway);
        if !policy.private_ipv4.is_private()
            || private == gate
            || private & self.mask != gate & self.mask
            || private & !self.mask == 0
            || private & !self.mask == !self.mask
            || policy.mac == [0; 6]
            || policy.mac[0] & 1 != 0
        {
            return Err(invalid(
                "invalid private address or guest MAC for this router",
            ));
        }
        let (guest_ipv4, gateway_ipv4, guest_prefix) = match policy.mode {
            AttachmentMode::Native => (policy.private_ipv4, self.gateway, 32),
            AttachmentMode::FixedInternal {
                guest,
                gateway,
                prefix,
            } => {
                let guest_mask = mask(prefix)?;
                let guest_subnet = u32::from(guest) & guest_mask;
                let overlap_mask = guest_mask & self.mask;
                if !guest.is_private()
                    || !gateway.is_private()
                    || guest == gateway
                    || guest_subnet != u32::from(gateway) & guest_mask
                    || [guest, gateway].into_iter().any(|ip| {
                        let host = u32::from(ip) & !guest_mask;
                        host == 0 || host == !guest_mask
                    })
                    || guest_subnet & overlap_mask == gate & overlap_mask
                {
                    return Err(invalid(
                        "fixed guest subnet or gateway conflicts with the router",
                    ));
                }
                (guest, gateway, prefix)
            }
        };

        let tap = prepare_tap_port()?;
        let port = tap.namespace();
        let mac = policy.mac.map(|byte| format!("{byte:02x}")).join(":");
        nft(port, &format!(
            "add table netdev tapguard\n\
             add chain netdev tapguard ingress {{ type filter hook ingress device \"{TAP_PORT_NAME}\" priority -300; policy drop; }}\n\
             add chain netdev tapguard identity\n\
             add rule netdev tapguard identity ether saddr {mac} ip saddr {guest_ipv4} counter accept\n\
             add rule netdev tapguard identity ether saddr {mac} arp saddr ether {mac} arp saddr ip {guest_ipv4} counter accept\n\
             add rule netdev tapguard identity counter drop\n"
        ))?;
        let link = format!("p{private:08x}");
        let target = namespace_path(port);
        ip(
            self.namespace(),
            &format!("link add {link} type veth peer name up0 netns {target}\n"),
        )?;
        let router_link = RouterLink {
            router: self.clone(),
            name: link.clone(),
            attached: true,
        };
        ip(
            self.namespace(),
            &format!(
                "link set {link} up\n\
             route add {}/32 dev {link} scope link\n",
                policy.private_ipv4
            ),
        )?;
        match policy.mode {
            AttachmentMode::Native => {
                command(
                    self.namespace(),
                    "sysctl",
                    &["-q", "-w", &format!("net.ipv4.conf.{link}.proxy_arp=1")],
                    None,
                )?;
                ip(
                    port,
                    &format!(
                        "link add br0 type bridge\n\
                     link set br0 up\n\
                     link set {TAP_PORT_NAME} master br0\n\
                     link set up0 master br0\n\
                     link set up0 up\n"
                    ),
                )?;
            }
            AttachmentMode::FixedInternal {
                guest,
                gateway,
                prefix,
            } => {
                command(port, "sysctl", &["-q", "-w", "net.ipv4.ip_forward=1"], None)?;
                ip(
                    port,
                    &format!(
                        "link set lo up\n\
                     link set up0 up\n\
                     addr add {}/32 dev lo\n\
                     route add {}/32 dev up0 scope link\n\
                     route add default via {} dev up0\n\
                     addr add {gateway}/{prefix} dev {TAP_PORT_NAME}\n",
                        policy.private_ipv4, self.gateway, self.gateway
                    ),
                )?;
                nft(port, &format!(
                    "add table ip fixed\n\
                     add chain ip fixed prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}\n\
                     add chain ip fixed postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n\
                     add rule ip fixed prerouting ip daddr {} dnat to {guest}\n\
                     add rule ip fixed postrouting oifname \"up0\" ip saddr {guest} snat to {}\n\
                     add rule ip fixed postrouting iifname \"{TAP_PORT_NAME}\" oifname \"{TAP_PORT_NAME}\" ip daddr {guest} snat to {gateway}\n",
                    policy.private_ipv4, policy.private_ipv4
                ))?;
            }
        }
        Ok(QuarantinedPort {
            router_link,
            tap,
            guest_ipv4,
            gateway_ipv4,
            guest_prefix,
        })
    }
}

impl QuarantinedPort {
    /// Install the exact prepared identity policy while the TAP is still down.
    pub(crate) fn arm_identity(&self) -> io::Result<()> {
        self.close_identity()?;
        nft(
            self.namespace(),
            "flush chain netdev tapguard ingress\nadd rule netdev tapguard ingress jump identity\n",
        )
    }

    /// Publish the link only after the private Guest authority reported release.
    pub(crate) fn publish_identity(&self) -> io::Result<()> {
        ip(self.namespace(), &format!("link set {TAP_PORT_NAME} up\n"))
    }

    pub(crate) fn close_identity(&self) -> io::Result<()> {
        ip(
            self.namespace(),
            &format!("link set {TAP_PORT_NAME} down\n"),
        )
    }

    /// Disconnect the host route before a released address can be reused.
    pub fn fence(&mut self) -> io::Result<()> {
        self.close_identity()?;
        self.router_link.fence()
    }

    pub fn namespace(&self) -> BorrowedFd<'_> {
        self.tap.namespace()
    }

    pub fn tap(&self) -> BorrowedFd<'_> {
        self.tap.tap()
    }

    pub fn guest_ipv4(&self) -> (Ipv4Addr, u8, Ipv4Addr) {
        (self.guest_ipv4, self.guest_prefix, self.gateway_ipv4)
    }
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn mask(prefix: u8) -> io::Result<u32> {
    if !(1..=30).contains(&prefix) {
        return Err(invalid("IPv4 subnet needs a prefix between /1 and /30"));
    }
    Ok(u32::MAX << (32 - prefix))
}

fn namespace_path(namespace: BorrowedFd<'_>) -> String {
    format!("/proc/{}/fd/{}", process::id(), namespace.as_raw_fd())
}

fn ip(namespace: BorrowedFd<'_>, script: &str) -> io::Result<()> {
    command(namespace, "ip", &["-batch", "-"], Some(script))
}

fn nft(namespace: BorrowedFd<'_>, script: &str) -> io::Result<()> {
    command(namespace, "nft", &["-f", "-"], Some(script))
}

fn command(
    namespace: BorrowedFd<'_>,
    program: &str,
    args: &[&str],
    input: Option<&str>,
) -> io::Result<()> {
    let mut child = Command::new("nsenter")
        .arg(format!("--net={}", namespace_path(namespace)))
        .arg("--")
        .arg(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let result = (|| {
        if let Some(data) = input {
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(data.as_bytes())?;
        }
        let deadline = Instant::now() + HOST_COMMAND_TIMEOUT;
        while child.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{program} did not complete"),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "{program} {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspect(namespace: BorrowedFd<'_>, tool: &str, args: &[&str]) -> std::process::Output {
        Command::new("nsenter")
            .arg(format!("--net={}", namespace_path(namespace)))
            .args(["--", tool])
            .args(args)
            .output()
            .unwrap()
    }

    #[test]
    #[ignore = "requires Linux network privileges, iproute2, nft and /dev/net/tun"]
    fn worker_prepare_keeps_both_modes_quarantined_and_scoped() {
        let host = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
        let gateway = "10.77.0.1".parse().unwrap();
        let native = PrivateRouter::new(gateway, 29).unwrap();
        let fixed = PrivateRouter::new(gateway, 29).unwrap();
        let private_ipv4 = "10.77.0.2".parse().unwrap();
        let first = native
            .prepare(PortPolicy {
                private_ipv4,
                mac: [2, 0, 0, 0, 0, 2],
                mode: AttachmentMode::Native,
            })
            .unwrap();
        let second = fixed
            .prepare(PortPolicy {
                private_ipv4,
                mac: [2, 0, 0, 0, 0, 2],
                mode: AttachmentMode::FixedInternal {
                    guest: "192.168.70.2".parse().unwrap(),
                    gateway: "192.168.70.1".parse().unwrap(),
                    prefix: 30,
                },
            })
            .unwrap();
        assert_eq!(first.guest_ipv4(), (private_ipv4, 32, gateway));
        assert_eq!(
            second.guest_ipv4().0,
            "192.168.70.2".parse::<Ipv4Addr>().unwrap()
        );
        for port in [&first, &second] {
            let link = inspect(
                port.namespace(),
                "ip",
                &["-j", "link", "show", "dev", TAP_PORT_NAME],
            );
            assert!(link.status.success());
            let device: serde_json::Value = serde_json::from_slice(&link.stdout).unwrap();
            assert!(!device[0]["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|flag| flag == "UP"));
            let guard = inspect(
                port.namespace(),
                "nft",
                &["list", "table", "netdev", "tapguard"],
            );
            assert!(guard.status.success());
            let guard = String::from_utf8(guard.stdout).unwrap();
            assert!(guard.contains("policy drop"));
            assert!(guard.contains("arp saddr ether"));
            assert!(!guard.contains("jump identity"));

            port.arm_identity().unwrap();
            port.publish_identity().unwrap();
            let link = inspect(
                port.namespace(),
                "ip",
                &["-j", "link", "show", "dev", TAP_PORT_NAME],
            );
            assert!(link.status.success());
            let device: serde_json::Value = serde_json::from_slice(&link.stdout).unwrap();
            assert!(
                device[0]["flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|flag| flag == "UP"),
                "{device}"
            );
            port.close_identity().unwrap();
        }
        assert_eq!(
            std::fs::read_link("/proc/thread-self/ns/net").unwrap(),
            host
        );

        drop(first);
        let address = private_ipv4.to_string();
        assert!(
            !inspect(native.namespace(), "ip", &["route", "get", &address])
                .status
                .success()
        );
        assert!(
            inspect(fixed.namespace(), "ip", &["route", "get", &address])
                .status
                .success()
        );
    }
}
