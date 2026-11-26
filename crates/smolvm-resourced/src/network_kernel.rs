//! Persist only the namespace references needed for same-boot TAP recovery.

use super::{run_command, AttachmentMode, PortPolicy, PrivateRouter, QuarantinedPort, RouterLink};
use crate::network::{NamespaceIdentity, PreparedTapPort, TAP_PORT_NAME};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek};
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub(crate) struct KernelProof {
    pub router: NamespaceIdentity,
    pub port: NamespaceIdentity,
    pub fingerprint: String,
}

fn namespace_open(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn namespace_path(directory: &Path, identity: NamespaceIdentity) -> PathBuf {
    directory.join(format!("router-{}-{}", identity.device, identity.inode))
}

fn existing_namespace(directory: &Path, identity: NamespaceIdentity) -> io::Result<File> {
    let file = namespace_open(&namespace_path(directory, identity))?;
    if NamespaceIdentity::read(file.as_fd())? != identity {
        return Err(io::Error::other("router namespace pin has changed"));
    }
    Ok(file)
}

fn save_namespace(directory: &Path, namespace: BorrowedFd<'_>) -> io::Result<NamespaceIdentity> {
    let identity = NamespaceIdentity::read(namespace)?;
    match existing_namespace(directory, identity) {
        Ok(_) => return Ok(identity),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let path = namespace_path(directory, identity);
    let target = CString::new(path.as_os_str().as_bytes())?;
    let source = CString::new(format!("/proc/self/fd/{}", namespace.as_raw_fd()))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        fs::remove_file(&path)?;
        return Err(error);
    }
    existing_namespace(directory, identity)?;
    File::open(directory)?.sync_all()?;
    Ok(identity)
}

fn remove_namespace(directory: &Path, identity: NamespaceIdentity) -> io::Result<()> {
    let path = namespace_path(directory, identity);
    let file = match namespace_open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    match NamespaceIdentity::read(file.as_fd()) {
        Ok(actual) if actual == identity => {
            let target = CString::new(path.as_os_str().as_bytes())?;
            if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(_) => {
            return Err(io::Error::other(
                "unexpected router namespace mounted at an old pin",
            ))
        }
        Err(_) => {
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.nlink() != 1
                || meta.len() != 0
            {
                return Err(io::Error::other(
                    "invalid unmounted router namespace placeholder",
                ));
            }
        }
    }
    fs::remove_file(path)?;
    File::open(directory)?.sync_all()
}

pub(crate) fn cleanup_pins(
    directory: &Path,
    keep: impl Fn(NamespaceIdentity) -> io::Result<bool>,
) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let name = entry?.file_name();
        let name = name.to_string_lossy();
        let Some((device, inode)) = name.strip_prefix("router-").and_then(|v| v.split_once('-'))
        else {
            continue;
        };
        let (Ok(device), Ok(inode)) = (device.parse(), inode.parse()) else {
            continue;
        };
        let identity = NamespaceIdentity { device, inode };
        if namespace_path(directory, identity).file_name()
            == Some(std::ffi::OsStr::new(name.as_ref()))
            && !keep(identity)?
        {
            remove_namespace(directory, identity)?;
        }
    }
    Ok(())
}

pub(crate) fn published_port_absent(
    directory: &Path,
    identity: NamespaceIdentity,
    private: Ipv4Addr,
) -> io::Result<bool> {
    let router = existing_namespace(directory, identity)?;
    let namespace = router.as_fd();
    let peer = format!("p{:08x}", u32::from(private));
    let links = probe_json(namespace, "ip", &["-j", "link", "show"])?;
    let routes = probe_json(
        namespace,
        "ip",
        &["-j", "-4", "route", "show", "table", "all"],
    )?;
    let address = private.to_string();
    let host = format!("{address}/32");
    Ok(!entries(&links)?.iter().any(|link| link["ifname"] == peer)
        && !entries(&routes)?
            .iter()
            .any(|route| route["dev"] == peer || route["dst"] == address || route["dst"] == host))
}

impl PrivateRouter {
    pub(crate) fn recover(
        directory: &Path,
        identity: NamespaceIdentity,
        gateway: Ipv4Addr,
        prefix: u8,
    ) -> io::Result<Self> {
        Ok(Self {
            namespace: Arc::new(existing_namespace(directory, identity)?),
            gateway,
            mask: super::mask(prefix)?,
            dns: None,
        })
    }
}

impl QuarantinedPort {
    pub(crate) fn recover(router: PrivateRouter, tap: PreparedTapPort, policy: PortPolicy) -> Self {
        let (guest_ipv4, gateway_ipv4, guest_prefix) = match policy.mode {
            AttachmentMode::Native => (policy.private_ipv4, router.gateway, 32),
            AttachmentMode::FixedInternal {
                guest,
                gateway,
                prefix,
            } => (guest, gateway, prefix),
        };
        let name = format!("p{:08x}", u32::from(policy.private_ipv4));
        Self {
            router_link: RouterLink {
                router,
                name,
                address: policy.private_ipv4,
                // Until attested, never delete or reconfigure a live borrowed link.
                attached: false,
                routed: Cell::new(false),
            },
            tap,
            guest_ipv4,
            gateway_ipv4,
            guest_prefix,
        }
    }

    pub(crate) fn adopt_published(&mut self, router: PrivateRouter) {
        self.router_link.router = router;
        self.router_link.attached = true;
        self.router_link.routed.set(true);
    }

    pub(crate) fn record_kernel_proof(&self, directory: &Path) -> io::Result<KernelProof> {
        let evidence = self.kernel_proof()?;
        let saved = save_namespace(directory, self.router_link.router.namespace())?;
        if evidence.router != saved {
            return Err(io::Error::other(
                "published router differs from its namespace pin",
            ));
        }
        Ok(evidence)
    }

    pub(crate) fn kernel_proof(&self) -> io::Result<KernelProof> {
        let port_ns = self.namespace();
        let router_ns = self.router_link.router.namespace();
        let name = self.router_link.name.as_str();
        let tap = link(port_ns, TAP_PORT_NAME)?;
        let uplink = link(port_ns, "up0")?;
        let peer = link(router_ns, name)?;
        if tap["kind"] != "tun"
            || peer["kind"] != "veth"
            || uplink["kind"] != "veth"
            || tap["up"] != true
            || uplink["up"] != true
            || peer["up"] != true
            || uplink["ifindex"] != peer["peer_index"]
            || peer["ifindex"] != uplink["peer_index"]
            || uplink["peer_namespace"].as_i64().is_none()
            || peer["peer_namespace"].as_i64().is_none()
        {
            return Err(io::Error::other(
                "published TAP and veth topology cannot be proved",
            ));
        }
        let private = self.router_link.address.to_string();
        let host_route = format!("{private}/32");
        let router_routes = routes(router_ns)?;
        let routed: Vec<_> = entries(&router_routes)?
            .iter()
            .filter(|entry| {
                entry["dev"] == name
                    || entry["dev"] == "lo"
                    || entry["type"] == "blackhole"
                    || entry["dst"] == private
                    || entry["dst"] == host_route
            })
            .collect();
        if !routed.iter().any(|row| {
            (row["dst"] == private || row["dst"] == host_route)
                && row["dev"] == name
                && row["scope"] == "link"
        }) {
            return Err(io::Error::other(
                "published private address has no original router link",
            ));
        }
        let route_rules = |ns| probe_json(ns, "ip", &["-j", "-4", "rule", "show"]);
        let bridge = if self.guest_prefix == 32 {
            link(port_ns, "br0")?
        } else {
            Value::Null
        };
        let mut sysctl = vec![
            read_setting(router_ns, "net.ipv4.ip_forward")?,
            read_setting(router_ns, "net.ipv6.conf.all.disable_ipv6")?,
            read_setting(port_ns, "net.ipv6.conf.all.disable_ipv6")?,
        ];
        if self.guest_prefix == 32 {
            sysctl.push(read_setting(
                router_ns,
                &format!("net.ipv4.conf.{name}.proxy_arp"),
            )?);
        } else {
            sysctl.push(read_setting(port_ns, "net.ipv4.ip_forward")?);
        }
        if sysctl.iter().any(|value| value != "1") {
            return Err(io::Error::other(
                "published network routing settings are inactive",
            ));
        }
        let value = json!([
            tap,
            uplink,
            peer,
            bridge,
            routes(port_ns)?,
            routed,
            address(port_ns, TAP_PORT_NAME)?,
            address(port_ns, "lo")?,
            address(router_ns, "lo")?,
            route_rules(router_ns)?,
            route_rules(port_ns)?,
            firewall(port_ns)?,
            firewall(router_ns)?,
            sysctl,
        ]);
        let bytes = serde_json::to_vec(&value).map_err(io::Error::other)?;
        Ok(KernelProof {
            router: NamespaceIdentity::read(router_ns)?,
            port: NamespaceIdentity::read(port_ns)?,
            fingerprint: format!("{:x}", Sha256::digest(bytes)),
        })
    }
}

fn entries(value: &Value) -> io::Result<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| io::Error::other("invalid kernel network inventory"))
}

fn link(namespace: BorrowedFd<'_>, name: &str) -> io::Result<Value> {
    let raw = probe_json(namespace, "ip", &["-j", "-d", "link", "show", "dev", name])?;
    let [row] = entries(&raw)? else {
        return Err(io::Error::other(
            "kernel returned ambiguous network link information",
        ));
    };
    let flags = entries(&row["flags"])?;
    Ok(
        json!({"ifindex":row["ifindex"],"name":row["ifname"],"kind":row["linkinfo"]["info_kind"],
        "master":row["master"],"mtu":row["mtu"],"mac":row["address"],"up":flags.iter().any(|flag| flag == "UP"),
        "peer_index":row["link_index"],"peer_namespace":row["link_netnsid"]}),
    )
}

fn address(namespace: BorrowedFd<'_>, name: &str) -> io::Result<Value> {
    // A bridged Native port deliberately has no assigned IPv4 address.
    let raw = probe_json(namespace, "ip", &["-j", "address", "show", "dev", name])?;
    let [row] = entries(&raw)? else {
        return Err(io::Error::other(
            "kernel returned ambiguous network address information",
        ));
    };
    Ok(row["addr_info"].clone())
}

fn routes(namespace: BorrowedFd<'_>) -> io::Result<Value> {
    let mut raw = probe_json(
        namespace,
        "ip",
        &["-j", "-4", "route", "show", "table", "all"],
    )?;
    let rows = raw
        .as_array_mut()
        .ok_or_else(|| io::Error::other("invalid kernel route inventory"))?;
    // Carrier may come up when the Guest activates its virtio queue.
    for row in rows {
        if let Some(flags) = row["flags"].as_array_mut() {
            flags.retain(|flag| flag != "linkdown");
        }
    }
    Ok(raw)
}

fn firewall(namespace: BorrowedFd<'_>) -> io::Result<Value> {
    let mut raw = probe_json(namespace, "nft", &["-j", "list", "ruleset"])?;
    let rows = raw["nftables"]
        .as_array_mut()
        .ok_or_else(|| io::Error::other("invalid nftables inventory"))?;
    rows.retain(|row| row.get("metainfo").is_none());
    fn strip_statistics(value: &mut Value) {
        match value {
            Value::Object(object) => {
                object.remove("handle");
                if let Some(Value::Object(counter)) = object.get_mut("counter") {
                    counter.remove("packets");
                    counter.remove("bytes");
                }
                object.values_mut().for_each(strip_statistics);
            }
            Value::Array(items) => items.iter_mut().for_each(strip_statistics),
            _ => {}
        }
    }
    strip_statistics(&mut raw);
    Ok(raw)
}

fn read_setting(namespace: BorrowedFd<'_>, key: &str) -> io::Result<String> {
    String::from_utf8(probe(namespace, "sysctl", &["-n", key])?)
        .map(|value| value.trim().to_owned())
        .map_err(io::Error::other)
}

fn probe_json(namespace: BorrowedFd<'_>, program: &str, args: &[&str]) -> io::Result<Value> {
    serde_json::from_slice(&probe(namespace, program, args)?).map_err(io::Error::other)
}

fn probe(namespace: BorrowedFd<'_>, program: &str, args: &[&str]) -> io::Result<Vec<u8>> {
    const MAXIMUM: u64 = 1 << 20;
    let mut file = tempfile::tempfile()?;
    run_command(
        namespace,
        program,
        args,
        None,
        Stdio::from(file.try_clone()?),
    )?;
    file.rewind()?;
    let mut output = Vec::new();
    file.take(MAXIMUM + 1).read_to_end(&mut output)?;
    if output.len() as u64 > MAXIMUM {
        return Err(io::Error::other(
            "kernel network inventory exceeded its response bound",
        ));
    }
    Ok(output)
}
