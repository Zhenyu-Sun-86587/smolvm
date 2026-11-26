//! The Worker owns the lifetime of each point-to-point forwarding namespace.

use super::{
    enter_private_namespace, ip, mask, namespace_path, nft, PrivateRouter, QuarantinedPort,
};
use crate::network::NamespaceIdentity;
use crate::network_catalog::PeeringNetwork;
use std::fs::{self, File};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;
use std::thread;

// Each address and neighbor belongs to a single unbridged veth device.
const PEERING_HOP: &str = "169.254.1.1";
const ROUTER_HOP: &str = "169.254.1.2";
const PEERING_MAC: &str = "02:53:ff:fe:00:01";
const ROUTER_MAC: &str = "02:53:ff:fe:00:02";

pub(crate) struct PeeringLink {
    namespace: File,
    left_router: NamespaceIdentity,
    right_router: NamespaceIdentity,
}

impl PeeringLink {
    pub(crate) fn open(
        left: &PeeringNetwork,
        left_router: &PrivateRouter,
        right: &PeeringNetwork,
        right_router: &PrivateRouter,
    ) -> io::Result<Self> {
        let left_identity = NamespaceIdentity::read(left_router.namespace())?;
        let right_identity = NamespaceIdentity::read(right_router.namespace())?;
        if left_identity == right_identity {
            return Err(io::Error::other(
                "private network routers share a namespace",
            ));
        }
        let namespace = thread::Builder::new()
            .name("prepare-network-peering".to_owned())
            .spawn(|| {
                let namespace = enter_private_namespace()?;
                fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n")?;
                Ok::<_, io::Error>(namespace)
            })?
            .join()
            .map_err(|_| io::Error::other("private network peering preparation panicked"))??;

        let fd = namespace.as_fd();
        // Keep forwarding closed until both sides have their exact routes.
        nft(fd, "add table ip smolvm_peering\n\
                 add chain ip smolvm_peering forwarding { type filter hook forward priority filter; policy drop; }\n")?;
        connect(fd, "left", left_router, left, right)?;
        connect(fd, "right", right_router, right, left)?;
        let left_addresses = nft_range(left.first, left.last);
        let right_addresses = nft_range(right.first, right.last);
        nft(fd, &format!(
            "add rule ip smolvm_peering forwarding iifname \"left\" oifname \"right\" ip saddr {left_addresses} ip daddr {right_addresses} accept\n\
             add rule ip smolvm_peering forwarding iifname \"right\" oifname \"left\" ip saddr {right_addresses} ip daddr {left_addresses} accept\n"
        ))?;
        Ok(Self {
            namespace,
            left_router: left_identity,
            right_router: right_identity,
        })
    }

    pub(crate) fn connects(&self, left: &PrivateRouter, right: &PrivateRouter) -> bool {
        NamespaceIdentity::read(left.namespace()).is_ok_and(|value| value == self.left_router)
            && NamespaceIdentity::read(right.namespace())
                .is_ok_and(|value| value == self.right_router)
    }
}

impl Drop for PeeringLink {
    fn drop(&mut self) {
        // Withdraw forwarding before closing the last namespace FD. The kernel also
        // removes both veth peers and their routes if the Worker exits abruptly.
        if let Err(error) = nft(
            self.namespace.as_fd(),
            "flush chain ip smolvm_peering forwarding\n",
        ) {
            eprintln!("resourced private network peering withdrawal: {error}");
        }
    }
}

impl QuarantinedPort {
    pub(crate) fn conflicts_with_peering(
        &self,
        router: &PrivateRouter,
        peer: &PeeringNetwork,
    ) -> bool {
        if self.guest_prefix == 32
            || !Arc::ptr_eq(&self.router_link.router.namespace, &router.namespace)
        {
            return false;
        }
        // FixedInternal peers need a route outside the interface's own subnet.
        let Ok(mask) = mask(self.guest_prefix) else {
            return true;
        };
        let local = u32::from(self.guest_ipv4) & mask;
        peer.overlaps_range(local, local | !mask)
    }
}

fn connect(
    peering: BorrowedFd<'_>,
    port: &str,
    router: &PrivateRouter,
    local: &PeeringNetwork,
    remote: &PeeringNetwork,
) -> io::Result<()> {
    let mut suffix = [0u8; 5];
    getrandom::fill(&mut suffix)
        .map_err(|_| io::Error::other("cannot allocate peering link name"))?;
    let link = format!("sp{}", hex::encode(suffix));
    let router_fd = router.namespace();
    let router_path = namespace_path(router_fd);
    ip(
        peering,
        &format!(
            "link add {port} type veth peer name {link} netns {router_path}\n\
         link set {port} address {PEERING_MAC}\n\
         link set {port} up\n\
         addr add {PEERING_HOP}/32 dev {port}\n\
         neigh add {ROUTER_HOP} lladdr {ROUTER_MAC} nud permanent dev {port}\n\
         route add {} via {ROUTER_HOP} dev {port} onlink\n",
            local.cidr,
        ),
    )?;
    ip(
        router_fd,
        &format!(
            "link set {link} address {ROUTER_MAC}\n\
         link set {link} up\n\
         addr add {ROUTER_HOP}/32 dev {link}\n\
         neigh add {PEERING_HOP} lladdr {PEERING_MAC} nud permanent dev {link}\n\
         route add {} via {PEERING_HOP} dev {link} onlink\n",
            remote.cidr,
        ),
    )
}

fn nft_range(first: Ipv4Addr, last: Ipv4Addr) -> String {
    if first == last {
        first.to_string()
    } else {
        format!("{first}-{last}")
    }
}
