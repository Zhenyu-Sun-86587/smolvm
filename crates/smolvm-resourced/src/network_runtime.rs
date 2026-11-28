use crate::activation_catalog::NetworkBinding;
use crate::catalog::{Catalog, Execution};
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::network::topology::{
    self, AttachmentMode, KernelProof, PortPolicy, PrivateRouter, QuarantinedPort,
};
use crate::network::{NamespaceIdentity, PreparedTapPort};
use crate::network_catalog::NetworkReservation;
use crate::network_lease_catalog::{AttachmentDescriptor, TapLease};
use crate::network_memberships::{self, Membership};
use crate::network_peering::Peering;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

pub(crate) struct NetworkRuntime {
    namespaces: PathBuf,
    routers: HashMap<String, PrivateRouter>,
    ports: HashMap<String, QuarantinedPort>,
    packet_wake: crate::packet_wake::Observer,
    peering: Peering,
    membership_filters: HashMap<String, MembershipFilter>,
}

#[derive(Default, Eq, PartialEq)]
struct MembershipFilter {
    internal: Vec<(Ipv4Addr, Ipv4Addr)>,
    peered: Vec<(Ipv4Addr, Ipv4Addr)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    attachment_id: String,
    guest_gateway_ipv4: Option<Ipv4Addr>,
    guest_prefix: Option<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PortId {
    attachment_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledge {
    attachment_id: String,
    lease_id: String,
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dial {
    attachment_id: String,
    lease_id: String,
    expected_revision: i64,
    guest_port: u16,
    transport: Transport,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}

impl NetworkRuntime {
    pub(crate) fn new(namespaces: PathBuf, peering_policy: Option<PathBuf>) -> Self {
        Self {
            namespaces,
            routers: HashMap::new(),
            ports: HashMap::new(),
            packet_wake: Default::default(),
            peering: Peering::new(peering_policy),
            membership_filters: HashMap::new(),
        }
    }

    pub(crate) fn cleanup_namespace_pins(&self, catalog: &Catalog) -> Result<()> {
        topology::cleanup_pins(&self.namespaces, |identity| {
            if self.routers.values().any(|router| {
                NamespaceIdentity::read(router.namespace()).is_ok_and(|value| value == identity)
            }) {
                return Ok(true);
            }
            catalog.router_pin_in_use(identity).map_err(std::io::Error::other)
        })
        .map_err(host_error)
    }

    pub(crate) fn recover_port(
        &self,
        catalog: &Catalog,
        execution: &Execution,
        lease: &TapLease,
        evidence: &KernelProof,
        pidfd: BorrowedFd<'_>,
    ) -> Result<(PrivateRouter, QuarantinedPort)> {
        let reservation = catalog.tap_network_reservation(lease)?;
        let attachment = &lease.attachment;
        let mode = match attachment.mode.as_str() {
            "native"
                if attachment.guest_ipv4 == attachment.private_ipv4
                    && attachment.guest_prefix == 32
                    && attachment.gateway_ipv4 == reservation.gateway_ipv4 =>
            {
                AttachmentMode::Native
            }
            "fixed_internal" => AttachmentMode::FixedInternal {
                guest: attachment.guest_ipv4,
                gateway: attachment.gateway_ipv4,
                prefix: attachment.guest_prefix,
            },
            _ => return Err(unknown_attachment()),
        };
        if attachment.mac != attachment_mac(attachment.private_ipv4) {
            return Err(unknown_attachment());
        }
        let mut router = match self.routers.get(&attachment.route_domain_id) {
            Some(router)
                if NamespaceIdentity::read(router.namespace()).map_err(host_error)?
                    == evidence.router =>
            {
                router.clone()
            }
            Some(_) => return Err(unknown_attachment()),
            None => PrivateRouter::recover(
                &self.namespaces,
                evidence.router,
                reservation.gateway_ipv4,
                catalog.private_network_prefix(&reservation.network_id)?,
            )
            .map_err(host_error)?,
        };
        let tap = PreparedTapPort::recover(execution.pid, pidfd, evidence.port).map_err(host_error)?;
        let port = QuarantinedPort::recover(
            router.clone(),
            tap,
            PortPolicy {
                private_ipv4: attachment.private_ipv4,
                mac: attachment.mac,
                mode,
            },
        );
        if &port.kernel_proof().map_err(host_error)? != evidence {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "published TAP topology or policy has changed",
            ));
        }
        if reservation.dns_name.is_some() {
            let path = catalog
                .db
                .path()
                .ok_or_else(|| Fault::new("E_CATALOG", "private DNS requires the Worker database"))?;
            router
                .ensure_dns(Path::new(path), &reservation.network_id)
                .map_err(host_error)?;
        }
        Ok((router, port))
    }

    pub(crate) fn adopt_recovered_port(
        &mut self,
        catalog: &mut Catalog,
        lease: &TapLease,
        router: PrivateRouter,
        mut port: QuarantinedPort,
    ) -> Result<()> {
        if self.ports.contains_key(&lease.attachment.attachment_id) {
            return Err(unknown_attachment());
        }
        if !self.routers.contains_key(&lease.attachment.route_domain_id) {
            router.apply_membership_filter(&[], &[]).map_err(host_error)?;
        }
        catalog.adopt_published_tap(lease)?;
        port.adopt_published(router.clone());
        self.routers
            .insert(lease.attachment.route_domain_id.clone(), router);
        self.ports.insert(lease.attachment.attachment_id.clone(), port);
        self.reconcile_memberships(catalog)
    }

    fn reconcile_memberships(&mut self, catalog: &Catalog) -> Result<()> {
        let groups = network_memberships::endpoints(&catalog.db)?;
        for (domain, router) in &self.routers {
            let network: String = catalog.db.query_row(
                "SELECT network_id FROM private_networks WHERE route_domain_id=?",
                [domain],
                |row| row.get(0),
            )?;
            let local = groups.get(&network).map(Vec::as_slice).unwrap_or_default();
            let internal = network_memberships::allowed_pairs(local, local);
            let mut peered = Vec::new();
            for remote in self.peering.active_peers(&network) {
                if let Some(endpoints) = groups.get(remote) {
                    peered.extend(network_memberships::allowed_pairs(local, endpoints));
                }
            }
            let filter = MembershipFilter { internal, peered };
            if self.membership_filters.get(domain) != Some(&filter) {
                router.apply_membership_filter(&filter.internal, &filter.peered).map_err(host_error)?;
                self.membership_filters.insert(domain.clone(), filter);
            }
        }
        Ok(())
    }

    pub(crate) fn apply_membership(
        &mut self,
        catalog: &Catalog,
        instance: &str,
        desired: &Membership,
    ) -> Result<()> {
        catalog.ready()?;
        if catalog.check_network_membership(instance, desired)? {
            // A failed update cannot retain the old grants after the new
            // revision becomes durable. Close the router transit gates first.
            let block = self.routers.iter().try_for_each(|(domain, router)| {
                router.apply_membership_filter(&[], &[]).map_err(host_error)?;
                self.membership_filters.insert(domain.clone(), MembershipFilter::default());
                Ok::<_, Fault>(())
            });
            if let Err(error) = block.and_then(|()| catalog.save_network_membership(instance, desired)) {
                let _ = self.reconcile_memberships(catalog);
                return Err(error);
            }
        }
        self.reconcile_memberships(catalog)
    }

    pub(crate) fn packet_rule(&mut self, catalog: &mut Catalog, request: &Request) -> Result<serde_json::Value> {
        self.packet_wake.rule(catalog, request, &self.ports)
    }

    pub(crate) fn poll(&mut self, catalog: &mut Catalog) -> Result<()> {
        self.peering.refresh(catalog, &self.routers, &self.ports);
        self.reconcile_memberships(catalog)?;
        self.packet_wake.poll(catalog, &self.ports)
    }

    pub(crate) fn peering_status(&self, request: &Request) -> Result<serde_json::Value> {
        if request.payload != serde_json::json!({}) {
            return Err(Fault::invalid("private network peering query requires an empty payload"));
        }
        Ok(self.peering.status())
    }

    pub(crate) fn activity(&self,catalog:&Catalog,execution:&Execution)->Result<serde_json::Value> {
        let op=catalog.operation(&execution.last_operation_id)?;
        let plan=crate::managed::plan(catalog,&op)?.ok_or_else(||Fault::new("E_RESOURCE_UNAVAILABLE","no authoritative network inventory"))?;
        if plan.machine.network.is_none(){return Ok(serde_json::json!({"inbound":0,"outbound":0}))}
        let leases=catalog.tap_leases_for_execution(execution)?;
        let [lease]=leases.as_slice() else {return Err(unknown_attachment())};
        if lease.state!="attached" || lease.gate!="open" {return Err(unknown_attachment())}
        let port=self.ports.get(&lease.attachment.attachment_id).ok_or_else(unknown_attachment)?;
        let (incoming,outgoing)=port.activity(lease.attachment.private_ipv4).map_err(host_error)?;
        Ok(serde_json::json!({"inbound":incoming,"outbound":outgoing}))
    }
    pub(crate) fn query(catalog: &Catalog, request: &Request) -> Result<TapLease> {
        let data: PortId = request.payload()?;
        if !valid_id(&data.attachment_id) {
            return Err(Fault::invalid("invalid network attachment ID"));
        }
        let operation = catalog.matching_operation(request)?;
        let (_, _, expected) = request.scope()?;
        let lease = catalog.tap_lease(&data.attachment_id)?;
        if lease.operation_id != operation.operation_id {
            return Err(Fault::new(
                "E_NOT_FOUND",
                "TAP lease not found within the operation",
            ));
        }
        let matches_intent = expected.incarnation_id == operation.expected_incarnation_id
            && expected.execution_epoch == operation.expected_execution_epoch;
        let matches_lease = expected.incarnation_id == lease.incarnation_id
            && Some(expected.execution_epoch) == lease.execution_epoch;
        if !matches_intent && !matches_lease {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "network attachment query has a different expected execution",
            ));
        }
        Ok(lease)
    }

    pub(crate) fn prepare(&mut self, catalog: &Catalog, request: &Request) -> Result<TapLease> {
        catalog.ready()?;
        let data: Prepare = request.payload()?;
        let operation = catalog.active_operation(request)?;
        if !operation.launches_execution() {
            return Err(Fault::invalid(
                "TAP preparation requires the reserving launch operation",
            ));
        }
        let reservation = catalog.scoped_network_reservation(request, &data.attachment_id)?;
        if reservation.state != "reserved" {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "network attachment reservation is unavailable",
            ));
        }
        let mode = match (
            reservation.mode.as_str(),
            data.guest_gateway_ipv4,
            data.guest_prefix,
        ) {
            ("native", None, None) => AttachmentMode::Native,
            ("fixed_internal", Some(gateway), Some(prefix)) => AttachmentMode::FixedInternal {
                guest: reservation.guest_ipv4,
                gateway,
                prefix,
            },
            _ => return Err(Fault::invalid("invalid guest route for attachment mode")),
        };
        if let Some(prior) = catalog.prior_tap_descriptor(&data.attachment_id)? {
            if data
                .guest_gateway_ipv4
                .is_some_and(|gateway| gateway != prior.gateway_ipv4)
                || data
                    .guest_prefix
                    .is_some_and(|prefix| prefix != prior.guest_prefix)
            {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "stable attachment has another guest route",
                ));
            }
        }
        match catalog.tap_lease(&data.attachment_id) {
            Ok(lease) => {
                if !self.ports.contains_key(&data.attachment_id) || lease.state == "unknown" {
                    return Err(Fault::new(
                        "E_FENCE_UNPROVEN",
                        "network attachment requires fencing",
                    ));
                }
                if data
                    .guest_gateway_ipv4
                    .is_some_and(|gateway| gateway != lease.attachment.gateway_ipv4)
                    || data
                        .guest_prefix
                        .is_some_and(|prefix| prefix != lease.attachment.guest_prefix)
                {
                    return Err(Fault::new(
                        "E_IDEMPOTENCY_CONFLICT",
                        "prepared guest route differs",
                    ));
                }
                self.reconcile_memberships(catalog)?;
                return Ok(lease);
            }
            Err(error) if error.code == "E_NOT_FOUND" => {}
            Err(error) => return Err(error),
        }
        let router = match self.routers.entry(reservation.route_domain_id.clone()) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let prefix = catalog.private_network_prefix(&reservation.network_id)?;
                let router =
                    PrivateRouter::new(reservation.gateway_ipv4, prefix).map_err(host_error)?;
                entry.insert(router)
            }
        };
        if reservation.dns_name.is_some() {
            let path = catalog.db.path().ok_or_else(|| {
                Fault::new("E_CATALOG", "private DNS requires the Worker database")
            })?;
            router
                .ensure_dns(std::path::Path::new(path), &reservation.network_id)
                .map_err(host_error)?;
        }
        let mac = attachment_mac(reservation.private_ipv4);
        let mut lease_id = [0; 16];
        getrandom::fill(&mut lease_id)
            .map_err(|_| Fault::new("E_HOST_IO", "cannot allocate lease identity"))?;
        let port = match router.prepare(PortPolicy {
            private_ipv4: reservation.private_ipv4,
            mac,
            mode,
        }) {
            Ok(port) => port,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                return Err(Fault::invalid(error.to_string()));
            }
            Err(error) => {
                catalog.mark_network_reservation_unknown(&data.attachment_id)?;
                return Err(host_error(error));
            }
        };
        let descriptor = descriptor(reservation, mac, &port);
        let lease =
            catalog.record_quarantined_tap(&operation, &hex::encode(lease_id), &descriptor)?;
        self.packet_wake.replaced_port(&data.attachment_id);
        self.ports.insert(data.attachment_id, port);
        self.peering.refresh(catalog, &self.routers, &self.ports);
        self.reconcile_memberships(catalog)?;
        Ok(lease)
    }

    pub(crate) fn acquire(
        &self,
        catalog: &mut Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<(TapLease, OwnedFd)> {
        let operation = catalog.active_operation(request)?;
        if operation.operation_id != execution.last_operation_id || !operation.launches_execution()
        {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "network lease does not belong to this launch",
            ));
        }
        let data: PortId = request.payload()?;
        if !valid_id(&data.attachment_id) {
            return Err(Fault::invalid("invalid network attachment ID"));
        }
        let port = self
            .ports
            .get(&data.attachment_id)
            .ok_or_else(unknown_attachment)?;
        let fd = port.tap().try_clone_to_owned().map_err(host_error)?;
        // Record the durable offer before handing the fd to the socket. An
        // uncertain send leaves the address and original queue pinned.
        let lease = catalog.offer_tap(execution, &data.attachment_id)?;
        if lease.gate != "closed" {
            return Err(unknown_attachment());
        }
        Ok((lease, fd))
    }

    pub(crate) fn acknowledge(
        &self,
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<TapLease> {
        let data: Acknowledge = request.payload()?;
        let operation = catalog.matching_operation(request)?;
        if !self.ports.contains_key(&data.attachment_id)
            || operation.operation_id != execution.last_operation_id
        {
            return Err(unknown_attachment());
        }
        catalog.acknowledge_tap(
            execution,
            &data.attachment_id,
            &data.lease_id,
            data.expected_revision,
        )
    }

    pub(crate) fn target_port(&self, binding: &NetworkBinding) -> Result<&QuarantinedPort> {
        self.ports
            .get(&binding.target.attachment.attachment_id)
            .ok_or_else(unknown_attachment)
    }

    pub(crate) fn publish_initial(
        &self,
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
        verify_process: impl Fn() -> Result<()>,
    ) -> Result<TapLease> {
        let data: Acknowledge = request.payload()?;
        let operation = catalog.matching_operation(request)?;
        if operation.kind != "launch" || operation.operation_id != execution.last_operation_id {
            return Err(Fault::invalid(
                "only a cold execution uses initial network activation",
            ));
        }
        let lease = catalog.tap_lease(&data.attachment_id)?;
        if !lease.matches(execution) || lease.lease_id != data.lease_id {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "network attachment is outside this launch",
            ));
        }
        if lease.revision != data.expected_revision {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "network lease revision changed",
            ));
        }
        if lease.state != "attached" {
            return Err(unknown_attachment());
        }
        if lease.gate == "open" {
            return Ok(lease);
        }
        catalog.ready()?;
        catalog.active_operation(request)?;
        let port = self
            .ports
            .get(&data.attachment_id)
            .ok_or_else(unknown_attachment)?;
        match lease.gate.as_str() {
            "closed" => catalog.record_initial_network_activation(&lease)?,
            "opening" => {}
            _ => return Err(unknown_attachment()),
        }
        let published = port.arm_identity().map_err(host_error).and_then(|()| {
            verify_process()?;
            port.publish_identity().map_err(host_error)?;
            verify_process()?;
            let proof = port.record_kernel_proof(&self.namespaces).map_err(host_error)?;
            catalog.record_network_kernel_proof(&lease, &proof)?;
            catalog.finish_initial_network_activation(&lease, "open")
        });
        if published.is_err() && port.close_identity().is_err() {
            catalog.finish_initial_network_activation(&lease, "unknown")?;
        }
        published?;
        catalog.tap_lease(&data.attachment_id)
    }

    pub(crate) fn arm_target(&self, binding: &NetworkBinding) -> Result<()> {
        self.target_port(binding)?
            .arm_identity()
            .map_err(host_error)
    }

    pub(crate) fn publish_target(&self, catalog: &Catalog, binding: &NetworkBinding) -> Result<()> {
        let lease = catalog.tap_lease(&binding.target.attachment.attachment_id)?;
        if lease.lease_id != binding.target.lease_id
            || lease.revision != binding.target.lease_revision
        {
            return Err(unknown_attachment());
        }
        let port = self.target_port(binding)?;
        port.publish_identity().map_err(host_error)?;
        let proof = port.record_kernel_proof(&self.namespaces).map_err(host_error)?;
        catalog.record_network_kernel_proof(&lease, &proof)
    }

    pub(crate) fn close_target(&self, binding: &NetworkBinding) -> Result<()> {
        self.target_port(binding)?
            .close_identity()
            .map_err(host_error)
    }

    pub(crate) fn dial(
        &self,
        catalog: &Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<(TapLease, &'static str, OwnedFd)> {
        catalog.ready()?;
        let data: Dial = request.payload()?;
        if !valid_id(&data.attachment_id) || data.guest_port == 0 {
            return Err(Fault::invalid(
                "network attachment and nonzero service port are required",
            ));
        }
        let operation = catalog.matching_operation(request)?;
        let lease = catalog.tap_lease(&data.attachment_id)?;
        if operation.operation_id != execution.last_operation_id
            || !lease.matches(execution)
            || lease.lease_id != data.lease_id
        {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "attachment differs from the service execution",
            ));
        }
        if lease.revision != data.expected_revision {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "service attachment revision changed",
            ));
        }
        if lease.state != "attached" || lease.gate != "open" {
            return Err(unknown_attachment());
        }
        let port = self
            .ports
            .get(&data.attachment_id)
            .ok_or_else(unknown_attachment)?;
        let address = std::net::SocketAddrV4::new(lease.attachment.private_ipv4, data.guest_port);
        let (kind, role) = match data.transport {
            Transport::Tcp => (socket2::Type::STREAM, "network_tcp"),
            Transport::Udp => (socket2::Type::DGRAM, "network_udp"),
        };
        let socket = port.dial(address, kind).map_err(host_error)?;
        Ok((lease, role, socket))
    }

    pub(crate) fn fence(&mut self, catalog: &Catalog, request: &Request) -> Result<()> {
        let data: PortId = request.payload()?;
        let reservation = catalog.scoped_network_reservation(request, &data.attachment_id)?;
        let lease = match catalog.tap_lease(&data.attachment_id) {
            Ok(lease) => lease,
            Err(error) if error.code == "E_NOT_FOUND" && reservation.state != "unknown" => {
                return self.cleanup_namespace_pins(catalog)
            }
            Err(error) => return Err(error),
        };
        if lease.operation_id != reservation.operation_id || lease.state == "unknown" {
            return Err(unknown_attachment());
        }
        self.retire_port(catalog, &lease)
    }

    pub(crate) fn fence_execution(
        &mut self,
        catalog: &Catalog,
        execution: &Execution,
        current_boot_id: &str,
    ) -> Result<()> {
        for lease in catalog.tap_leases_for_execution(execution)? {
            if lease.host_boot_id != current_boot_id {
                // The port, TAP and router were kernel objects of the previous boot.
                catalog.retire_fenced_tap(&lease)?;
            } else if lease.state != "unknown" {
                self.retire_port(catalog, &lease)?;
            } else {
                self.retire_absent_port(catalog, &lease)?;
            }
        }
        self.cleanup_namespace_pins(catalog)
    }

    /// Only for an execution whose exit and write fence have been established.
    pub(crate) fn retire_absent_port(&self, catalog: &Catalog, lease: &TapLease) -> Result<()> {
        if let Some(proof) = catalog.network_kernel_proof(lease)? {
            if topology::published_port_absent(
                &self.namespaces,
                proof.router,
                lease.attachment.private_ipv4,
            )
            .map_err(host_error)?
            {
                catalog.retire_fenced_tap(lease)?;
            }
        }
        Ok(())
    }

    fn retire_port(&mut self, catalog: &Catalog, lease: &TapLease) -> Result<()> {
        let attachment_id = &lease.attachment.attachment_id;
        let port = self
            .ports
            .get_mut(attachment_id)
            .ok_or_else(unknown_attachment)?;
        port.fence().map_err(host_error)?;
        catalog.retire_fenced_tap(lease)?;
        self.ports.remove(attachment_id);
        if let Err(error) = self.packet_wake.closed_port(catalog, &self.ports, lease) {
            eprintln!("could not refresh private wake observers after fencing: {error}");
        }
        let domain = &lease.attachment.route_domain_id;
        if self.routers.get(domain).is_some_and(PrivateRouter::idle) {
            self.routers.remove(domain);
            self.membership_filters.remove(domain);
        }
        self.cleanup_namespace_pins(catalog)
    }
}

fn attachment_mac(address: Ipv4Addr) -> [u8; 6] {
    let [a, b, c, d] = address.octets();
    [0x02, 0x53, a, b, c, d]
}

fn descriptor(
    reservation: NetworkReservation,
    mac: [u8; 6],
    port: &QuarantinedPort,
) -> AttachmentDescriptor {
    let (guest_ipv4, guest_prefix, gateway_ipv4) = port.guest_ipv4();
    AttachmentDescriptor {
        schema: "NetworkAttachment/1".to_owned(),
        attachment_id: reservation.attachment_id,
        route_domain_id: reservation.route_domain_id,
        private_ipv4: reservation.private_ipv4,
        guest_ipv4,
        guest_prefix,
        gateway_ipv4,
        device_id: reservation.device_id,
        mac,
        mode: reservation.mode,
    }
}

fn unknown_attachment() -> Fault {
    Fault::new(
        "E_FENCE_UNPROVEN",
        "prepared network attachment ownership cannot be established",
    )
}

fn host_error(error: std::io::Error) -> Fault {
    eprintln!("unable to configure private network attachment: {error}");
    Fault::new("E_HOST_IO", "private network host configuration failed")
}
