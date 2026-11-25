use crate::catalog::{Catalog, Execution};
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::network::topology::{AttachmentMode, PortPolicy, PrivateRouter, QuarantinedPort};
use crate::network_catalog::NetworkReservation;
use crate::network_lease_catalog::{AttachmentDescriptor, TapLease};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;

#[derive(Default)]
pub(crate) struct NetworkRuntime {
    routers: HashMap<String, PrivateRouter>,
    ports: HashMap<String, QuarantinedPort>,
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

impl NetworkRuntime {
    pub(crate) fn query(catalog: &Catalog, request: &Request) -> Result<TapLease> {
        let data: PortId = request.payload()?;
        let reservation = catalog.scoped_network_reservation(request, &data.attachment_id)?;
        let lease = catalog.tap_lease(&data.attachment_id)?;
        if lease.operation_id != reservation.operation_id {
            return Err(Fault::new(
                "E_NOT_FOUND",
                "TAP lease not found within the operation",
            ));
        }
        Ok(lease)
    }

    pub(crate) fn prepare(&mut self, catalog: &Catalog, request: &Request) -> Result<TapLease> {
        catalog.ready()?;
        let data: Prepare = request.payload()?;
        let operation = catalog.active_operation(request)?;
        if operation.kind != "launch" {
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
        self.ports.insert(data.attachment_id, port);
        Ok(lease)
    }

    pub(crate) fn acquire(
        &self,
        catalog: &mut Catalog,
        request: &Request,
        execution: &Execution,
    ) -> Result<(TapLease, OwnedFd)> {
        let operation = catalog.active_operation(request)?;
        if operation.operation_id != execution.last_operation_id || operation.kind != "launch" {
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

    pub(crate) fn fence(&mut self, catalog: &Catalog, request: &Request) -> Result<()> {
        let data: PortId = request.payload()?;
        let reservation = catalog.scoped_network_reservation(request, &data.attachment_id)?;
        let lease = match catalog.tap_lease(&data.attachment_id) {
            Ok(lease) => lease,
            Err(error) if error.code == "E_NOT_FOUND" && reservation.state != "unknown" => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        if lease.operation_id != reservation.operation_id || lease.state == "unknown" {
            return Err(unknown_attachment());
        }
        let port = self
            .ports
            .get_mut(&data.attachment_id)
            .ok_or_else(unknown_attachment)?;
        port.fence().map_err(host_error)?;
        catalog.retire_fenced_tap(&lease)?;
        self.ports.remove(&data.attachment_id);
        let domain = &lease.attachment.route_domain_id;
        if self.routers.get(domain).is_some_and(PrivateRouter::idle) {
            self.routers.remove(domain);
        }
        Ok(())
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
