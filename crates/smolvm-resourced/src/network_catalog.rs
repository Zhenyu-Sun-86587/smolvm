//! Worker authority for durable private IPv4 reservations.
use crate::catalog::Catalog;
use crate::ipc::{valid_id, Fault, Request, Result};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisterNetwork {
    pub(crate) network_id: String,
    pub(crate) route_domain_id: String,
    pub(crate) cidr: String,
}

pub(crate) struct PeeringNetwork {
    pub(crate) route_domain_id: String,
    pub(crate) cidr: String,
    pub(crate) first: Ipv4Addr,
    pub(crate) last: Ipv4Addr,
}

impl PeeringNetwork {
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        self.overlaps_range(u32::from(other.first) - 2, u32::from(other.last) + 1)
    }

    pub(crate) fn overlaps_range(&self, first: u32, last: u32) -> bool {
        // Compare the entire prefix, including the reserved network, gateway and broadcast.
        u32::from(self.first) - 2 <= last && first <= u32::from(self.last) + 1
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Native,
    FixedInternal,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::FixedInternal => "fixed_internal",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReserveNetwork {
    attachment_id: String,
    network_id: String,
    device_id: String,
    mode: Mode,
    guest_ipv4: Option<Ipv4Addr>,
    preferred_private_ipv4: Option<Ipv4Addr>,
    transfer_id: Option<String>,
    rebind_revision: Option<i64>,
    dns_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkReservationId {
    attachment_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseNetwork {
    attachment_id: String,
    expected_revision: i64,
}

#[derive(Serialize)]
pub(crate) struct NetworkReservation {
    pub(crate) attachment_id: String,
    pub(crate) operation_id: String,
    instance_id: String,
    pub(crate) network_id: String,
    pub(crate) route_domain_id: String,
    pub(crate) device_id: String,
    pub(crate) mode: String,
    pub(crate) gateway_ipv4: Ipv4Addr,
    pub(crate) private_ipv4: Ipv4Addr,
    pub(crate) guest_ipv4: Ipv4Addr,
    pub(crate) state: String,
    revision: i64,
    pub(crate) dns_name: Option<String>,
}

pub(crate) struct Prefix {
    pub(crate) gateway: u32,
    pub(crate) first: u32,
    pub(crate) last: u32,
}

pub(crate) fn parse_prefix(cidr: &str) -> Result<Prefix> {
    let invalid = || {
        Fault::invalid("private network needs a canonical RFC1918 IPv4 CIDR with space for a gateway and guest")
    };
    let (addr, prefix) = cidr.split_once('/').ok_or_else(invalid)?;
    let addr = addr.parse::<Ipv4Addr>().map_err(|_| invalid())?;
    let prefix = prefix.parse::<u32>().map_err(|_| invalid())?;
    if !(1..=30).contains(&prefix) {
        return Err(invalid());
    }
    let network = u32::from(addr);
    let host_bits = u32::MAX >> prefix;
    let broadcast = network | host_bits;
    if network & host_bits != 0 || !addr.is_private() || !Ipv4Addr::from(broadcast).is_private() {
        return Err(invalid());
    }
    if format!("{addr}/{prefix}") != cidr {
        return Err(invalid());
    }
    Ok(Prefix {
        gateway: network + 1,
        first: network + 2,
        last: broadcast - 1,
    })
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch(include_str!("schema_network.sql"))?;
    Ok(())
}

fn scan_reservation(row: &Row<'_>) -> rusqlite::Result<NetworkReservation> {
    Ok(NetworkReservation {
        attachment_id: row.get(0)?,
        operation_id: row.get(1)?,
        instance_id: row.get(2)?,
        network_id: row.get(3)?,
        route_domain_id: row.get(4)?,
        device_id: row.get(5)?,
        mode: row.get(6)?,
        gateway_ipv4: Ipv4Addr::from(row.get::<_, u32>(7)?),
        private_ipv4: Ipv4Addr::from(row.get::<_, u32>(8)?),
        guest_ipv4: Ipv4Addr::from(row.get::<_, u32>(9)?),
        state: row.get(10)?,
        revision: row.get(11)?,
        dns_name: row.get(12)?,
    })
}

fn lookup(db: &Connection, id: &str) -> Result<Option<NetworkReservation>> {
    if !valid_id(id) {
        return Err(Fault::invalid("invalid network attachment ID"));
    }
    Ok(db
        .query_row(
            "SELECT a.attachment_id,a.operation_id,a.instance_id,a.network_id,n.route_domain_id,
                a.device_id,a.mode,n.gateway_ipv4,a.private_ipv4,a.guest_ipv4,a.state,a.revision,dns.name
         FROM network_attachments a JOIN private_networks n USING(network_id)
         LEFT JOIN network_dns_names dns USING(attachment_id)
         WHERE a.attachment_id=?",
            [id],
            scan_reservation,
        )
        .optional()?)
}

fn unallocated_ipv4(db: &Connection, network: &str, first: u32, last: u32) -> Result<u32> {
    let mut statement = db.prepare(
        "SELECT private_ipv4 FROM network_attachments WHERE network_id=?1 AND state<>'released'
         UNION SELECT f.private_ipv4 FROM network_overlay_source_fences f
         JOIN private_networks n USING(route_domain_id) WHERE n.network_id=?1
         ORDER BY private_ipv4",
    )?;
    let mut candidate = first;
    for address in statement.query_map([network], |row| row.get::<_, u32>(0))? {
        let address = address?;
        if address > candidate {
            break;
        }
        if address == candidate {
            candidate += 1;
        }
    }
    if candidate > last {
        return Err(Fault::new(
            "E_RESOURCE_EXHAUSTED",
            "private IPv4 address pool is exhausted",
        ));
    }
    Ok(candidate)
}

impl Catalog {
    pub(crate) fn peering_network(&self, network_id: &str) -> Result<Option<PeeringNetwork>> {
        let definition = self
            .db
            .query_row(
                "SELECT route_domain_id,cidr FROM private_networks WHERE network_id=?",
                [network_id],
                |row| Ok((row.get(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        definition
            .map(|(route_domain_id, cidr)| {
                let prefix = parse_prefix(&cidr)?;
                Ok(PeeringNetwork {
                    route_domain_id,
                    cidr,
                    first: Ipv4Addr::from(prefix.first),
                    last: Ipv4Addr::from(prefix.last),
                })
            })
            .transpose()
    }

    pub(crate) fn tap_network_metadata(
        &self,
        lease: &crate::network_lease_catalog::TapLease,
    ) -> Result<(String, Option<String>)> {
        let reservation = self.tap_network_reservation(lease)?;
        Ok((reservation.network_id, reservation.dns_name))
    }

    pub(crate) fn tap_network_reservation(
        &self,
        lease: &crate::network_lease_catalog::TapLease,
    ) -> Result<NetworkReservation> {
        lookup(&self.db, &lease.attachment.attachment_id)?
            .filter(|entry| {
                entry.operation_id == lease.operation_id
                    && entry.instance_id == lease.instance_id
                    && entry.state == "reserved"
                    && entry.route_domain_id == lease.attachment.route_domain_id
                    && entry.device_id == lease.attachment.device_id
                    && entry.mode == lease.attachment.mode
                    && entry.private_ipv4 == lease.attachment.private_ipv4
                    && entry.guest_ipv4 == lease.attachment.guest_ipv4
            })
            .ok_or_else(|| {
                Fault::new(
                    "E_FENCE_UNPROVEN",
                    "TAP has no corresponding network reservation",
                )
            })
    }

    pub(crate) fn reserve_managed_network(
        &mut self,
        request: &Request,
        attachment_id: &str,
        dns_name: &str,
        network: &crate::managed::Network,
        overlay: &crate::network::overlay::Overlay,
    ) -> Result<NetworkReservation> {
        let prior = lookup(&self.db, attachment_id)?;
        let mut dns_name = dns_name;
        if let Some(before) = &prior {
            let migrated: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM network_transfer_guards WHERE attachment_id=?)",
                [attachment_id], |row| row.get(0),
            )?;
            if migrated {
                dns_name = before.dns_name.as_deref().unwrap_or(dns_name);
            }
        }
        let fixed = network.fixed_route();
        self.reserve_network_with_overlay(
            request,
            &ReserveNetwork {
                attachment_id: attachment_id.into(),
                network_id: network.network_id.clone(),
                device_id: "net0".into(),
                mode: if fixed.is_some() {
                    Mode::FixedInternal
                } else {
                    Mode::Native
                },
                guest_ipv4: fixed.map(|(guest, _, _)| guest),
                preferred_private_ipv4: None,
                transfer_id: None,
                rebind_revision: prior.as_ref().map(|before| before.revision),
                dns_name: Some(dns_name.into()),
            },
            overlay,
        )
    }

    pub(crate) fn private_network_prefix(&self, network_id: &str) -> Result<u8> {
        let cidr = self.db.query_row(
            "SELECT cidr FROM private_networks WHERE network_id=?",
            [network_id],
            |row| row.get::<_, String>(0),
        )?;
        cidr.split_once('/')
            .and_then(|(_, prefix)| prefix.parse().ok())
            .ok_or_else(|| Fault::new("E_CATALOG", "invalid private network CIDR"))
    }

    pub(crate) fn mark_network_reservation_unknown(&self, attachment_id: &str) -> Result<()> {
        self.db.execute(
            "UPDATE network_attachments SET state='unknown',revision=revision+1
             WHERE attachment_id=? AND state='reserved'",
            [attachment_id],
        )?;
        Ok(())
    }

    pub(crate) fn archived_network_target(
        &self,
        id: &str,
        archived: &crate::managed::Network,
    ) -> Result<crate::managed::Network> {
        if !valid_id(id) {
            return Err(Fault::invalid("invalid backup recovery network ID"));
        }
        let (domain, cidr): (String, String) = self
            .db
            .query_row(
                "SELECT route_domain_id,cidr FROM private_networks WHERE network_id=?",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                network_recovery_fault("backup restore needs a registered target network")
            })?;
        let original = parse_prefix(&archived.cidr)?;
        let target = parse_prefix(&cidr)?;
        if domain == archived.route_domain_id
            || (target.gateway.saturating_sub(1) <= original.last.saturating_add(1)
                && original.gateway.saturating_sub(1) <= target.last.saturating_add(1))
        {
            return Err(network_recovery_fault(
                "target network overlaps the original route domain or private address block",
            ));
        }
        Ok(crate::managed::Network {
            network_id: id.into(),
            route_domain_id: domain,
            cidr,
            mode: archived.mode,
        })
    }

    pub(crate) fn register_private_network(&self, data: &RegisterNetwork) -> Result<()> {
        self.ready()?;
        self.ensure_private_network(data)
    }

    pub(crate) fn ensure_private_network(&self, data: &RegisterNetwork) -> Result<()> {
        if !valid_id(&data.network_id) || !valid_id(&data.route_domain_id) {
            return Err(Fault::invalid("invalid network or route domain ID"));
        }
        let address = parse_prefix(&data.cidr)?;
        self.db.execute(
            "INSERT OR IGNORE INTO private_networks VALUES(?,?,?,?,?,?)",
            params![
                data.network_id,
                data.route_domain_id,
                data.cidr,
                address.gateway,
                address.first,
                address.last
            ],
        )?;
        let prior = self
            .db
            .query_row(
                "SELECT route_domain_id,cidr FROM private_networks WHERE network_id=?",
                [&data.network_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if prior != Some((data.route_domain_id.clone(), data.cidr.clone())) {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "network ID or route domain has another private network",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn reserve_network(
        &mut self,
        request: &Request,
        data: &ReserveNetwork,
    ) -> Result<NetworkReservation> {
        self.reserve_network_with_overlay(request, data, &Default::default())
    }

    pub(crate) fn reserve_network_with_overlay(
        &mut self,
        request: &Request,
        data: &ReserveNetwork,
        overlay: &crate::network::overlay::Overlay,
    ) -> Result<NetworkReservation> {
        let allocation = overlay.allocation().filter(|pool| pool.network_id == data.network_id);
        let operation = self.matching_operation(request)?;
        verify_epoch(request, &operation)?;
        if data.preferred_private_ipv4.is_some() != data.transfer_id.is_some() {
            return Err(Fault::invalid("stable address reservation requires a designated transfer target"));
        }
        if let Some(id) = &data.transfer_id {
            if !valid_id(id)
                || (operation.kind != "restore_target"
                    && (operation.kind != "launch"
                        || !crate::machine_migration::cold_target(&self.db, &operation.operation_id, id)?))
            {
                return Err(Fault::invalid("stable address reservation requires a designated transfer target"));
            }
        }
        if !valid_id(&data.attachment_id)
            || !valid_id(&data.network_id)
            || !valid_id(&data.device_id)
            || data.device_id.len() >= 64
            || (data.mode == Mode::Native) != data.guest_ipv4.is_none()
            || data.guest_ipv4.is_some_and(|address| !address.is_private())
            || data
                .dns_name
                .as_ref()
                .is_some_and(|name| !crate::network_dns::valid_name(name))
        {
            return Err(Fault::invalid("invalid network attachment profile"));
        }
        if let Some(prior) = lookup(&self.db, &data.attachment_id)? {
            if let Some(pool) = allocation {
                let address = u32::from(prior.private_ipv4);
                if !(pool.first..=pool.last).contains(&address) {
                    let transferred: bool = self.db.query_row(
                        "SELECT EXISTS(SELECT 1 FROM network_transfer_guards WHERE attachment_id=?)",
                        [&prior.attachment_id], |row| row.get(0),
                    )?;
                    if !transferred {
                        return Err(Fault::new("E_NETWORK_ATTACHMENT_CONFLICT",
                            "existing private address is outside the configured Worker overlay allocation"));
                    }
                }
            }
            if prior.network_id != data.network_id
                || prior.device_id != data.device_id
                || prior.mode != data.mode.as_str()
                || (prior.state != "released" && prior.dns_name != data.dns_name)
                || data.preferred_private_ipv4.is_some_and(|address| address != prior.private_ipv4)
                || data
                    .guest_ipv4
                    .is_some_and(|address| address != prior.guest_ipv4)
            {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "attachment ID already has another intent",
                ));
            }
            if let Some(transfer) = &data.transfer_id {
                if prior.state == "released" && prior.operation_id != operation.operation_id {
                    return self.reclaim_aborted_transfer(request, prior, transfer, data.dns_name.as_deref());
                }
                if !crate::network_transfer::guard_matches(&self.db, &operation.operation_id, &data.attachment_id, transfer)? {
                    return Err(Fault::new("E_IDEMPOTENCY_CONFLICT", "attachment already has another transfer intent"));
                }
            }
            return if prior.operation_id == operation.operation_id {
                Ok(prior)
            } else {
                self.rebind_network(request, prior, data.rebind_revision)
            };
        }
        if data.rebind_revision.is_some() {
            return Err(Fault::new(
                "E_NOT_FOUND",
                "network reservation to rebind does not exist",
            ));
        }
        self.ready()?;
        let operation = self.active_operation(request)?;
        if !operation.launches_execution() && operation.kind != "network_reservation" {
            return Err(Fault::invalid(
                "network reservation requires a launch or network_reservation operation",
            ));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (first, last, domain, cidr) = tx
            .query_row(
                "SELECT first_ipv4,last_ipv4,route_domain_id,cidr FROM private_networks WHERE network_id=?",
                [&data.network_id],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
            )
            .optional()?
            .ok_or_else(|| Fault::new("E_NOT_FOUND", "private network is not registered"))?;
        if allocation.is_some_and(|pool| pool.route_domain_id != domain || pool.cidr != cidr) {
            return Err(Fault::new("E_OVERLAY_UNAVAILABLE", "private network differs from its configured overlay domain"));
        }
        let owned: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_attachments
             WHERE route_id=? AND instance_id=? AND device_id=? AND state<>'released')",
            params![operation.route_id, operation.instance_id, data.device_id],
            |row| row.get(0),
        )?;
        if owned {
            return Err(Fault::new(
                "E_NETWORK_ATTACHMENT_CONFLICT",
                "device already holds a private address",
            ));
        }
        let private = if let Some(address) = data.preferred_private_ipv4 {
            let address = u32::from(address);
            let taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM network_attachments WHERE network_id=? AND private_ipv4=? AND state<>'released')",
                params![data.network_id, address], |row| row.get(0),
            )?;
            if !(first..=last).contains(&address) || taken {
                return Err(Fault::new("E_NETWORK_ATTACHMENT_CONFLICT", "requested private address is outside the target pool or already reserved"));
            }
            address
        } else {
            let (mut first, last) = allocation.map_or((first, last), |pool| (pool.first, pool.last));
            loop {
                let candidate = unallocated_ipv4(&tx, &data.network_id, first, last)?;
                if allocation.is_none() || !overlay.remote_address_reserved(Ipv4Addr::from(candidate)) {
                    break candidate;
                }
                first = candidate + 1;
            }
        };
        let guest = data.guest_ipv4.map(u32::from).unwrap_or(private);
        tx.execute(
            "INSERT INTO network_attachments VALUES(?,?,?,?,?,?,?, ?,?,'reserved',1)",
            params![
                data.attachment_id,
                operation.operation_id,
                operation.route_id,
                operation.instance_id,
                data.network_id,
                data.device_id,
                data.mode.as_str(),
                private,
                guest
            ],
        )?;
        if let Some(transfer) = &data.transfer_id {
            tx.execute(
                "INSERT INTO network_transfer_guards(operation_id,attachment_id,migration_id) VALUES(?,?,?)",
                params![operation.operation_id, data.attachment_id, transfer],
            )?;
        }
        if let Some(name) = &data.dns_name {
            if tx.execute(
                "INSERT OR IGNORE INTO network_dns_names VALUES(?,?,?)",
                params![data.attachment_id, data.network_id, name],
            )? != 1
            {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "another attachment owns this private DNS name",
                ));
            }
        }
        let reservation = lookup(&tx, &data.attachment_id)?
            .ok_or_else(|| Fault::new("E_CATALOG", "network reservation was not stored"))?;
        tx.commit()?;
        Ok(reservation)
    }

    fn reclaim_aborted_transfer(
        &mut self,
        request: &Request,
        prior: NetworkReservation,
        migration: &str,
        dns_name: Option<&str>,
    ) -> Result<NetworkReservation> {
        self.ready()?;
        let operation = self.active_operation(request)?;
        let old = self.operation(&prior.operation_id)?;
        let prior_aborted: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM machine_migrations m
             JOIN network_transfer_guards g USING(migration_id)
             WHERE m.native_operation_id=?1 AND m.side='target' AND m.state='aborted'
               AND g.operation_id=?1 AND g.attachment_id=?2 AND m.decision_json IS NULL)",
            params![old.operation_id,prior.attachment_id], |row|row.get(0),
        )?;
        if !prior_aborted || old.phase != "ABORTED" || !operation.launches_execution()
            || old.route_id != operation.route_id || old.bundle_digest != operation.bundle_digest
            || old.instance_id != operation.instance_id || prior.dns_name.as_deref() != dns_name
        {
            return Err(Fault::new("E_FENCE_UNPROVEN", "previous transfer reservation has no confirmed abort"));
        }
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE network_attachments SET operation_id=?1,state='reserved',revision=revision+1
             WHERE attachment_id=?2 AND state='released' AND revision=?3
               AND NOT EXISTS(SELECT 1 FROM network_tap_leases WHERE attachment_id=?2 AND state<>'retired')
               AND NOT EXISTS(SELECT 1 FROM network_attachments current
                 WHERE current.network_id=?4 AND current.private_ipv4=?5 AND current.state<>'released')",
            params![operation.operation_id, prior.attachment_id, prior.revision,
                prior.network_id, u32::from(prior.private_ipv4)],
        )?;
        if changed != 1 {
            return Err(Fault::new("E_NETWORK_ATTACHMENT_CONFLICT", "stable address is unavailable after the prior aborted transfer"));
        }
        tx.execute(
            "INSERT INTO network_transfer_guards(operation_id,attachment_id,migration_id) VALUES(?,?,?)",
            params![operation.operation_id, prior.attachment_id, migration],
        )?;
        tx.commit()?;
        self.scoped_network_reservation(request, &prior.attachment_id)
    }

    fn rebind_network(
        &self,
        request: &Request,
        prior: NetworkReservation,
        expected_revision: Option<i64>,
    ) -> Result<NetworkReservation> {
        let old_operation = self.operation(&prior.operation_id)?;
        let new_operation = self.matching_operation(request)?;
        if expected_revision.is_none()
            || old_operation.route_id != new_operation.route_id
            || old_operation.instance_id != new_operation.instance_id
            || old_operation.bundle_digest != new_operation.bundle_digest
        {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "attachment ID already has another intent",
            ));
        }
        if expected_revision != Some(prior.revision) {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "network reservation revision changed",
            ));
        }
        self.ready()?;
        let active = self.active_operation(request)?;
        if prior.state != "reserved"
            || old_operation.phase == "NEW"
            || !active.launches_execution()
            || active.expected_incarnation_id.is_some()
        {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "previous network owner has not been fenced",
            ));
        }
        match self.tap_lease(&prior.attachment_id) {
            Ok(_) => {
                return Err(Fault::new(
                    "E_FENCE_UNPROVEN",
                    "previous TAP still owns the reservation",
                ))
            }
            Err(error) if error.code == "E_NOT_FOUND" => (),
            Err(error) => return Err(error),
        }
        if self.db.execute(
            "UPDATE network_attachments SET operation_id=?,revision=revision+1
             WHERE attachment_id=? AND operation_id=? AND revision=? AND state='reserved'",
            params![
                active.operation_id,
                prior.attachment_id,
                prior.operation_id,
                prior.revision
            ],
        )? != 1
        {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "network reservation changed before rebinding",
            ));
        }
        self.scoped_network_reservation(request, &prior.attachment_id)
    }

    pub(crate) fn get_network_reservation(
        &self,
        request: &Request,
        data: &NetworkReservationId,
    ) -> Result<NetworkReservation> {
        self.scoped_network_reservation(request, &data.attachment_id)
    }

    pub(crate) fn scoped_network_reservation(
        &self,
        request: &Request,
        id: &str,
    ) -> Result<NetworkReservation> {
        let operation = self.matching_operation(request)?;
        verify_epoch(request, &operation)?;
        lookup(&self.db, id)?
            .filter(|entry| entry.operation_id == operation.operation_id)
            .ok_or_else(|| {
                Fault::new(
                    "E_NOT_FOUND",
                    "network reservation not found within the operation",
                )
            })
    }

    pub(crate) fn release_network_reservation(
        &self,
        request: &Request,
        data: &ReleaseNetwork,
    ) -> Result<NetworkReservation> {
        let prior = self.scoped_network_reservation(request, &data.attachment_id)?;
        match self.tap_lease(&data.attachment_id) {
            Ok(_) => {
                return Err(Fault::new(
                    "E_FENCE_UNPROVEN",
                    "fence the prepared network lease before releasing its address",
                ))
            }
            Err(error) if error.code == "E_NOT_FOUND" => {}
            Err(error) => return Err(error),
        }
        if prior.state == "released"
            && data.expected_revision.checked_add(1) == Some(prior.revision)
        {
            return Ok(prior);
        }
        if prior.state != "reserved" {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "only an unissued network reservation may be released",
            ));
        }
        if data.expected_revision != prior.revision {
            return Err(Fault::new(
                "E_REVISION_CONFLICT",
                "network attachment revision changed",
            ));
        }
        self.db.execute(
            "UPDATE network_attachments SET state='released',revision=revision+1
            WHERE attachment_id=? AND state='reserved' AND revision=?",
            params![data.attachment_id, prior.revision],
        )?;
        self.scoped_network_reservation(request, &data.attachment_id)
    }
}

pub(crate) fn archived_address_is_valid(cidr: &str, address: Ipv4Addr) -> Result<bool> {
    let prefix = parse_prefix(cidr)?;
    Ok((prefix.first..=prefix.last).contains(&u32::from(address)))
}

pub(crate) fn network_recovery_fault(reason: &'static str) -> Fault {
    Fault::new("E_NETWORK_RECOVERY_UNAVAILABLE", reason)
}

fn verify_epoch(request: &Request, operation: &crate::catalog::Operation) -> Result<()> {
    let (_, _, expected) = request.scope()?;
    if expected.incarnation_id != operation.expected_incarnation_id
        || expected.execution_epoch != operation.expected_execution_epoch
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "reservation request has a different expected execution",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{Expected, PROTOCOL};

    fn operation(catalog: &mut Catalog, id: &str, instance: &str, kind: &str) -> Request {
        let request = Request {
            protocol: PROTOCOL.to_owned(),
            request_id: id.to_owned(),
            operation_id: Some(id.to_owned()),
            request_digest: Some(format!("sha256:{}", "b".repeat(64))),
            route_id: Some("deep".to_owned()),
            bundle_digest: Some(format!("sha256:{}", "a".repeat(64))),
            expected: Some(Expected {
                instance_id: instance.to_owned(),
                incarnation_id: None,
                execution_epoch: 0,
            }),
            method: "ReserveNetworkAttachment".to_owned(),
            fd_table: Vec::new(),
            payload: serde_json::Value::Null,
        };
        catalog.begin(&request, kind).unwrap();
        request
    }

    fn reserve(id: &str, network_id: &str) -> ReserveNetwork {
        ReserveNetwork {
            attachment_id: id.to_owned(),
            network_id: network_id.to_owned(),
            device_id: "net0".to_owned(),
            mode: Mode::Native,
            guest_ipv4: None,
            preferred_private_ipv4: None,
            transfer_id: None,
            rebind_revision: None,
            dns_name: None,
        }
    }

    #[test]
    fn live_tap_recovery_requires_the_original_committed_publication() {
        use crate::catalog::NewExecution;
        use crate::network::{topology::KernelProof, NamespaceIdentity};
        use crate::network_lease_catalog::AttachmentDescriptor;

        for case in ["committed", "migration held", "migration complete", "active", "unknown gate", "legacy schema"] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("catalog.sqlite");
            let mut catalog = Catalog::open(&path, "boot", "original").unwrap();
            let bundle = format!("sha256:{}", "a".repeat(64));
            catalog.register_bundle(&bundle, &"c".repeat(64)).unwrap();
            catalog.register_private_network(&RegisterNetwork {
                network_id: "home".into(),
                route_domain_id: "router-home".into(),
                cidr: "10.20.0.0/29".into(),
            }).unwrap();
            let mut request = operation(&mut catalog, "launch-vm", "vm", "launch");
            let launch = catalog.operation("launch-vm").unwrap();
            let reservation = catalog.reserve_network(&request, &reserve("attachment", "home")).unwrap();
            let descriptor = AttachmentDescriptor {
                schema: "NetworkAttachment/1".into(),
                attachment_id: reservation.attachment_id,
                route_domain_id: reservation.route_domain_id,
                private_ipv4: reservation.private_ipv4,
                guest_ipv4: reservation.guest_ipv4,
                guest_prefix: 32,
                gateway_ipv4: reservation.gateway_ipv4,
                device_id: reservation.device_id,
                mac: [2, 0x53, 10, 20, 0, 2],
                mode: reservation.mode,
            };
            catalog.record_quarantined_tap(&launch, "lease", &descriptor).unwrap();
            let expected = Expected {
                instance_id: "vm".into(),
                incarnation_id: Some("execution".into()),
                execution_epoch: 1,
            };
            let execution = catalog.register_execution(&launch, NewExecution {
                route: "deep", bundle: &bundle, expected: &expected, boot: "boot",
                pid: 123, start: 456, uid: 1000, permit_digest: &"d".repeat(64), kernel_import: None,
            }).unwrap();
            let offered = catalog.offer_tap(&execution, "attachment").unwrap();
            let attached = catalog.acknowledge_tap(&execution, "attachment", "lease", offered.revision).unwrap();
            catalog.record_initial_network_activation(&attached).unwrap();
            let proof = KernelProof {
                router: NamespaceIdentity { device: 4, inode: 101 },
                port: NamespaceIdentity { device: 4, inode: 102 },
                fingerprint: "a".repeat(64),
            };
            catalog.record_network_kernel_proof(&attached, &proof).unwrap();
            catalog.finish_initial_network_activation(&attached, "open").unwrap();
            if case != "active" {
                request.expected = Some(expected);
                catalog.finish(&request, false, 1).unwrap();
            }
            if case == "unknown gate" {
                catalog.db.execute("UPDATE initial_network_activations SET phase='unknown'", []).unwrap();
            }
            if let Some(state) = case.strip_prefix("migration ") {
                catalog.db.execute(
                    "INSERT INTO machine_migrations
                     (migration_id,ticket_digest,ticket_json,side,instance_id,native_operation_id,state)
                     VALUES('move',?,'{}','source','vm','migration-source',?)",
                    params![launch.request_digest,state],
                ).unwrap();
                catalog.db.execute(
                    "INSERT INTO machine_migration_source_taps
                     VALUES('move','lease',?,json_object('attachment_revision',?),?,'closed')",
                    params![attached.revision,attached.revision,serde_json::to_string(&proof).unwrap()],
                ).unwrap();
            }
            if case == "legacy schema" {
                catalog.db.execute_batch(
                    "DROP TABLE kernel_cow_imports; DROP TABLE kernel_mm_anchors; DROP TABLE kernel_statepoint_checkpoints;
                     DROP TABLE verified_block_backings;
                     ALTER TABLE managed_fork_children DROP COLUMN capture_lost;
                     ALTER TABLE managed_fork_batches DROP COLUMN memory_fork_backend;
                     ALTER TABLE managed_fork_batches DROP COLUMN selected_memory_fork_backend;
                     ALTER TABLE managed_fork_batches DROP COLUMN kernel_export_deadline;
                     ALTER TABLE managed_fork_batches DROP COLUMN credential_relay_hold;
                     DROP TABLE product_machine_volumes; DROP TABLE network_kernel_receipts; PRAGMA user_version=27;"
                ).unwrap();
            }
            drop(catalog);

            let mut catalog = Catalog::open(&path, "boot", "replacement").unwrap();
            let execution = catalog.reconcile_execution("execution").unwrap();
            let unknown = catalog.tap_lease("attachment").unwrap();
            assert_eq!((unknown.state.as_str(), unknown.gate.as_str()), ("unknown", "unknown"));
            if matches!(case, "committed" | "migration held") {
                let migration = case == "migration held";
                assert_eq!(catalog.has_migration_source_gate(&unknown).unwrap(), migration);
                assert_eq!(catalog.recoverable_network_proof(&unknown, &execution).unwrap(), proof);
                assert!(catalog.router_pin_in_use(proof.router).unwrap());
                catalog.adopt_published_tap(&unknown).unwrap();
                let recovered = catalog.tap_lease("attachment").unwrap();
                assert_eq!((recovered.state.as_str(), recovered.gate.as_str()),
                    ("attached", if migration { "closed" } else { "open" }));
                if migration {
                    let revisions: (i64, i64) = catalog.db.query_row(
                        "SELECT lease_revision,json_extract(transfer_json,'$.attachment_revision')
                         FROM machine_migration_source_taps WHERE migration_id='move'",
                        [], |row| Ok((row.get(0)?,row.get(1)?)),
                    ).unwrap();
                    assert_eq!(revisions, (recovered.revision, attached.revision));
                }
                assert_eq!(recovered.attachment_digest().unwrap(), attached.attachment_digest().unwrap());
                assert!(recovered.revision > attached.revision);
                assert_eq!(catalog.complete_recovery("replacement").unwrap()["state"], "ready");
                catalog.retire_fenced_tap(&recovered).unwrap();
                assert!(!catalog.router_pin_in_use(proof.router).unwrap());
            } else {
                assert_eq!(catalog.recoverable_network_proof(&unknown, &execution).unwrap_err().code,
                           "E_FENCE_UNPROVEN", "{case}");
                assert_eq!(catalog.adopt_published_tap(&unknown).unwrap_err().code,
                           "E_FENCE_UNPROVEN", "{case}");
                assert_eq!(catalog.complete_recovery("replacement").unwrap_err().code,
                           "E_RECOVERING", "{case}");
                assert_eq!(catalog.tap_lease("attachment").unwrap(), unknown);
            }
        }
    }

    #[test]
    fn private_ipam_is_exact_durable_and_scoped_to_router_domains() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("worker.db");
        let mut catalog = Catalog::open(&path, "boot", "first").unwrap();
        catalog
            .register_bundle(&format!("sha256:{}", "a".repeat(64)), &"c".repeat(64))
            .unwrap();
        for (network, domain) in [("home", "router-home"), ("overlap", "router-overlap")] {
            let config = RegisterNetwork {
                network_id: network.to_owned(),
                route_domain_id: domain.to_owned(),
                cidr: "10.20.0.0/30".to_owned(),
            };
            catalog.register_private_network(&config).unwrap();
            catalog.register_private_network(&config).unwrap();
        }

        let create_a = operation(
            &mut catalog,
            "reserve-a",
            "machine-a",
            "network_reservation",
        );
        let create_b = operation(
            &mut catalog,
            "reserve-b",
            "machine-b",
            "network_reservation",
        );
        let attachment_a = reserve("attachment-a", "home");
        let a = catalog.reserve_network(&create_a, &attachment_a).unwrap();
        assert_eq!(a.private_ipv4, Ipv4Addr::new(10, 20, 0, 2));
        assert_eq!(a.guest_ipv4, a.private_ipv4);
        assert_eq!(
            catalog
                .reserve_network(&create_a, &attachment_a)
                .unwrap()
                .private_ipv4,
            a.private_ipv4
        );
        assert_eq!(
            catalog
                .reserve_network(&create_b, &reserve("attachment-b", "home"))
                .err()
                .unwrap()
                .code,
            "E_RESOURCE_EXHAUSTED"
        );
        assert_eq!(
            catalog
                .reserve_network(&create_b, &attachment_a)
                .err()
                .unwrap()
                .code,
            "E_IDEMPOTENCY_CONFLICT"
        );

        let mut fixed = reserve("attachment-overlap", "overlap");
        fixed.mode = Mode::FixedInternal;
        fixed.guest_ipv4 = Some(Ipv4Addr::new(192, 168, 1, 2));
        let b = catalog.reserve_network(&create_b, &fixed).unwrap();
        assert_eq!(b.private_ipv4, a.private_ipv4);
        assert_ne!(b.route_domain_id, a.route_domain_id);
        assert_eq!(b.guest_ipv4, fixed.guest_ipv4.unwrap());

        let release = ReleaseNetwork {
            attachment_id: b.attachment_id,
            expected_revision: b.revision,
        };
        assert_eq!(
            catalog
                .release_network_reservation(&create_b, &release)
                .unwrap()
                .state,
            "released"
        );
        catalog.finish(&create_a, false, 1).unwrap();
        catalog.finish(&create_b, false, 1).unwrap();
        assert_eq!(
            catalog
                .release_network_reservation(&create_b, &release)
                .unwrap()
                .state,
            "released"
        );
        catalog
            .db
            .execute(
                "UPDATE network_attachments SET state='unknown' WHERE attachment_id='attachment-a'",
                [],
            )
            .unwrap();
        drop(catalog);

        let mut catalog = Catalog::open(&path, "boot", "second").unwrap();
        catalog.complete_recovery("second").unwrap();
        let create_c = operation(
            &mut catalog,
            "reserve-c",
            "machine-c",
            "network_reservation",
        );
        let unknown = catalog
            .get_network_reservation(
                &create_a,
                &NetworkReservationId {
                    attachment_id: a.attachment_id,
                },
            )
            .unwrap();
        assert_eq!(unknown.state, "unknown");
        let release = ReleaseNetwork {
            attachment_id: unknown.attachment_id,
            expected_revision: unknown.revision,
        };
        assert_eq!(
            catalog
                .release_network_reservation(&create_a, &release)
                .err()
                .unwrap()
                .code,
            "E_FENCE_UNPROVEN"
        );
        assert_eq!(
            catalog
                .reserve_network(&create_c, &reserve("other", "home"))
                .err()
                .unwrap()
                .code,
            "E_RESOURCE_EXHAUSTED"
        );
    }

    #[test]
    fn rebind_preserves_the_reserved_address_and_fences_the_predecessor() {
        let temp = tempfile::tempdir().unwrap();
        let mut catalog = Catalog::open(&temp.path().join("worker.db"), "boot", "first").unwrap();
        catalog
            .register_bundle(&format!("sha256:{}", "a".repeat(64)), &"c".repeat(64))
            .unwrap();
        catalog
            .register_private_network(&RegisterNetwork {
                network_id: "stable".to_owned(),
                route_domain_id: "router".to_owned(),
                cidr: "10.20.0.0/30".to_owned(),
            })
            .unwrap();
        let first = operation(
            &mut catalog,
            "original",
            "same-machine",
            "network_reservation",
        );
        let mut intent = reserve("endpoint", "stable");
        intent.dns_name = Some("stable.example.test".to_owned());
        let prior = catalog.reserve_network(&first, &intent).unwrap();
        catalog.finish(&first, false, 1).unwrap();

        let next = operation(&mut catalog, "relaunch", "same-machine", "launch");
        intent.rebind_revision = Some(prior.revision + 1);
        assert_eq!(
            catalog.reserve_network(&next, &intent).err().unwrap().code,
            "E_STALE_REVISION"
        );
        intent.rebind_revision = Some(prior.revision);
        let rebound = catalog.reserve_network(&next, &intent).unwrap();
        assert_eq!(rebound.revision, prior.revision + 1);
        assert_eq!(rebound.private_ipv4, prior.private_ipv4);
        assert_eq!(rebound.dns_name, prior.dns_name);
        assert_eq!(
            catalog.reserve_network(&next, &intent).unwrap().revision,
            rebound.revision
        );
        let id = NetworkReservationId {
            attachment_id: "endpoint".to_owned(),
        };
        assert_eq!(
            catalog
                .get_network_reservation(&first, &id)
                .err()
                .unwrap()
                .code,
            "E_NOT_FOUND"
        );
    }
}
