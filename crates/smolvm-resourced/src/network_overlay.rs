//! Authenticated IPv4 overlay for one explicitly enabled Worker route domain.

use crate::catalog::Catalog;
use crate::ipc::{valid_id, Fault, Result};
use crate::network::topology::{command, ip, namespace_path, nft, PrivateRouter, QuarantinedPort};
use crate::network::NamespaceIdentity;
use crate::network_catalog::parse_prefix;
use crate::network_memberships::{self, Membership};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEVICE: &str = "smoverlay";
const MAX_LEASE: Duration = Duration::from_secs(15);
const MAX_PEERS: usize = 32;
const MAX_ROUTES: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    version: u32,
    worker_id: String,
    worker_namespace: PathBuf,
    network_id: String,
    route_domain_id: String,
    cidr: String,
    allocation_cidr: String,
    listen_port: u16,
    private_key_file: PathBuf,
    peers: Vec<Peer>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    worker_id: String,
    public_key: String,
    endpoint: SocketAddr,
}

struct Config {
    settings: Settings,
    namespace: File,
    private_key: String,
    allocation: Allocation,
    first: u32,
    last: u32,
}

pub(crate) struct Allocation {
    pub(crate) network_id: String,
    pub(crate) route_domain_id: String,
    pub(crate) cidr: String,
    pub(crate) first: u32,
    pub(crate) last: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Route {
    pub(crate) machine_id: String,
    pub(crate) worker_id: String,
    owner_epoch: i64,
    pub(crate) instance_id: String,
    pub(crate) incarnation_id: String,
    pub(crate) execution_epoch: i64,
    pub(crate) attachment_id: String,
    pub(crate) attachment_revision: i64,
    policy_revision: i64,
    networks: Vec<String>,
    pub(crate) private_ipv4: Ipv4Addr,
    dns_name: String,
}

impl Route {
    fn fingerprint(&self) -> u64 {
        let mut hash = DefaultHasher::new();
        self.hash(&mut hash);
        hash.finish()
    }

    fn membership(&self) -> Membership {
        Membership {
            policy_revision: self.policy_revision,
            networks: self.networks.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Apply {
    route_domain_id: String,
    revision: i64,
    lease_seconds: u64,
    expires_at_unix_ms: u64,
    routes: Vec<Route>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Query {
    route_domain_id: String,
}

struct Snapshot {
    revision: i64,
    expires_at_unix_ms: u64,
    deadline: Instant,
    routes: Vec<Route>,
}

#[derive(Clone, Default)]
pub(crate) struct DnsView(Arc<RwLock<Option<DnsEntries>>>);

struct DnsEntries {
    deadline: Instant,
    answers: BTreeMap<(Ipv4Addr, String), Ipv4Addr>,
}

impl DnsView {
    pub(crate) fn lookup(&self, source: Ipv4Addr, name: &str) -> Option<Ipv4Addr> {
        let entries = self.0.read().ok()?;
        let view = entries
            .as_ref()
            .filter(|view| Instant::now() < view.deadline)?;
        view.answers.get(&(source, name.to_owned())).copied()
    }

    fn replace(&self, entries: Option<DnsEntries>) {
        if let Ok(mut view) = self.0.write() {
            *view = entries;
        }
    }
}

type Pair = (Ipv4Addr, Ipv4Addr);
type Generations = (u64, u64);

#[derive(Clone, Copy)]
struct Grant {
    generations: Generations,
    mark: u32,
}

struct Link {
    router: File,
    remote: Vec<(String, Ipv4Addr)>,
    granted: BTreeMap<Pair, Grant>,
    next_mark: u32,
    deadline: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct Overlay {
    config: Option<Config>,
    snapshot: Option<Snapshot>,
    reconciled: bool,
    link: Option<Link>,
    dns: DnsView,
}

impl Overlay {
    pub(crate) fn new(path: Option<&Path>) -> io::Result<Self> {
        Ok(Self {
            config: path.map(Config::read).transpose()?,
            ..Self::default()
        })
    }

    pub(crate) fn configure_catalog(&self, catalog: &Catalog) -> Result<()> {
        let Some(pool) = self.allocation() else {
            return Ok(());
        };
        catalog.ensure_private_network(&crate::network_catalog::RegisterNetwork {
            network_id: pool.network_id.clone(),
            route_domain_id: pool.route_domain_id.clone(),
            cidr: pool.cidr.clone(),
        })?;
        let conflict: bool = catalog.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_attachments a WHERE a.network_id=?1
             AND a.state<>'released' AND a.private_ipv4 NOT BETWEEN ?2 AND ?3
             AND NOT EXISTS(SELECT 1 FROM network_transfer_guards g WHERE g.attachment_id=a.attachment_id))",
            rusqlite::params![pool.network_id, pool.first, pool.last],
            |row| row.get(0),
        )?;
        if conflict {
            return Err(Fault::new("E_NETWORK_ATTACHMENT_CONFLICT",
                "existing private reservation conflicts with the configured Worker overlay allocation"));
        }
        Ok(())
    }

    pub(crate) fn allocation(&self) -> Option<&Allocation> {
        self.config.as_ref().map(|config| &config.allocation)
    }

    pub(crate) fn dns_view(&self, domain: &str) -> DnsView {
        if self.configured_domain(domain) {
            self.dns.clone()
        } else {
            DnsView::default()
        }
    }

    pub(crate) fn configured_domain(&self, domain: &str) -> bool {
        self.config
            .as_ref()
            .is_some_and(|config| config.settings.route_domain_id == domain)
    }

    pub(crate) fn has_peer(&self, domain: &str, local: &str, peer: &str) -> bool {
        self.config.as_ref().is_some_and(|config| {
            config.settings.route_domain_id == domain
                && config.settings.worker_id == local
                && config
                    .settings
                    .peers
                    .iter()
                    .any(|known| known.worker_id == peer)
        })
    }

    pub(crate) fn status(&self, catalog: &Catalog, query: Query) -> Result<Value> {
        if !valid_id(&query.route_domain_id) {
            return Err(Fault::invalid("invalid overlay route domain ID"));
        }
        let Some(config) = self
            .config
            .as_ref()
            .filter(|config| config.settings.route_domain_id == query.route_domain_id)
        else {
            return Ok(
                json!({"configured":false, "ready":false, "route_domain_id":query.route_domain_id}),
            );
        };
        let settings = &config.settings;
        let network = catalog.peering_network(&settings.network_id)?;
        let ready = catalog.ready().is_ok()
            && network.is_some_and(|network| {
                network.route_domain_id == settings.route_domain_id && network.cidr == settings.cidr
            });
        Ok(json!({
            "configured": true,
            "ready": ready,
            "worker_id": settings.worker_id,
            "network_id": settings.network_id,
            "route_domain_id": settings.route_domain_id,
            "cidr": settings.cidr,
            "allocation_cidr": settings.allocation_cidr,
            "peer_worker_ids": settings.peers.iter().map(|peer| &peer.worker_id).collect::<Vec<_>>(),
            "revision": self.snapshot.as_ref().filter(|snapshot| self.reconciled && Instant::now() < snapshot.deadline).map_or(0, |snapshot| snapshot.revision),
            "accepted_revision": accepted_revision(catalog, &settings.route_domain_id)?.map_or(0, |(revision, _)| revision),
        }))
    }

    pub(crate) fn install(&mut self, catalog: &Catalog, mut input: Apply) -> Result<Value> {
        let config = self
            .config
            .as_ref()
            .filter(|config| config.settings.route_domain_id == input.route_domain_id)
            .ok_or_else(|| {
                Fault::new(
                    "E_OVERLAY_UNAVAILABLE",
                    "Worker overlay domain is not configured",
                )
            })?;
        let received = Instant::now();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Fault::new("E_HOST_IO", "Worker wall clock is invalid"))?;
        let expiry = Duration::from_millis(input.expires_at_unix_ms);
        let lease = Duration::from_secs(input.lease_seconds);
        let remaining = expiry
            .checked_sub(now)
            .filter(|value| !value.is_zero() && *value <= lease + Duration::from_millis(250));
        if input.revision < 1
            || lease.is_zero()
            || lease > MAX_LEASE
            || remaining.is_none()
            || input.routes.len() > MAX_ROUTES
        {
            return Err(Fault::invalid(
                "invalid overlay route revision, lease, or size",
            ));
        }
        config.validate_routes(&input.routes)?;
        input
            .routes
            .sort_unstable_by_key(|route| route.private_ipv4);
        if let Some(prior) = &self.snapshot {
            if input.revision < prior.revision
                || (input.revision == prior.revision
                    && (input.routes != prior.routes
                        || input.expires_at_unix_ms != prior.expires_at_unix_ms))
            {
                return Err(Fault::new(
                    "E_STALE_REVISION",
                    "overlay route revision changed",
                ));
            }
        }
        let encoded = serde_json::to_vec(&(
            &input.route_domain_id,
            input.revision,
            input.lease_seconds,
            input.expires_at_unix_ms,
            &input.routes,
        ))
        .map_err(|_| Fault::invalid("cannot encode Worker overlay routes"))?;
        let digest = hex::encode(Sha256::digest(encoded));
        match accepted_revision(catalog, &input.route_domain_id)? {
            Some((revision, known))
                if revision == input.revision
                    && known == digest
                    && self
                        .snapshot
                        .as_ref()
                        .is_some_and(|prior| prior.revision == revision) => {}
            Some((revision, _)) if revision >= input.revision => {
                return Err(Fault::new(
                    "E_STALE_REVISION",
                    "overlay needs a newer route revision",
                ));
            }
            _ => {
                catalog.db.execute(
                    "INSERT INTO network_overlay_revisions(route_domain_id,revision,digest)
                     VALUES(?1,?2,?3) ON CONFLICT(route_domain_id)
                     DO UPDATE SET revision=excluded.revision,digest=excluded.digest",
                    params![input.route_domain_id, input.revision, digest],
                )?;
            }
        }
        let deadline = received + remaining.expect("checked lease").min(lease);
        self.reconciled = false;
        self.snapshot = Some(Snapshot {
            revision: input.revision,
            expires_at_unix_ms: input.expires_at_unix_ms,
            deadline,
            routes: input.routes,
        });
        Ok(json!({"route_domain_id":input.route_domain_id,"revision":input.revision}))
    }

    pub(crate) fn mark_reconciled(&mut self, applied: bool) {
        self.reconciled = applied;
    }

    pub(crate) fn permits_source_fence(
        &self,
        transfer: &crate::network_transfer::Transfer,
        execution: &crate::catalog::Execution,
    ) -> bool {
        self.snapshot
            .as_ref()
            .filter(|snapshot| Instant::now() < snapshot.deadline)
            .is_none_or(|snapshot| {
                snapshot
                    .routes
                    .iter()
                    .filter(|route| {
                        route.machine_id == transfer.machine_id
                            || route.private_ipv4 == transfer.private_ipv4
                    })
                    .all(|route| {
                        route.machine_id == transfer.machine_id
                            && route.worker_id == transfer.source_worker_id
                            && route.owner_epoch == transfer.expected_owner_epoch
                            && route.instance_id == execution.instance_id
                            && route.incarnation_id == execution.incarnation_id
                            && route.execution_epoch == execution.execution_epoch
                            && route.attachment_id == transfer.attachment_id
                            && route.attachment_revision == transfer.attachment_revision
                            && route.private_ipv4 == transfer.private_ipv4
                            && route.policy_revision == transfer.policy_revision
                    })
            })
    }

    pub(crate) fn withdrawn(&self, machine: &str, address: Ipv4Addr) -> bool {
        self.reconciled
            && self.snapshot.as_ref().is_some_and(|snapshot| {
                Instant::now() < snapshot.deadline
                    && !snapshot
                        .routes
                        .iter()
                        .any(|route| route.machine_id == machine || route.private_ipv4 == address)
            })
    }

    pub(crate) fn remote_address_reserved(&self, address: Ipv4Addr) -> bool {
        self.config
            .as_ref()
            .zip(self.snapshot.as_ref())
            .is_some_and(|(config, snapshot)| {
                snapshot.routes.iter().any(|route| {
                    route.worker_id != config.settings.worker_id && route.private_ipv4 == address
                })
            })
    }

    pub(crate) fn revoke_local(&mut self, instance: &str) -> Result<()> {
        let Some(snapshot) = &self.snapshot else {
            return Ok(());
        };
        let Some(config) = &self.config else {
            return Ok(());
        };
        let addresses: BTreeSet<_> = snapshot
            .routes
            .iter()
            .filter(|route| {
                route.worker_id == config.settings.worker_id && route.instance_id == instance
            })
            .map(|route| route.private_ipv4)
            .collect();
        if addresses.is_empty() {
            return Ok(());
        }
        self.dns.replace(None);
        if let Some(link) = &mut self.link {
            link.granted
                .retain(|(local, _), _| !addresses.contains(local));
            let remaining = link.deadline.map_or(Duration::ZERO, |deadline| {
                deadline.saturating_duration_since(Instant::now())
            });
            if let Err(error) = install_filter(link.router.as_fd(), &link.granted, remaining) {
                self.link = None;
                return Err(host_fault(error));
            }
        }
        Ok(())
    }

    pub(crate) fn revoke(&mut self) -> Result<()> {
        self.dns.replace(None);
        if let Some(link) = &mut self.link {
            if let Err(error) = link.revoke() {
                self.link = None;
                return Err(host_fault(error));
            }
        }
        Ok(())
    }

    pub(crate) fn remove_link(&mut self) {
        self.dns.replace(None);
        self.link = None;
    }

    pub(crate) fn reconcile(
        &mut self,
        catalog: &Catalog,
        routers: &HashMap<String, PrivateRouter>,
        ports: &HashMap<String, QuarantinedPort>,
    ) -> Result<()> {
        let Some(config) = &self.config else {
            return Ok(());
        };
        let Some(router) = routers.get(&config.settings.route_domain_id) else {
            self.remove_link();
            return Ok(());
        };
        let known = catalog.peering_network(&config.settings.network_id)?;
        if catalog.ready().is_err()
            || !known.is_some_and(|known| {
                known.route_domain_id == config.settings.route_domain_id
                    && known.cidr == config.settings.cidr
            })
        {
            return self.revoke();
        }
        let Some(snapshot) = self
            .snapshot
            .as_ref()
            .filter(|snapshot| Instant::now() < snapshot.deadline)
        else {
            return self.revoke();
        };
        let mut local = Vec::new();
        let mut remote = Vec::new();
        for route in &snapshot.routes {
            if route.worker_id == config.settings.worker_id {
                if ports.contains_key(&route.attachment_id)
                    && route_is_published(catalog, &config.settings.route_domain_id, route)?
                {
                    local.push((route, route.membership(), route.fingerprint()));
                }
            } else {
                remote.push((route, route.membership(), route.fingerprint()));
            }
        }
        let remote_addresses = remote
            .iter()
            .map(|(route, _, _)| (route.worker_id.clone(), route.private_ipv4))
            .collect();
        let mut pairs = Vec::new();
        let mut answers = BTreeMap::new();
        for (source, source_membership, source_generation) in &local {
            for (target, target_membership, target_generation) in &remote {
                if source_membership.overlaps(target_membership) {
                    pairs.push((
                        (source.private_ipv4, target.private_ipv4),
                        (*source_generation, *target_generation),
                    ));
                    answers.insert(
                        (source.private_ipv4, target.dns_name.clone()),
                        target.private_ipv4,
                    );
                }
            }
        }
        if local.is_empty() {
            // A snapshot may arrive before any local Guest becomes eligible.
            return self.revoke();
        }
        let result = (|| {
            let link = match &mut self.link {
                Some(link) => link,
                empty => empty.insert(Link::open(config, router)?),
            };
            link.apply(config, remote_addresses, pairs, snapshot.deadline)
        })();
        if let Err(error) = result {
            self.remove_link();
            return Err(host_fault(error));
        }
        self.dns.replace(Some(DnsEntries {
            deadline: snapshot.deadline,
            answers,
        }));
        Ok(())
    }
}

fn accepted_revision(catalog: &Catalog, domain: &str) -> Result<Option<(i64, String)>> {
    Ok(catalog
        .db
        .query_row(
            "SELECT revision,digest FROM network_overlay_revisions WHERE route_domain_id=?",
            [domain],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

fn route_is_published(catalog: &Catalog, domain: &str, route: &Route) -> Result<bool> {
    let lease = match catalog.tap_lease(&route.attachment_id) {
        Ok(lease) => lease,
        Err(error) if error.code == "E_NOT_FOUND" => return Ok(false),
        Err(error) => return Err(error),
    };
    if lease.state != "attached"
        || lease.gate != "open"
        || lease.revision != route.attachment_revision
        || lease.route_id != "deep"
        || lease.instance_id != route.instance_id
        || lease.incarnation_id.as_deref() != Some(route.incarnation_id.as_str())
        || lease.execution_epoch != Some(route.execution_epoch)
        || lease.attachment.mode != "native"
        || lease.attachment.route_domain_id != domain
        || lease.attachment.private_ipv4 != route.private_ipv4
    {
        return Ok(false);
    }
    let reservation = catalog.tap_network_reservation(&lease)?;
    if reservation.dns_name.as_deref() != Some(route.dns_name.as_str())
        || network_memberships::lookup(&catalog.db, &route.instance_id)? != route.membership()
    {
        return Ok(false);
    }
    let current: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM instance_bindings b
          JOIN operations o ON o.operation_id=?4
          JOIN network_tap_leases t ON t.lease_id=?5
          LEFT JOIN network_kernel_receipts k USING(lease_id)
          JOIN worker_state w ON w.singleton=1 AND w.host_boot_id=t.host_boot_id
            AND w.broker_session_id=coalesce(k.adopted_session_id,t.broker_session_id)
          WHERE b.route_id='deep' AND b.instance_id=?1 AND b.incarnation_id=?2
            AND b.execution_epoch=?3 AND o.phase='COMPLETED' AND w.recovering=0)",
        params![
            route.instance_id,
            route.incarnation_id,
            route.execution_epoch,
            lease.operation_id,
            lease.lease_id
        ],
        |row| row.get(0),
    )?;
    let execution = catalog.execution(&route.incarnation_id)?;
    Ok(current
        && lease.matches(&execution)
        && execution.phase == "registered"
        && crate::worker::observe_pid(execution.pid)
            .is_ok_and(|(start, _)| start == execution.pid_start_time))
}

impl Config {
    fn read(path: &Path) -> io::Result<Self> {
        let mut settings: Settings = serde_json::from_str(&protected_text(path, 32 * 1024, 0o022)?)
            .map_err(|_| invalid("invalid Worker overlay configuration"))?;
        if settings.version != 1
            || !valid_id(&settings.worker_id)
            || !valid_id(&settings.network_id)
            || !valid_id(&settings.route_domain_id)
            || settings.listen_port == 0
            || settings.peers.is_empty()
            || settings.peers.len() > MAX_PEERS
        {
            return Err(invalid("invalid Worker overlay configuration"));
        }
        let domain = parse_prefix(&settings.cidr).map_err(|error| invalid(error.message))?;
        let slice =
            parse_prefix(&settings.allocation_cidr).map_err(|error| invalid(error.message))?;
        if settings.cidr == settings.allocation_cidr
            || slice.first < domain.first
            || slice.last > domain.last
        {
            return Err(invalid(
                "Worker overlay allocation must be a strict subnet of the route domain",
            ));
        }
        let allocation = Allocation {
            network_id: settings.network_id.clone(),
            route_domain_id: settings.route_domain_id.clone(),
            cidr: settings.cidr.clone(),
            first: slice.first,
            last: slice.last,
        };
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for peer in &settings.peers {
            if !valid_id(&peer.worker_id)
                || peer.worker_id == settings.worker_id
                || !valid_key(&peer.public_key)
                || peer.endpoint.port() == 0
                || peer.endpoint.ip().is_unspecified()
                || peer.endpoint.ip().is_multicast()
                || peer.endpoint.ip().is_loopback()
                || !ids.insert(&peer.worker_id)
                || !keys.insert(&peer.public_key)
                || !endpoints.insert(peer.endpoint)
            {
                return Err(invalid("invalid or duplicate Worker overlay peer"));
            }
        }
        settings
            .peers
            .sort_unstable_by(|a, b| a.worker_id.cmp(&b.worker_id));
        if !settings.worker_namespace.is_absolute() || !settings.private_key_file.is_absolute() {
            return Err(invalid(
                "Worker overlay requires absolute namespace and private key paths",
            ));
        }
        let namespace = File::open(&settings.worker_namespace)?;
        let configured = NamespaceIdentity::read(namespace.as_fd())?;
        let current = File::open("/proc/thread-self/ns/net")?;
        let initial = File::open("/proc/1/ns/net")?;
        if configured != NamespaceIdentity::read(current.as_fd())?
            || configured == NamespaceIdentity::read(initial.as_fd())?
        {
            return Err(invalid(
                "Worker overlay requires its configured, isolated process network namespace",
            ));
        }
        let key = protected_text(&settings.private_key_file, 64, 0o077)?;
        let private_key = key.trim_end_matches('\n');
        if !valid_key(private_key) {
            return Err(invalid("invalid Worker overlay private key"));
        }
        command(namespace.as_fd(), "wg", &["pubkey"], Some(private_key)).map_err(|_| {
            invalid("Worker overlay requires WireGuard tools and a valid private key")
        })?;
        // Verify kernel support in the authorized Worker namespace before advertising it.
        let probe = random_link_name()?;
        ip(
            namespace.as_fd(),
            &format!("link add {probe} type wireguard\n"),
        )?;
        ip(namespace.as_fd(), &format!("link del {probe}\n"))?;
        Ok(Self {
            settings,
            namespace,
            private_key: private_key.to_owned(),
            allocation,
            first: domain.first,
            last: domain.last,
        })
    }

    fn validate_routes(&self, routes: &[Route]) -> Result<()> {
        let mut machines = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        let mut names = BTreeSet::new();
        for route in routes {
            if ![
                &route.machine_id,
                &route.instance_id,
                &route.incarnation_id,
                &route.attachment_id,
            ]
            .into_iter()
            .all(|id| valid_id(id))
                || (route.worker_id != self.settings.worker_id
                    && !self
                        .settings
                        .peers
                        .iter()
                        .any(|peer| peer.worker_id == route.worker_id))
                || route.owner_epoch < 1
                || route.execution_epoch < 1
                || route.attachment_revision < 1
                || !route.membership().valid()
                || !(self.first..=self.last).contains(&u32::from(route.private_ipv4))
                || !crate::network_dns::valid_name(&route.dns_name)
                || !machines.insert(&route.machine_id)
                || !addresses.insert(route.private_ipv4)
                || !names.insert(&route.dns_name)
            {
                return Err(Fault::invalid(
                    "overlay has an invalid or duplicate published endpoint",
                ));
            }
        }
        Ok(())
    }
}

impl Link {
    fn open(config: &Config, router: &PrivateRouter) -> io::Result<Self> {
        let namespace = router.namespace();
        // A crashed broker can leave a pinned router namespace. Stop its prior
        // interface before opening another lease in the recovered namespace.
        clear_inherited_link(namespace)?;
        install_filter(namespace, &BTreeMap::new(), Duration::ZERO)?;
        let mut seed = [0; 4];
        getrandom::fill(&mut seed)
            .map_err(|_| io::Error::other("cannot allocate overlay flow generation"))?;
        let link = Self {
            router: namespace.try_clone_to_owned()?.into(),
            remote: Vec::new(),
            granted: BTreeMap::new(),
            next_mark: (u32::from_ne_bytes(seed) & (u32::MAX / 2)).max(1),
            deadline: None,
        };
        let parent = config.namespace.as_fd();
        let name = random_link_name()?;
        ip(parent, &format!("link add {name} type wireguard\n"))?;
        if let Err(error) = ip(
            parent,
            &format!("link set {name} netns {}\n", namespace_path(namespace)),
        ) {
            let _ = ip(parent, &format!("link del {name}\n"));
            return Err(error);
        }
        if let Err(error) = ip(namespace, &format!("link set {name} name {DEVICE}\n")) {
            let _ = ip(namespace, &format!("link del {name}\n"));
            return Err(error);
        }
        link.set_peers(config, &[])?;
        ip(namespace, &format!("link set {DEVICE} up\n"))?;
        Ok(link)
    }

    fn apply(
        &mut self,
        config: &Config,
        remote: Vec<(String, Ipv4Addr)>,
        pairs: Vec<(Pair, Generations)>,
        deadline: Instant,
    ) -> io::Result<()> {
        if self.deadline.is_some_and(|old| old <= Instant::now()) {
            self.granted.clear();
        }
        if remote == self.remote
            && self.deadline == Some(deadline)
            && pairs.len() == self.granted.len()
            && pairs.iter().all(|(pair, generations)| {
                self.granted
                    .get(pair)
                    .is_some_and(|grant| grant.generations == *generations)
            })
        {
            return Ok(());
        }
        if self.remote != remote {
            install_filter(self.router.as_fd(), &BTreeMap::new(), Duration::ZERO)?;
            self.set_peers(config, &remote)?;
            let namespace = self.router.as_fd();
            ip(namespace, &format!("route flush dev {DEVICE}\n"))?;
            let mut routes = String::new();
            for (_, address) in &remote {
                writeln!(routes, "route add {address}/32 dev {DEVICE} scope link").unwrap();
            }
            if !routes.is_empty() {
                ip(namespace, &routes)?;
            }
            self.remote = remote;
        }
        let mut grants = BTreeMap::new();
        for (pair, generations) in pairs {
            let grant = match self
                .granted
                .get(&pair)
                .filter(|grant| grant.generations == generations)
            {
                Some(grant) => *grant,
                None => {
                    let mark = self.next_mark;
                    self.next_mark = mark
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("overlay flow generation exhausted"))?;
                    Grant { generations, mark }
                }
            };
            grants.insert(pair, grant);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        install_filter(self.router.as_fd(), &grants, remaining)?;
        self.granted = grants;
        self.deadline = Some(deadline);
        Ok(())
    }

    fn set_peers(&self, config: &Config, routes: &[(String, Ipv4Addr)]) -> io::Result<()> {
        let settings = &config.settings;
        let mut script = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {}\n",
            config.private_key, settings.listen_port
        );
        for peer in &settings.peers {
            let addresses = routes
                .iter()
                .filter(|(worker, _)| worker == &peer.worker_id)
                .map(|(_, address)| format!("{address}/32"))
                .collect::<Vec<_>>();
            writeln!(
                script,
                "\n[Peer]\nPublicKey = {}\nEndpoint = {}",
                peer.public_key, peer.endpoint
            )
            .unwrap();
            if !addresses.is_empty() {
                writeln!(script, "AllowedIPs = {}", addresses.join(",")).unwrap();
            }
        }
        command(
            self.router.as_fd(),
            "wg",
            &["syncconf", DEVICE, "/dev/stdin"],
            Some(&script),
        )
        .map_err(|_| io::Error::other("cannot apply Worker overlay WireGuard peer configuration"))
    }

    fn revoke(&mut self) -> io::Result<()> {
        if self.deadline.is_some() {
            install_filter(self.router.as_fd(), &BTreeMap::new(), Duration::ZERO)?;
            self.granted.clear();
            self.deadline = None;
        }
        Ok(())
    }
}

pub(crate) fn clear_inherited_link(namespace: BorrowedFd<'_>) -> io::Result<()> {
    if command(namespace, "ip", &["link", "show", "dev", DEVICE], None).is_ok() {
        install_filter(namespace, &BTreeMap::new(), Duration::ZERO)?;
        ip(namespace, &format!("link del {DEVICE}\n"))?;
    }
    Ok(())
}

impl Drop for Link {
    fn drop(&mut self) {
        let namespace = self.router.as_fd();
        let _ = install_filter(namespace, &BTreeMap::new(), Duration::ZERO);
        let _ = ip(namespace, &format!("link del {DEVICE}\n"));
    }
}

fn install_filter(
    namespace: BorrowedFd<'_>,
    grants: &BTreeMap<Pair, Grant>,
    remaining: Duration,
) -> io::Result<()> {
    let mut script = format!(
        "add table ip sm_overlay\ndelete table ip sm_overlay\nadd table ip sm_overlay\n\
         add chain ip sm_overlay transit {{ type filter hook forward priority 5; policy accept; }}\n\
         add chain ip sm_overlay local {{ type filter hook input priority 5; policy accept; }}\n\
         add rule ip sm_overlay local iifname \"{DEVICE}\" drop\n"
    );
    let remaining_ms = remaining.as_millis();
    if !grants.is_empty() && remaining_ms > 0 {
        script.push_str(
            "add set ip sm_overlay allowed { type ipv4_addr . ipv4_addr; flags timeout; }\n\
             add map ip sm_overlay generations { type ipv4_addr . ipv4_addr : mark; flags timeout; }\n\
             add set ip sm_overlay established { type ipv4_addr . ipv4_addr . mark; flags timeout; }\n",
        );
        let entries: Vec<_> = grants.iter().collect();
        for batch in entries.chunks(128) {
            for (set, with_mark) in [
                ("allowed", false),
                ("generations", false),
                ("established", true),
            ] {
                let elements = batch
                    .iter()
                    .map(|((local, remote), grant)| {
                        let key = if with_mark {
                            format!("{local} . {remote} . {}", grant.mark)
                        } else {
                            format!("{local} . {remote}")
                        };
                        let value = if set == "generations" {
                            format!(" : {}", grant.mark)
                        } else {
                            String::new()
                        };
                        format!("{key} timeout {remaining_ms}ms{value}")
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(script, "add element ip sm_overlay {set} {{ {elements} }}").unwrap();
            }
        }
        for (interfaces, tuple) in [
            (
                format!(r#"iifname "p*" oifname "{DEVICE}""#),
                "ip saddr . ip daddr",
            ),
            (
                format!(r#"iifname "{DEVICE}" oifname "p*""#),
                "ip daddr . ip saddr",
            ),
        ] {
            // A fresh SYN authorizes the conntrack entry for this exact pair
            // generation. An established stream cannot resume after a revoke,
            // even if no packet hit the router while the grant was absent.
            writeln!(script, "add rule ip sm_overlay transit {interfaces} tcp flags & (syn | ack) == syn ct mark set {tuple} map @generations").unwrap();
            writeln!(script, "add rule ip sm_overlay transit {interfaces} meta l4proto tcp {tuple} . ct mark @established accept").unwrap();
            writeln!(script, "add rule ip sm_overlay transit {interfaces} meta l4proto != tcp {tuple} @allowed accept").unwrap();
        }
    }
    for interface in ["iifname", "oifname"] {
        writeln!(script, "add rule ip sm_overlay transit {interface} \"{DEVICE}\" meta l4proto tcp reject with tcp reset").unwrap();
        writeln!(
            script,
            "add rule ip sm_overlay transit {interface} \"{DEVICE}\" drop"
        )
        .unwrap();
    }
    nft(namespace, &script)
}

fn valid_key(value: &str) -> bool {
    value.len() == 44
        && value.as_bytes()[43] == b'='
        && value.as_bytes()[..43]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/".contains(byte))
        && value.as_bytes()[..43].iter().any(|byte| *byte != b'A')
}

fn protected_text(path: &Path, max: usize, forbidden_mode: u32) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & forbidden_mode != 0 {
        return Err(invalid(
            "Worker overlay configuration or key has unsafe ownership or mode",
        ));
    }
    let mut value = String::new();
    file.take(max as u64 + 1).read_to_string(&mut value)?;
    if value.len() > max {
        return Err(invalid(
            "Worker overlay configuration or key exceeds its size limit",
        ));
    }
    Ok(value)
}

fn random_link_name() -> io::Result<String> {
    let mut random = [0; 5];
    getrandom::fill(&mut random)
        .map_err(|_| io::Error::other("cannot allocate overlay interface name"))?;
    Ok(format!("swo{}", hex::encode(random)))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn host_fault(error: io::Error) -> Fault {
    Fault::new("E_HOST_IO", error.to_string())
}

#[cfg(test)]
#[path = "network_overlay_tests.rs"]
mod tests;
