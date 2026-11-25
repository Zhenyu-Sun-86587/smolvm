//! Authorize private ingress as a wake demand for a specific managed endpoint.
mod ingress;
pub(crate) use ingress::open as open_ingress;
pub(crate) use ingress::Datagram;

use crate::catalog::Catalog;
use crate::ipc::{valid_id, Expected, Fault, Request, Result, PROTOCOL};
use crate::lifecycle_controller::{binding, monotonic, protections, row_policy};
use crate::network::topology::QuarantinedPort;
use crate::network_lease_catalog::TapLease;
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::time::{SystemTime, UNIX_EPOCH};

const PRINCIPAL: &str = "worker-private-packet";
const TRIGGER: &str = "private_network_packet";
const MAX_RULES_PER_SOURCE: i64 = 32;
const RATE_LIMIT_MS: i64 = 5_000;
const DEMAND_TIMEOUT_MS: i64 = 120_000;
const MAX_PACKET_AGE_NS: i64 = 3_000_000_000;
const DATAGRAM_TIMEOUT_MS: i64 = 15_000;
const MAX_BUFFERED_DATAGRAMS: usize = 64;
const MAX_RECORDED_CUTS: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleInput {
    source_attachment_id: String,
    target_attachment_id: String,
    transport: Transport,
    guest_port: u16,
    enabled: Option<bool>,
    expected_revision: Option<i64>,
    source_execution: Option<Expected>,
}

struct Endpoint {
    instance: String,
    network: String,
    address: Ipv4Addr,
    revision: i64,
    bundle: String,
}

fn endpoint(db: &Connection, id: &str) -> Result<Option<Endpoint>> {
    Ok(db.query_row("SELECT a.instance_id,a.network_id,a.private_ipv4,a.revision,o.bundle_digest FROM network_attachments a
        JOIN operations o USING(operation_id) WHERE a.attachment_id=? AND a.route_id='deep' AND a.state='reserved'
        AND EXISTS(SELECT 1 FROM managed_launches l WHERE l.operation_id=a.operation_id)", [id], |r| {
        Ok(Endpoint { instance:r.get(0)?, network:r.get(1)?, address:Ipv4Addr::from(r.get::<_,u32>(2)?), revision:r.get(3)?, bundle:r.get(4)? })
    }).optional()?)
}

struct Rule {
    id: String,
    source: String,
    target: String,
    transport: String,
    port: u16,
    enabled: bool,
    revision: i64,
    source_incarnation: Option<String>,
    source_epoch: Option<i64>,
    source_lease: Option<String>,
    source_lease_revision: Option<i64>,
    since_ns: i64,
    mutation_id: String,
    mutation_digest: String,
}

const RULE_COLUMNS: &str = "id,source_attachment,target_attachment,transport,guest_port,enabled,revision,source_incarnation,source_epoch,
    source_lease,source_lease_revision,enabled_since_ns,mutation_id,mutation_digest";

impl Rule {
    fn read(db: &Connection, id: &str) -> Result<Option<Self>> {
        Ok(db
            .query_row(
                &format!("SELECT {RULE_COLUMNS} FROM private_packet_wake_rules WHERE id=?"),
                [id],
                Self::row,
            )
            .optional()?)
    }

    fn row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            source: r.get(1)?,
            target: r.get(2)?,
            transport: r.get(3)?,
            port: r.get(4)?,
            enabled: r.get(5)?,
            revision: r.get(6)?,
            source_incarnation: r.get(7)?,
            source_epoch: r.get(8)?,
            source_lease: r.get(9)?,
            source_lease_revision: r.get(10)?,
            since_ns: r.get(11)?,
            mutation_id: r.get(12)?,
            mutation_digest: r.get(13)?,
        })
    }

    fn reply(&self, db: &Connection, current: Option<&TapLease>) -> Result<Value> {
        let last = db.query_row("SELECT operation_id,rule_revision,target_epoch,authorized,datagram FROM private_packet_wake_results WHERE rule_id=?", [&self.id], |r| {
            Ok(json!({"operation_id":r.get::<_,String>(0)?,"rule_revision":r.get::<_,i64>(1)?,
                "execution_epoch":r.get::<_,i64>(2)?,"authorized":r.get::<_,bool>(3)?,"datagram":r.get::<_,Option<String>>(4)?}))
        }).optional()?;
        Ok(
            json!({"rule_id":self.id,"source_attachment_id":self.source,"target_attachment_id":self.target,
            "transport":self.transport,"guest_port":self.port,"enabled":self.enabled,"revision":self.revision,
            "source_incarnation_id":self.source_incarnation,"source_execution_epoch":self.source_epoch,
            "source_current":current.is_some_and(|lease| self.matches(lease)),"last_wake":last}),
        )
    }

    fn matches(&self, lease: &TapLease) -> bool {
        self.enabled
            && self.source_incarnation == lease.incarnation_id
            && self.source_epoch == lease.execution_epoch
            && self.source_lease.as_deref() == Some(lease.lease_id.as_str())
            && self.source_lease_revision == Some(lease.revision)
    }
}

struct Monitor {
    lease_id: String,
    socket: OwnedFd,
    sequence: u64,
}

struct RouteCut {
    epoch: i64,
    sequence: u64,
}

struct HeldDatagram {
    data: Datagram,
    until: i64,
}

#[derive(Default)]
pub(crate) struct Observer {
    monitors: HashMap<String, Monitor>,
    cuts: HashMap<String, RouteCut>,
    datagrams: HashMap<String, HeldDatagram>,
    sequence: u64,
}

fn unavailable(detail: &str) -> Fault {
    Fault::new("E_RESOURCE_UNAVAILABLE", detail)
}

fn denied(detail: &str) -> Fault {
    Fault::new("E_PERMISSION_DENIED", detail)
}

fn wall_ns() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_nanos()).ok())
        .ok_or_else(|| Fault::new("E_HOST_IO", "could not read packet clock"))
}

fn current_tap(
    catalog: &Catalog,
    ports: &HashMap<String, QuarantinedPort>,
    attachment: &str,
) -> Result<Option<TapLease>> {
    if !ports.contains_key(attachment) {
        return Ok(None);
    }
    let lease = match catalog.tap_lease(attachment) {
        Ok(lease)
            if lease.state == "attached" && lease.gate == "open" && lease.route_id == "deep" =>
        {
            lease
        }
        Ok(_) => return Ok(None),
        Err(error) if error.code == "E_NOT_FOUND" => return Ok(None),
        Err(error) => return Err(error),
    };
    let process: Option<(i32, i64)> = catalog.db.query_row("SELECT e.pid,e.pid_start_time FROM executions e
        JOIN instance_bindings b USING(route_id,instance_id,incarnation_id,execution_epoch),worker_state w
        WHERE e.incarnation_id=? AND e.execution_epoch=? AND e.phase='registered' AND e.host_boot_id=w.host_boot_id
        AND w.recovering=0 AND w.broker_session_id=? AND e.route_id='deep' AND e.instance_id=? AND e.bundle_digest=?
        AND e.last_operation_id=? AND e.host_boot_id=?", params![lease.incarnation_id,lease.execution_epoch,lease.broker_session_id,
        lease.instance_id,lease.bundle_digest,lease.operation_id,lease.host_boot_id], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    let alive = process.is_some_and(|(pid, start)| {
        crate::worker::observe_pid(pid).is_ok_and(|(now, _)| start == now)
    });
    Ok(alive.then_some(lease))
}

impl Observer {
    fn monitor(
        &mut self,
        lease: &TapLease,
        port: &QuarantinedPort,
        after: u64,
    ) -> Result<&Monitor> {
        let id = &lease.attachment.attachment_id;
        if self
            .monitors
            .get(id)
            .is_none_or(|existing| existing.lease_id != lease.lease_id || existing.sequence < after)
        {
            let socket = port.observe_ingress().map_err(|error| {
                eprintln!("could not read private router ingress: {error}");
                Fault::new(
                    "E_HOST_IO",
                    "private router ingress observation is unavailable",
                )
            })?;
            self.monitors.insert(
                id.clone(),
                Monitor {
                    lease_id: lease.lease_id.clone(),
                    socket,
                    sequence: self.sequence,
                },
            );
        }
        Ok(&self.monitors[id])
    }

    pub(crate) fn replaced_port(&mut self, attachment: &str) {
        self.cuts.remove(attachment);
    }

    pub(crate) fn closed_port(
        &mut self,
        catalog: &Catalog,
        ports: &HashMap<String, QuarantinedPort>,
        lease: &TapLease,
    ) -> Result<()> {
        let target = &lease.attachment.attachment_id;
        self.monitors.remove(target);
        let Some(epoch) = lease.execution_epoch else {
            return Ok(());
        };
        if self.cuts.len() >= MAX_RECORDED_CUTS {
            if let Some(oldest) = self
                .cuts
                .iter()
                .min_by_key(|(_, cut)| cut.sequence)
                .map(|(id, _)| id.clone())
            {
                self.cuts.remove(&oldest);
            }
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| unavailable("private wake observer sequence exhausted"))?;
        self.cuts.insert(
            target.clone(),
            RouteCut {
                epoch,
                sequence: self.sequence,
            },
        );
        // Discard queues opened before the destination's route disappeared. A
        // datagram from the fresh socket cannot have traversed that old route.
        let sources = {
            let mut query = catalog.db.prepare("SELECT DISTINCT source_attachment FROM private_packet_wake_rules
                WHERE target_attachment=? AND enabled=1 AND transport='udp' ORDER BY source_attachment LIMIT ?")?;
            let rows = query.query_map(params![target, MAX_BUFFERED_DATAGRAMS as i64], |r| {
                r.get::<_, String>(0)
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for source in sources {
            if let Some(lease) = current_tap(catalog, ports, &source)? {
                self.monitor(&lease, &ports[&source], self.sequence)?;
            }
        }
        Ok(())
    }

    pub(crate) fn rule(
        &mut self,
        catalog: &mut Catalog,
        request: &Request,
        ports: &HashMap<String, QuarantinedPort>,
    ) -> Result<Value> {
        catalog.ready()?;
        let (_, bundle, expected) = request.scope()?;
        let (actual, _) = binding(catalog, request)?;
        if request.method == "QueryPrivatePacketWakeEndpoint" {
            if actual != *expected {
                return Err(Fault::new(
                    "E_STALE_EXECUTION",
                    "private wake target binding changed",
                ));
            }
            let attachment: Option<(String, u32, Option<String>)> = catalog.db.query_row(
                "SELECT a.attachment_id,a.guest_ipv4,dns.name FROM network_attachments a JOIN operations o USING(operation_id)
                 LEFT JOIN network_dns_names dns USING(attachment_id)
                 WHERE a.instance_id=? AND a.route_id='deep' AND a.device_id='net0' AND o.bundle_digest=? AND a.state='reserved'
                   AND EXISTS(SELECT 1 FROM managed_launches l WHERE l.operation_id=a.operation_id)",
                params![expected.instance_id,bundle], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
            ).optional()?;
            let (id, guest, dns) = attachment
                .ok_or_else(|| Fault::new("E_NOT_FOUND", "no managed private wake endpoint"))?;
            let endpoint = endpoint(&catalog.db, &id)?
                .ok_or_else(|| unavailable("private wake endpoint disappeared"))?;
            return Ok(
                json!({"attachment_id":id,"network_id":endpoint.network,"private_ipv4":endpoint.address,
                    "guest_ipv4":Ipv4Addr::from(guest),"dns_name":dns,"revision":endpoint.revision}),
            );
        }
        let input: RuleInput = request.payload()?;
        if !valid_id(&input.source_attachment_id)
            || !valid_id(&input.target_attachment_id)
            || input.guest_port == 0
            || input.source_attachment_id == input.target_attachment_id
        {
            return Err(Fault::invalid(
                "private wake needs two distinct attachments and a nonzero port",
            ));
        }
        let target = endpoint(&catalog.db, &input.target_attachment_id)?
            .filter(|target| target.instance == actual.instance_id && target.bundle == bundle)
            .ok_or_else(|| {
                Fault::new(
                    "E_NOT_FOUND",
                    "private wake target attachment not found within this binding",
                )
            })?;
        let id = format!(
            "packet-{:x}",
            Sha256::digest(
                json!([
                    input.source_attachment_id,
                    input.target_attachment_id,
                    input.transport.name(),
                    input.guest_port
                ])
                .to_string()
            )
        );
        let previous = Rule::read(&catalog.db, &id)?;
        let source_tap = current_tap(catalog, ports, &input.source_attachment_id)?;
        if request.method == "QueryPrivatePacketWakeRule" {
            if actual != *expected {
                return Err(Fault::new(
                    "E_STALE_EXECUTION",
                    "private wake target binding changed",
                ));
            }
            return previous
                .ok_or_else(|| Fault::new("E_NOT_FOUND", "private packet wake rule not found"))?
                .reply(&catalog.db, source_tap.as_ref());
        }
        let (operation, digest) = request.operation()?;
        let fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(json!([bundle, expected, request.payload, digest]).to_string())
        );
        if let Some(prior) = previous.as_ref().filter(|r| r.mutation_id == operation) {
            if prior.mutation_digest != fingerprint {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "private wake rule mutation changed",
                ));
            }
            return prior.reply(&catalog.db, source_tap.as_ref());
        }
        if actual != *expected {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "private wake target binding changed",
            ));
        }
        let enabled = input
            .enabled
            .ok_or_else(|| Fault::invalid("enabled is required"))?;
        let revision = previous.as_ref().map_or(0, |rule| rule.revision);
        if input.expected_revision != Some(revision) {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "private packet wake rule revision changed",
            ));
        }
        let verified = if enabled {
            let source = endpoint(&catalog.db, &input.source_attachment_id)?
                .filter(|source| source.network == target.network)
                .ok_or_else(|| denied("private wake peers must be in the same network"))?;
            let lease = source_tap
                .as_ref()
                .zip(input.source_execution.as_ref())
                .filter(|(lease, expected)| {
                    source.instance == expected.instance_id
                        && lease.instance_id == expected.instance_id
                        && lease.incarnation_id == expected.incarnation_id
                        && lease.execution_epoch == Some(expected.execution_epoch)
                })
                .map(|(lease, _)| lease)
                .ok_or_else(|| {
                    Fault::new(
                        "E_STALE_EXECUTION",
                        "current published wake source required",
                    )
                })?;
            let count = catalog.db.query_row("SELECT count(*) FROM private_packet_wake_rules WHERE source_attachment=? AND enabled=1 AND id<>?",
                params![input.source_attachment_id,id], |r| r.get::<_,i64>(0))?;
            if count >= MAX_RULES_PER_SOURCE {
                return Err(Fault::new(
                    "E_RESOURCE_LIMIT",
                    "private packet wake rule limit reached for this source",
                ));
            }
            let after = if input.transport == Transport::Udp {
                self.cuts
                    .get(&input.target_attachment_id)
                    .map_or(0, |cut| cut.sequence)
            } else {
                0
            };
            self.monitor(lease, &ports[&input.source_attachment_id], after)?;
            Some(lease)
        } else {
            if previous.is_none() {
                return Err(Fault::new(
                    "E_NOT_FOUND",
                    "private packet wake rule not found",
                ));
            }
            None
        };
        catalog.db.execute("INSERT INTO private_packet_wake_rules VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
            enabled=excluded.enabled,revision=excluded.revision,source_incarnation=excluded.source_incarnation,source_epoch=excluded.source_epoch,
            source_lease=excluded.source_lease,source_lease_revision=excluded.source_lease_revision,enabled_since_ns=excluded.enabled_since_ns,
            mutation_id=excluded.mutation_id,mutation_digest=excluded.mutation_digest",
            params![id,input.source_attachment_id,input.target_attachment_id,input.transport.name(),input.guest_port,enabled,
                revision.checked_add(1).ok_or_else(|| Fault::invalid("wake rule revision exhausted"))?,verified.and_then(|x|x.incarnation_id.as_deref()),
                verified.and_then(|x|x.execution_epoch),verified.map(|x|x.lease_id.as_str()),verified.map(|x|x.revision),wall_ns()?,operation,fingerprint])?;
        Rule::read(&catalog.db, &id)?
            .ok_or_else(|| unavailable("private packet wake rule disappeared"))?
            .reply(&catalog.db, source_tap.as_ref())
    }

    pub(crate) fn poll(
        &mut self,
        catalog: &mut Catalog,
        ports: &HashMap<String, QuarantinedPort>,
    ) -> Result<()> {
        if catalog.ready().is_err() {
            self.monitors.clear();
            self.datagrams.clear();
            self.cuts.clear();
            return Ok(());
        }
        let now = monotonic()?;
        self.datagrams.retain(|_, held| held.until > now);
        reconcile(catalog, ports, &mut self.datagrams)?;
        let rules = {
            let mut query = catalog.db.prepare(&format!(
                "SELECT {RULE_COLUMNS} FROM private_packet_wake_rules WHERE enabled=1"
            ))?;
            let rows = query.query_map([], Rule::row)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut sources: HashMap<String, Vec<(Rule, Endpoint)>> = HashMap::new();
        for rule in rules {
            if !ports.contains_key(&rule.source) {
                continue;
            }
            let Some(target) = endpoint(&catalog.db, &rule.target)? else {
                continue;
            };
            sources
                .entry(rule.source.clone())
                .or_default()
                .push((rule, target));
        }
        let mut active = HashSet::new();
        let wall = wall_ns()?;
        for (source, rules) in sources {
            let Some(lease) = current_tap(catalog, ports, &source)? else {
                continue;
            };
            if !rules.iter().any(|(rule, _)| rule.matches(&lease)) {
                continue;
            }
            let after = rules
                .iter()
                .filter(|(rule, _)| rule.transport == "udp" && rule.matches(&lease))
                .filter_map(|(rule, _)| self.cuts.get(&rule.target).map(|cut| cut.sequence))
                .max()
                .unwrap_or(0);
            let monitor = match self.monitor(&lease, &ports[&source], after) {
                Ok(monitor) => monitor,
                Err(_) => continue,
            };
            let sequence = monitor.sequence;
            let packets = match ingress::drain(&monitor.socket) {
                Ok(packets) => packets,
                Err(error) => {
                    eprintln!("private packet wake observer closed: {error}");
                    continue;
                }
            };
            active.insert(source);
            for mut pkt in packets {
                if pkt.source != lease.attachment.private_ipv4
                    || wall.saturating_sub(pkt.received_ns) > MAX_PACKET_AGE_NS
                    || pkt.received_ns > wall.saturating_add(MAX_PACKET_AGE_NS)
                {
                    continue;
                }
                for (rule, target) in &rules {
                    if rule.matches(&lease)
                        && pkt.target == target.address
                        && pkt.port == rule.port
                        && pkt.transport.name() == rule.transport
                        && pkt.received_ns >= rule.since_ns
                    {
                        if let Some(queued) = enqueue(catalog, rule, target)? {
                            let after_cut = self.cuts.get(&rule.target).is_some_and(|cut| {
                                sequence >= cut.sequence && queued.offline_epoch == Some(cut.epoch)
                            });
                            if after_cut && self.datagrams.len() < MAX_BUFFERED_DATAGRAMS {
                                if let Some(data) = pkt.datagram.take() {
                                    let age_ms =
                                        wall.saturating_sub(pkt.received_ns).max(0) / 1_000_000;
                                    self.datagrams.insert(
                                        queued.id,
                                        HeldDatagram {
                                            data,
                                            until: now + DATAGRAM_TIMEOUT_MS - age_ms,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        self.monitors.retain(|key, _| active.contains(key));
        Ok(())
    }
}

fn current_target(db: &Connection, target: &Endpoint) -> Result<Option<Expected>> {
    Ok(db
        .query_row(
            "SELECT incarnation_id,execution_epoch FROM instance_bindings
        WHERE route_id='deep' AND instance_id=?",
            [&target.instance],
            |r| {
                Ok(Expected {
                    instance_id: target.instance.clone(),
                    incarnation_id: r.get(0)?,
                    execution_epoch: r.get(1)?,
                })
            },
        )
        .optional()?)
}

fn request(method: &str, target: &Endpoint, expected: &Expected, payload: Value) -> Request {
    Request {
        protocol: PROTOCOL.into(),
        request_id: method.into(),
        method: method.into(),
        route_id: Some("deep".into()),
        bundle_digest: Some(target.bundle.clone()),
        expected: Some(expected.clone()),
        operation_id: None,
        request_digest: None,
        fd_table: vec![],
        payload,
    }
}

struct Queued {
    id: String,
    offline_epoch: Option<i64>,
}

fn enqueue(catalog: &mut Catalog, rule: &Rule, target: &Endpoint) -> Result<Option<Queued>> {
    let now = monotonic()?;
    let db = &catalog.db;
    let Some(expected) = current_target(db, target)? else {
        return Ok(None);
    };
    let Ok((policy_revision, policy)) = row_policy(db, &expected.instance_id) else {
        return Ok(None);
    };
    if !policy.permits_wake(TRIGGER) {
        return Ok(None);
    }
    let available: bool = db.query_row("SELECT NOT EXISTS(SELECT 1 FROM private_packet_wake_demands WHERE instance_id=?1)
        AND NOT EXISTS(SELECT 1 FROM private_packet_wake_limits WHERE instance_id=?1 AND next_request_at>?2)
        AND EXISTS(SELECT 1 FROM instance_bindings WHERE instance_id=?1 AND route_id='deep' AND active_operation_id IS NULL)",
        params![expected.instance_id,now], |r|r.get(0))?;
    if !available {
        return Ok(None);
    }
    let sleeping: bool = if let Some(incarnation) = &expected.incarnation_id {
        db.query_row("SELECT EXISTS(SELECT 1 FROM native_standby s JOIN native_transitions n USING(operation_id)
            JOIN network_tap_leases t ON t.incarnation_id=s.incarnation_id,worker_state w
            WHERE s.incarnation_id=? AND n.mode='managed' AND n.network_gate=1 AND n.stage='complete'
            AND t.attachment_id=? AND t.state='attached' AND t.execution_epoch=? AND t.broker_session_id=w.broker_session_id)",
            params![incarnation,rule.target,expected.execution_epoch], |r|r.get(0))?
    } else {
        db.query_row("SELECT EXISTS(SELECT 1 FROM statepoints p JOIN operations o USING(operation_id)
            JOIN executions e ON e.incarnation_id=p.source_incarnation_id JOIN network_tap_leases t ON t.incarnation_id=e.incarnation_id
            WHERE o.instance_id=? AND e.execution_epoch=? AND e.phase='exited' AND p.phase='hibernated'
            AND json_extract(p.export_json,'$.purpose') IN ('hibernate','rollback_rescue') AND t.attachment_id=? AND t.state='retired')",
            params![expected.instance_id,expected.execution_epoch,rule.target], |r|r.get(0))?
    };
    if !sleeping {
        return Ok(None);
    }
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| Fault::new("E_HOST_IO", "cannot allocate private wake demand identity"))?;
    let id = format!("packet-{}", hex::encode(nonce));
    let req = request(
        "RequestWake",
        target,
        &expected,
        json!({"protection_id":id,"principal":PRINCIPAL,"reason":"authorized private packet",
        "trigger":TRIGGER,"expected_binding_revision":protections::revision(&expected)?,"authorization_revision":rule.revision,"endpoint_revision":target.revision}),
    );
    let tx = catalog
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if current_target(&tx, target)?.as_ref() != Some(&expected) {
        return Ok(None);
    }
    protections::mutate(&tx, &req, &expected)?;
    tx.execute(
        "INSERT INTO private_packet_wake_demands VALUES(?,?,?,?,?,?)",
        params![
            expected.instance_id,
            id,
            rule.id,
            rule.revision,
            policy_revision,
            now + DEMAND_TIMEOUT_MS
        ],
    )?;
    tx.execute("INSERT INTO private_packet_wake_limits VALUES(?,?) ON CONFLICT(instance_id) DO UPDATE SET next_request_at=excluded.next_request_at",
        params![expected.instance_id,now+RATE_LIMIT_MS])?;
    tx.commit()?;
    Ok(Some(Queued {
        id,
        offline_epoch: expected
            .incarnation_id
            .is_none()
            .then_some(expected.execution_epoch),
    }))
}

struct Demand {
    machine: String,
    id: String,
    rule: String,
    revision: i64,
    policy_revision: i64,
    expires: i64,
    incarnation: Option<String>,
    epoch: i64,
    endpoint_revision: i64,
    protection_revision: i64,
    operation: Option<String>,
    stage: Option<String>,
    kind: Option<String>,
}

fn reconcile(
    catalog: &mut Catalog,
    ports: &HashMap<String, QuarantinedPort>,
    datagrams: &mut HashMap<String, HeldDatagram>,
) -> Result<()> {
    let demands = {
        let mut query = catalog.db.prepare("SELECT d.instance_id,d.protection_id,d.rule_id,d.rule_revision,d.policy_revision,d.expires_at,
            p.incarnation_id,p.epoch,p.endpoint_revision,p.revision,p.wake_operation,s.stage,s.kind FROM private_packet_wake_demands d
            JOIN lifecycle_protections p ON p.instance_id=d.instance_id AND p.id=d.protection_id
            LEFT JOIN lifecycle_decisions s ON s.id=p.wake_operation")?;
        let rows = query.query_map([], |r| {
            Ok(Demand {
                machine: r.get(0)?,
                id: r.get(1)?,
                rule: r.get(2)?,
                revision: r.get(3)?,
                policy_revision: r.get(4)?,
                expires: r.get(5)?,
                incarnation: r.get(6)?,
                epoch: r.get(7)?,
                endpoint_revision: r.get(8)?,
                protection_revision: r.get(9)?,
                operation: r.get(10)?,
                stage: r.get(11)?,
                kind: r.get(12)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for demand in demands {
        let now = monotonic()?;
        let rule = Rule::read(&catalog.db, &demand.rule)?
            .ok_or_else(|| unavailable("private wake rule disappeared"))?;
        let target = endpoint(&catalog.db, &rule.target)?;
        let policy = row_policy(&catalog.db, &demand.machine).ok();
        let eligible = demand.expires > now
            && rule.enabled
            && rule.revision == demand.revision
            && policy.is_some_and(|(rev, policy)| {
                rev == demand.policy_revision && policy.permits_wake(TRIGGER)
            })
            && current_tap(catalog, ports, &rule.source)?.is_some_and(|lease| rule.matches(&lease));
        let Some(target) = target else {
            cleanup(&mut catalog.db, &demand)?;
            datagrams.remove(&demand.id);
            continue;
        };
        let Some(expected) = current_target(&catalog.db, &target)? else {
            cleanup(&mut catalog.db, &demand)?;
            datagrams.remove(&demand.id);
            continue;
        };
        let completed =
            demand.stage.as_deref() == Some("completed") && expected.incarnation_id.is_some();
        let same_epoch = expected.incarnation_id == demand.incarnation
            && expected.execution_epoch == demand.epoch
            && target.revision == demand.endpoint_revision;
        let restore = demand.kind.as_deref() == Some("vm_restore")
            && demand.incarnation.is_none()
            && demand.endpoint_revision.checked_add(1) == Some(target.revision);
        let successor = restore && demand.epoch.checked_add(1) == Some(expected.execution_epoch);
        let reattaching = restore
            && demand.epoch == expected.execution_epoch
            && expected.incarnation_id.is_none();
        if eligible && !completed && (same_epoch || successor || reattaching) {
            continue;
        }
        let (method, payload, authorized) = if completed {
            let exact = current_tap(catalog, ports, &rule.target)?.is_some_and(|lease| {
                lease.incarnation_id == expected.incarnation_id
                    && lease.execution_epoch == Some(expected.execution_epoch)
            });
            let authorized = eligible && exact && (same_epoch || successor);
            (
                "AuthorizeWakeActivation",
                json!({"wake_operation":demand.operation,"authorized":authorized,
                "authorization_revision":demand.revision,"endpoint_revision":target.revision}),
                authorized,
            )
        } else {
            ("CancelWakeDemand", json!({}), false)
        };
        let mut req = request(method, &target, &expected, payload);
        req.payload["protection_id"] = json!(demand.id);
        req.payload["principal"] = json!(PRINCIPAL);
        req.payload["expected_revision"] = json!(demand.protection_revision);
        let tx = catalog
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if current_target(&tx, &target)?.as_ref() != Some(&expected) {
            continue;
        }
        let applied = match protections::mutate(&tx, &req, &expected) {
            Ok(receipt) if authorized => {
                let release = request(
                    "ReleaseActivityHold",
                    &target,
                    &expected,
                    json!({"protection_id":demand.id,"principal":PRINCIPAL,"expected_revision":receipt["revision"]}),
                );
                protections::mutate(&tx, &release, &expected)?;
                true
            }
            Ok(_) => true,
            // Another control-plane action may fence the requested target before this pass.
            Err(error) if matches!(error.code, "E_STATE_CONFLICT" | "E_NOT_FOUND") => false,
            Err(error) => return Err(error),
        };
        let operation = demand.operation.filter(|_| completed && applied);
        let datagram = datagrams
            .remove(&demand.id)
            .filter(|held| authorized && held.until > now);
        if let Some(operation) = &operation {
            let status = (rule.transport == "udp" && demand.incarnation.is_none()).then_some(
                if datagram.is_some() {
                    "unknown"
                } else {
                    "dropped"
                },
            );
            tx.execute("INSERT INTO private_packet_wake_results(rule_id,operation_id,rule_revision,target_epoch,authorized,datagram)
                VALUES(?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET operation_id=excluded.operation_id,
                rule_revision=excluded.rule_revision,target_epoch=excluded.target_epoch,authorized=excluded.authorized,datagram=excluded.datagram",
                params![rule.id,operation,demand.revision,expected.execution_epoch,authorized,status])?;
        }
        remove_demand(&tx, &demand.machine, &demand.id)?;
        tx.commit()?;
        if let (Some(held), Some(operation)) = (datagram, operation) {
            // The delivery is consumed before injecting it. A Worker crash can
            // leave the outcome unknown and can never replay it on restart.
            let sender = current_tap(catalog, ports, &rule.source)?
                .is_some_and(|lease| rule.matches(&lease));
            let recipient = current_tap(catalog, ports, &rule.target)?.is_some_and(|lease| {
                lease.incarnation_id == expected.incarnation_id
                    && lease.execution_epoch == Some(expected.execution_epoch)
            });
            let forwarded = sender
                && recipient
                && held.until > monotonic()?
                && ports[&rule.target].forward_wake_datagram(held.data).is_ok();
            catalog.db.execute("UPDATE private_packet_wake_results SET datagram=? WHERE rule_id=? AND operation_id=?",
                params![if forwarded {"forwarded"} else {"dropped"},rule.id,operation])?;
        }
    }
    Ok(())
}

fn remove_demand(db: &Connection, instance: &str, id: &str) -> Result<()> {
    db.execute(
        "DELETE FROM private_packet_wake_demands WHERE instance_id=? AND protection_id=?",
        params![instance, id],
    )?;
    db.execute(
        "DELETE FROM lifecycle_protections WHERE instance_id=? AND id=? AND principal=?",
        params![instance, id, PRINCIPAL],
    )?;
    Ok(())
}

fn cleanup(db: &mut Connection, demand: &Demand) -> Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    remove_demand(&tx, &demand.machine, &demand.id)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn recover(db: &Connection) -> Result<()> {
    db.execute_batch(
        "DELETE FROM lifecycle_protections AS p WHERE EXISTS (SELECT 1 FROM private_packet_wake_demands d
            WHERE d.instance_id=p.instance_id AND d.protection_id=p.id);
        DELETE FROM private_packet_wake_limits;",
    )?;
    Ok(())
}

pub(crate) fn sleeping_address(
    db: &Connection,
    network: &str,
    name: &str,
    peer: Ipv4Addr,
) -> rusqlite::Result<Option<Ipv4Addr>> {
    let entry = db.query_row("SELECT destination.private_ipv4,source_vm.pid,source_vm.pid_start_time
        FROM network_dns_names dns JOIN network_attachments destination USING(attachment_id)
        JOIN private_packet_wake_rules rule ON rule.target_attachment=destination.attachment_id
        JOIN network_attachments source ON source.attachment_id=rule.source_attachment AND source.network_id=dns.network_id
        JOIN network_tap_leases tap ON tap.lease_id=rule.source_lease AND tap.attachment_id=source.attachment_id
            AND tap.operation_id=source.operation_id AND tap.revision=rule.source_lease_revision
        JOIN executions source_vm ON source_vm.incarnation_id=rule.source_incarnation AND source_vm.execution_epoch=rule.source_epoch
            AND source_vm.incarnation_id=tap.incarnation_id AND source_vm.execution_epoch=tap.execution_epoch
        JOIN instance_bindings live ON live.route_id=source_vm.route_id AND live.instance_id=source_vm.instance_id
            AND live.incarnation_id=source_vm.incarnation_id AND live.execution_epoch=source_vm.execution_epoch
        JOIN instance_bindings asleep ON asleep.route_id=destination.route_id AND asleep.instance_id=destination.instance_id
        JOIN lifecycle_policies policy ON policy.instance_id=asleep.instance_id, worker_state worker
        WHERE dns.network_id=?1 AND dns.name=?2 AND source.private_ipv4=?3 AND rule.enabled=1
            AND source.state='reserved' AND destination.state='reserved' AND tap.state='attached'
            AND source_vm.phase='registered' AND worker.recovering=0 AND worker.broker_session_id=tap.broker_session_id
            AND worker.host_boot_id=source_vm.host_boot_id AND asleep.incarnation_id IS NULL
            AND coalesce(json_extract(policy.policy_json,'$.wake_conditions.private_network_packet'),1)=1
            AND (EXISTS(SELECT 1 FROM initial_network_activations i WHERE i.lease_id=tap.lease_id AND i.phase='open')
              OR EXISTS(SELECT 1 FROM target_activations a WHERE a.operation_id=tap.operation_id AND a.phase='released' AND a.decision='commit'
                 AND a.incarnation_id=tap.incarnation_id AND a.execution_epoch=tap.execution_epoch
                 AND json_extract(a.binding_json,'$.network.target.lease_id')=tap.lease_id))
            AND EXISTS(SELECT 1 FROM statepoints p JOIN executions original ON original.incarnation_id=p.source_incarnation_id
                JOIN network_tap_leases predecessor ON predecessor.incarnation_id=original.incarnation_id
                WHERE original.instance_id=asleep.instance_id AND original.execution_epoch=asleep.execution_epoch
                    AND original.phase='exited' AND p.phase='hibernated' AND predecessor.state='retired'
                    AND predecessor.attachment_id=destination.attachment_id)
        LIMIT 1",params![network,name,u32::from(peer)], |r| Ok((r.get::<_,u32>(0)?,r.get::<_,i32>(1)?,r.get::<_,i64>(2)?))).optional()?;
    Ok(entry.and_then(|(address, pid, start)| {
        crate::worker::observe_pid(pid)
            .ok()
            .filter(|(actual, _)| *actual == start)
            .map(|_| Ipv4Addr::from(address))
    }))
}
