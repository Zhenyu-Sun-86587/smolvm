//! Operator-authorized peering between unambiguous private networks on one Worker.

use crate::catalog::Catalog;
use crate::ipc::valid_id;
use crate::network::topology::{PeeringLink, PrivateRouter, QuarantinedPort};
use crate::network_catalog::PeeringNetwork;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_POLICY_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
struct Pair {
    left: String,
    right: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    version: u32,
    allowed_pairs: Vec<Pair>,
}

pub(crate) struct Peering {
    policy: Option<PathBuf>,
    requested: BTreeSet<Pair>,
    links: BTreeMap<Pair, PeeringLink>,
    error: Option<String>,
}

impl Peering {
    pub(crate) fn new(policy: Option<PathBuf>) -> Self {
        Self {
            policy,
            requested: BTreeSet::new(),
            links: BTreeMap::new(),
            error: None,
        }
    }

    pub(crate) fn status(&self) -> Value {
        json!({"configured":self.policy.is_some(), "requested":self.requested,
            "active":self.links.keys().collect::<Vec<_>>(), "error":self.error})
    }

    pub(crate) fn refresh(
        &mut self,
        catalog: &Catalog,
        routers: &HashMap<String, PrivateRouter>,
        ports: &HashMap<String, QuarantinedPort>,
    ) {
        let Some(path) = &self.policy else { return };
        if catalog.ready().is_err() {
            self.links.clear();
            return;
        }
        let result = match read_policy(path) {
            Ok(requested) => {
                self.requested = requested;
                self.reconcile(catalog, routers, ports)
            }
            Err(error) => {
                self.requested.clear();
                Err(error)
            }
        };
        let error = match result {
            Ok(error) => error,
            Err(error) => {
                self.links.clear();
                Some(error.to_string())
            }
        };
        if error != self.error {
            if let Some(message) = &error {
                eprintln!("resourced private network peering: {message}");
            }
            self.error = error;
        }
    }

    fn reconcile(
        &mut self,
        catalog: &Catalog,
        routers: &HashMap<String, PrivateRouter>,
        ports: &HashMap<String, QuarantinedPort>,
    ) -> io::Result<Option<String>> {
        // Withdraw removed grants before provisioning new routes.
        self.links.retain(|pair, _| self.requested.contains(pair));
        let ids: BTreeSet<&str> = self
            .requested
            .iter()
            .flat_map(|pair| [pair.left.as_str(), pair.right.as_str()])
            .collect();
        let mut known = BTreeMap::new();
        for id in ids {
            if let Some(network) = catalog
                .peering_network(id)
                .map_err(|error| io::Error::other(error.message))?
            {
                known.insert(id, network);
            }
        }
        let mut ready = BTreeMap::new();
        let mut first_failure = None;
        for (pair, (left, right)) in resolve_pairs(&self.requested, &known)? {
            let Some((left_router, right_router)) = routers
                .get(&left.route_domain_id)
                .zip(routers.get(&right.route_domain_id))
            else {
                continue;
            };
            if ports.values().any(|port| {
                port.conflicts_with_peering(left_router, right)
                    || port.conflicts_with_peering(right_router, left)
            }) {
                first_failure.get_or_insert_with(|| {
                    format!(
                        "{} ↔ {} overlaps a FixedInternal guest subnet",
                        pair.left, pair.right,
                    )
                });
                continue;
            }
            ready.insert(pair, (left, left_router, right, right_router));
        }
        self.links.retain(|pair, link| {
            ready
                .get(pair)
                .is_some_and(|(_, left, _, right)| link.connects(left, right))
        });

        for (pair, (left, left_router, right, right_router)) in ready {
            let std::collections::btree_map::Entry::Vacant(entry) = self.links.entry(pair.clone())
            else {
                continue;
            };
            match PeeringLink::open(left, left_router, right, right_router) {
                Ok(link) => {
                    entry.insert(link);
                }
                Err(error) => {
                    first_failure
                        .get_or_insert_with(|| format!("{} ↔ {}: {error}", pair.left, pair.right));
                }
            }
        }
        Ok(first_failure)
    }
}

fn read_policy(path: &Path) -> io::Result<BTreeSet<Pair>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(invalid("peering policy must be a root-owned regular file without group or other write permission"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(invalid("peering policy exceeds 16 KiB"));
    }
    parse_policy(&bytes)
}

fn parse_policy(input: &[u8]) -> io::Result<BTreeSet<Pair>> {
    let policy: Policy = serde_json::from_slice(input).map_err(invalid)?;
    if policy.version != 1 {
        return Err(invalid(
            "unsupported private network peering policy version",
        ));
    }
    let mut pairs = BTreeSet::new();
    for mut pair in policy.allowed_pairs {
        if !valid_id(&pair.left) || !valid_id(&pair.right) || pair.left == pair.right {
            return Err(invalid(
                "peering requires two distinct registered private network IDs",
            ));
        }
        if pair.left > pair.right {
            std::mem::swap(&mut pair.left, &mut pair.right);
        }
        if !pairs.insert(pair) {
            return Err(invalid("duplicate private network pair"));
        }
    }
    Ok(pairs)
}

fn resolve_pairs<'a>(
    requested: &'a BTreeSet<Pair>,
    known: &'a BTreeMap<&str, PeeringNetwork>,
) -> io::Result<BTreeMap<&'a Pair, (&'a PeeringNetwork, &'a PeeringNetwork)>> {
    let mut destinations: BTreeMap<&str, Vec<&PeeringNetwork>> = BTreeMap::new();
    let mut resolved = BTreeMap::new();
    for pair in requested {
        let (Some(left), Some(right)) = (
            known.get(pair.left.as_str()),
            known.get(pair.right.as_str()),
        ) else {
            continue;
        };
        if left.overlaps(right) {
            return Err(invalid(format!(
                "overlapping private networks {} and {}",
                pair.left, pair.right
            )));
        }
        for (network, remote) in [(pair.left.as_str(), right), (pair.right.as_str(), left)] {
            let peers = destinations.entry(network).or_default();
            if peers.iter().any(|prior| prior.overlaps(remote)) {
                return Err(invalid(format!(
                    "ambiguous peering destinations for {network}"
                )));
            }
            peers.push(remote);
        }
        resolved.insert(pair, (left, right));
    }
    Ok(resolved)
}

fn invalid(cause: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, cause)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(pairs: &[(&str, &str)]) -> BTreeSet<Pair> {
        let values: Vec<_> = pairs
            .iter()
            .map(|(left, right)| json!({"left":left,"right":right}))
            .collect();
        parse_policy(&serde_json::to_vec(&json!({"version":1,"allowed_pairs":values})).unwrap())
            .unwrap()
    }

    fn subnet(domain: &str, cidr: &str, first: &str, last: &str) -> PeeringNetwork {
        PeeringNetwork {
            route_domain_id: domain.into(),
            cidr: cidr.into(),
            first: first.parse().unwrap(),
            last: last.parse().unwrap(),
        }
    }

    #[test]
    fn symmetric_grants_wait_for_both_registered_networks() {
        let grant = policy(&[("right", "left")]);
        assert_eq!(grant, policy(&[("left", "right")]));
        let mut networks = BTreeMap::from([(
            "left",
            subnet("left-domain", "10.50.0.0/24", "10.50.0.2", "10.50.0.254"),
        )]);
        assert!(resolve_pairs(&grant, &networks).unwrap().is_empty());
        networks.insert(
            "right",
            subnet("right-domain", "10.51.0.0/24", "10.51.0.2", "10.51.0.254"),
        );
        assert_eq!(resolve_pairs(&grant, &networks).unwrap().len(), 1);
        assert!(resolve_pairs(&policy(&[]), &networks).unwrap().is_empty());
    }

    #[test]
    fn overlapping_peering_and_ambiguous_next_hops_are_invalid_configuration() {
        let networks = BTreeMap::from([
            (
                "left",
                subnet("left-domain", "10.50.0.0/24", "10.50.0.2", "10.50.0.254"),
            ),
            (
                "right",
                subnet("right-domain", "10.51.0.0/24", "10.51.0.2", "10.51.0.254"),
            ),
            (
                "overlap",
                subnet(
                    "other-domain",
                    "10.51.0.128/25",
                    "10.51.0.130",
                    "10.51.0.254",
                ),
            ),
        ]);
        assert!(resolve_pairs(&policy(&[("right", "overlap")]), &networks).is_err());
        assert!(resolve_pairs(
            &policy(&[("left", "right"), ("left", "overlap")]),
            &networks
        )
        .is_err());
    }
}
