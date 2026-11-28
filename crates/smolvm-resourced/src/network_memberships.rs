//! Durable network labels and the Worker-side policy shared by forwarding and DNS.

use crate::catalog::Catalog;
use crate::ipc::{Fault, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Membership {
    pub policy_revision: i64,
    pub networks: Vec<String>,
}

impl Default for Membership {
    fn default() -> Self {
        Self {
            policy_revision: 1,
            networks: Vec::new(),
        }
    }
}

impl Membership {
    fn valid(&self) -> bool {
        self.policy_revision >= 1
            && (self.policy_revision > 1 || self.networks.is_empty())
            && self.networks.len() <= 32
            && self.networks.windows(2).all(|pair| pair[0] < pair[1])
            && self.networks.iter().all(|label| {
                let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
                let bytes = label.as_bytes();
                (1..=63).contains(&bytes.len())
                    && alnum(bytes[0])
                    && alnum(bytes[bytes.len() - 1])
                    && bytes.iter().all(|b| alnum(*b) || *b == b'-')
            })
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.networks.is_empty() && other.networks.is_empty()
            || self
                .networks
                .iter()
                .any(|label| other.networks.binary_search(label).is_ok())
    }
}

pub(crate) fn lookup(db: &Connection, instance: &str) -> rusqlite::Result<Membership> {
    db.query_row(
        "SELECT policy_revision, networks FROM network_memberships WHERE instance_id=?",
        [instance],
        |row| from_json(row.get(0)?, &row.get::<_, String>(1)?),
    )
    .optional()
    .map(Option::unwrap_or_default)
}

fn from_json(revision: i64, raw: &str) -> rusqlite::Result<Membership> {
    let parse = || {
        let membership = Membership {
            policy_revision: revision,
            networks: serde_json::from_str(raw)?,
        };
        Ok::<_, serde_json::Error>(membership)
    };
    let membership = parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(error))
    })?;
    if membership.valid() {
        Ok(membership)
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

pub(crate) fn allowed(db: &Connection, source: &str, target: &str) -> rusqlite::Result<bool> {
    if source == target {
        return Ok(true);
    }
    // The caller may hold a read-only connection shared with another thread's
    // mutation. Read both labels in a single SQLite statement.
    let (left_revision, left, right_revision, right) = db.query_row(
        "SELECT coalesce(l.policy_revision,1),coalesce(l.networks,'[]'),
                coalesce(r.policy_revision,1),coalesce(r.networks,'[]')
         FROM (SELECT 1) LEFT JOIN network_memberships l ON l.instance_id=?1
                         LEFT JOIN network_memberships r ON r.instance_id=?2",
        [source, target],
        |row| {
            Ok((
                row.get(0)?,
                row.get::<_, String>(1)?,
                row.get(2)?,
                row.get::<_, String>(3)?,
            ))
        },
    )?;
    Ok(from_json(left_revision, &left)?.overlaps(&from_json(right_revision, &right)?))
}

pub(crate) fn allowed_attachments(
    db: &Connection,
    left: &str,
    right: &str,
) -> rusqlite::Result<bool> {
    let pair = db
        .query_row(
            "SELECT l.instance_id,r.instance_id FROM network_attachments l, network_attachments r
         WHERE l.attachment_id=?1 AND r.attachment_id=?2 AND l.network_id=r.network_id
               AND l.state='reserved' AND r.state='reserved'",
            [left, right],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    match pair {
        Some((left, right)) => allowed(db, &left, &right),
        None => Ok(false),
    }
}

impl Catalog {
    pub(crate) fn check_network_membership(
        &self,
        instance: &str,
        desired: &Membership,
    ) -> Result<bool> {
        if !desired.valid() {
            return Err(Fault::invalid(
                "invalid network label set or policy revision",
            ));
        }
        let current = lookup(&self.db, instance)?;
        if desired == &current {
            return Ok(false);
        }
        if desired.policy_revision <= current.policy_revision {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "network policy revision changed",
            ));
        }
        Ok(true)
    }

    pub(crate) fn save_network_membership(
        &self,
        instance: &str,
        desired: &Membership,
    ) -> Result<()> {
        let raw = serde_json::to_string(&desired.networks)
            .map_err(|_| Fault::invalid("invalid network labels"))?;
        self.db.execute(
            "INSERT INTO network_memberships(instance_id,policy_revision,networks)
             VALUES(?1,?2,?3) ON CONFLICT(instance_id) DO UPDATE SET
             policy_revision=excluded.policy_revision,networks=excluded.networks",
            params![instance, desired.policy_revision, raw],
        )?;
        Ok(())
    }
}

pub(crate) struct Endpoint {
    instance: String,
    address: Ipv4Addr,
    membership: Membership,
}

pub(crate) fn endpoints(db: &Connection) -> rusqlite::Result<BTreeMap<String, Vec<Endpoint>>> {
    let mut query = db.prepare(
        "SELECT a.network_id,a.instance_id,a.private_ipv4,
                coalesce(m.policy_revision,1),coalesce(m.networks,'[]')
         FROM network_attachments a LEFT JOIN network_memberships m USING(instance_id)
         WHERE a.state='reserved' ORDER BY a.network_id,a.private_ipv4",
    )?;
    let rows = query.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            Endpoint {
                instance: row.get(1)?,
                address: Ipv4Addr::from(row.get::<_, u32>(2)?),
                membership: from_json(row.get(3)?, &row.get::<_, String>(4)?)?,
            },
        ))
    })?;
    let mut groups = BTreeMap::<_, Vec<_>>::new();
    for row in rows {
        let (network, endpoint) = row?;
        groups.entry(network).or_default().push(endpoint);
    }
    Ok(groups)
}

pub(crate) fn allowed_pairs(left: &[Endpoint], right: &[Endpoint]) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let mut result = Vec::new();
    for source in left {
        for target in right {
            if source.instance == target.instance || source.membership.overlaps(&target.membership)
            {
                result.push((source.address, target.address));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_and_defaults_use_the_same_symmetric_policy() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("schema_network_memberships.sql"))
            .unwrap();
        let rows = [
            ("red", r#"["red"]"#),
            ("red-blue", r#"["blue","red"]"#),
            ("blue", r#"["blue"]"#),
        ];
        for (instance, networks) in rows {
            db.execute(
                "INSERT INTO network_memberships VALUES(?,2,?)",
                [instance, networks],
            )
            .unwrap();
        }
        assert!(allowed(&db, "default", "other-default").unwrap());
        assert!(!allowed(&db, "default", "blue").unwrap());
        assert!(allowed(&db, "red", "red-blue").unwrap());
        assert!(allowed(&db, "red-blue", "blue").unwrap());
        assert!(!allowed(&db, "red", "blue").unwrap());
        db.execute("UPDATE network_memberships SET networks='[]',policy_revision=3 WHERE instance_id='red'", []).unwrap();
        assert!(!allowed(&db, "red", "red-blue").unwrap());
        assert!(allowed(&db, "red", "default").unwrap());
    }
}
