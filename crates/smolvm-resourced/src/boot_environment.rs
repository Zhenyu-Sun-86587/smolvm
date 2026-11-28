//! Metadata for a private, short-lived managed System boot delivery.
use crate::catalog::{Catalog, Execution, Operation};
use crate::ipc::{Fault, Request, Result, valid_digest};
use crate::native_client::ExecutionRef;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const GUEST_PORT: u32 = 610;
pub const MAX_VALUES_BYTES: usize = 256 << 10;
pub const MAX_WIRE_BYTES: usize = 2 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub catalog: i64,
    pub machine: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub revision: Revision,
    pub expires_ms: i64,
    pub commitment: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub revision: Revision,
    pub execution: ExecutionRef,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub revision: Revision,
    pub values: BTreeMap<String, String>,
}

pub fn wall_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_millis() as i64)
        .unwrap_or(0)
}

impl Attempt {
    pub fn expired(&self) -> bool {
        wall_ms() >= self.expires_ms
    }

    fn validate_new(&self) -> Result<()> {
        if self.revision.catalog < 0
            || self.revision.machine < 1
            || !valid_digest(&self.commitment)
            || self.expired()
            || self.expires_ms > wall_ms() + 10 * 60 * 1000
        {
            return Err(Fault::invalid(
                "invalid or expired boot environment attempt",
            ));
        }
        Ok(())
    }
}

pub fn matches(attempt: &Attempt, nonce: &str, values: &BTreeMap<String, String>) -> bool {
    let mut salt = [0u8; 32];
    if hex::decode_to_slice(nonce, &mut salt).is_err() || values.is_empty() {
        return false;
    }
    let mut total = 0;
    let mut digest = Sha256::new();
    digest.update(salt);
    for (key, value) in values {
        let mut name = key.bytes();
        if !name
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            || !name.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || key.len() > 128
            || key.starts_with("SANDBOX_GUEST_")
            || value.len() > 32 << 10
            || value.contains('\0')
        {
            return false;
        }
        total += key.len() + value.len() + 2;
        if total > MAX_VALUES_BYTES {
            return false;
        }
        for bytes in [key.as_bytes(), value.as_bytes()] {
            digest.update((bytes.len() as u32).to_be_bytes());
            digest.update(bytes);
        }
    }
    attempt.commitment == format!("sha256:{:x}", digest.finalize())
}

pub(crate) fn record(db: &Connection, id: &str, attempt: &Attempt) -> Result<()> {
    attempt.validate_new()?;
    db.execute("INSERT INTO boot_environment_attempts(operation_id,catalog_revision,machine_revision,expires_ms,commitment)
        VALUES(?,?,?,?,?)", params![id,attempt.revision.catalog,attempt.revision.machine,attempt.expires_ms,attempt.commitment])?;
    Ok(())
}

fn read(db: &Connection, id: &str) -> Result<Option<(Attempt, bool)>> {
    Ok(db
        .query_row(
            "SELECT catalog_revision,machine_revision,expires_ms,commitment,applied
        FROM boot_environment_attempts WHERE operation_id=?",
            [id],
            |row| {
                Ok((
                    Attempt {
                        revision: Revision {
                            catalog: row.get(0)?,
                            machine: row.get(1)?,
                        },
                        expires_ms: row.get(2)?,
                        commitment: row.get(3)?,
                    },
                    row.get(4)?,
                ))
            },
        )
        .optional()?)
}

pub(crate) fn attempt(db: &Connection, id: &str) -> Result<Option<Attempt>> {
    Ok(read(db, id)?.map(|(attempt, _)| attempt))
}

pub(crate) fn require_applied(db: &Connection, id: &str) -> Result<()> {
    if read(db, id)?.is_some_and(|(_, applied)| !applied) {
        return Err(Fault::new(
            "E_FENCE_UNPROVEN",
            "System boot environment is not confirmed",
        ));
    }
    Ok(())
}

pub(crate) fn receipt(db: &Connection, op: &Operation) -> Result<Option<Proof>> {
    let Some(execution) = op.execution.as_ref() else {
        return Ok(None);
    };
    Ok(read(db, &op.operation_id)?
        .filter(|(_, applied)| *applied)
        .map(|(attempt, _)| Proof {
            revision: attempt.revision,
            execution: execution.clone(),
        }))
}

pub(crate) fn acknowledge(
    catalog: &Catalog,
    request: &Request,
    execution: &Execution,
) -> Result<()> {
    let op = catalog.matching_operation(request)?;
    let (route, bundle, expected) = request.scope()?;
    let revision: Revision = request.payload()?;
    let Some((attempt, applied)) = read(&catalog.db, &op.operation_id)? else {
        return Err(Fault::invalid(
            "launch does not accept a boot environment acknowledgement",
        ));
    };
    if op.kind != "launch"
        || !execution.matches(route, bundle, expected)
        || execution.last_operation_id != op.operation_id
        || attempt.revision != revision
        || (!applied && attempt.expired())
    {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "boot environment acknowledgement does not match the active launch",
        ));
    }
    if applied && op.phase == "COMPLETED" {
        return Ok(());
    }
    catalog.active_operation(request)?;
    catalog.db.execute(
        "UPDATE boot_environment_attempts SET applied=1 WHERE operation_id=?",
        [&op.operation_id],
    )?;
    Ok(())
}
