//! One bounded free-page balloon round before a pressure-driven Hibernate.
use crate::{
    catalog::Catalog,
    ipc::{Expected, Fault, Result},
    native_control::Endpoint,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::time::Duration;

fn sample() -> Option<u64> {
    let group = crate::worker_scope::cgroup().ok()?;
    std::fs::read_to_string(group.join("memory.current"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub(crate) fn before_hibernate(
    catalog: &Catalog,
    boot: &str,
    expected: &Expected,
    decision: &str,
) -> Result<bool> {
    let Some(incarnation) = expected.incarnation_id.as_deref() else {
        return Ok(false);
    };
    let since: i64 = catalog.db.query_row(
        "SELECT changed_at FROM lifecycle_pressure WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let before = sample();
    let requested = json!({"decision_id":decision,"outcome":"unknown","worker_memory_before_bytes":before,
                          "worker_memory_after_bytes":null,"guest_reported_bytes":null});
    // An unresolved round after a Worker crash still consumes the attempt for
    // this pressure window. The next dispatch rechecks actual pressure.
    if catalog.db.execute(
        "INSERT INTO native_pressure_balloon VALUES(1,?,?,?,?)
         ON CONFLICT(singleton) DO UPDATE SET host_boot_id=excluded.host_boot_id,pressure_since_ms=excluded.pressure_since_ms,
           decision_id=excluded.decision_id,evidence_json=excluded.evidence_json
         WHERE native_pressure_balloon.host_boot_id<>excluded.host_boot_id
            OR native_pressure_balloon.pressure_since_ms<>excluded.pressure_since_ms",
        params![boot,since,decision,requested.to_string()],
    )? == 0 {
        return Ok(false);
    }
    let outcome = Endpoint::load(&catalog.db, incarnation, boot).and_then(|endpoint| {
        endpoint.command_with_timeout("HINT_FREE 600", Duration::from_millis(950))
    });
    let (state, reported, error) = match outcome {
        Ok(reply) => {
            let words: Vec<_> = reply.split_ascii_whitespace().collect();
            let bytes = match words.as_slice() {
                ["hinted", raw, "bytes", "in", _, "ms", ..] => raw.parse::<u64>().ok(),
                _ => None,
            };
            if reply.ends_with("(timed out)") {
                ("timed_out", bytes, None)
            } else if bytes.is_some() {
                ("observed", bytes, None)
            } else {
                (
                    "unknown",
                    None,
                    Some("unrecognized free-page hint receipt".to_string()),
                )
            }
        }
        Err(error) => ("unavailable", None, Some(error.message)),
    };
    let result = json!({"decision_id":decision,"outcome":state,"guest_reported_bytes":reported,
                      "worker_memory_before_bytes":before,"worker_memory_after_bytes":sample(),"error":error});
    catalog.db.execute(
        "UPDATE native_pressure_balloon SET evidence_json=? WHERE decision_id=?",
        params![result.to_string(), decision],
    )?;
    Ok(true)
}

pub(crate) fn latest(db: &Connection) -> Result<Option<Value>> {
    let value: Option<String> = db
        .query_row(
            "SELECT evidence_json FROM native_pressure_balloon WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|text| serde_json::from_str(&text).map_err(|error| Fault::invalid(error.to_string())))
        .transpose()
}
