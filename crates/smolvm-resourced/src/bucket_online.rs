//! Cut complete immutable writer sets before sending them to the local Bucket broker.
use crate::catalog::{Catalog, Operation, binding};
use crate::ipc::{Expected, Fault, PROTOCOL, Request, Result, valid_digest, valid_id};
use crate::managed::{self, DiskSet};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configure {
    attempt_id: String,
    #[serde(default)]
    backend: String,
    #[serde(default)]
    sync: bool,
}

#[derive(Debug)]
struct Attempt {
    id: String,
    expected: Expected,
    bundle: String,
    target: String,
    phase: String,
    generations: Vec<String>,
    remote: Option<Value>,
    receipt: Option<Value>,
}

fn unavailable(message: impl ToString) -> Fault {
    Fault::new("E_BUCKET_STORAGE_UNAVAILABLE", message.to_string())
}

fn stale() -> Fault {
    Fault::new("E_STALE_EXECUTION", "Bucket writer execution changed")
}

fn decode<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T> {
    serde_json::from_str(raw).map_err(unavailable)
}

fn get(catalog: &Catalog, id: &str) -> Result<Option<Attempt>> {
    let row = catalog
        .db
        .query_row(
            "SELECT expected_json,bundle_digest,target,phase,generation_ids,remote_commit,receipt
         FROM bucket_storage_attempts WHERE attempt_id=?",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(expected, bundle, target, phase, generations, remote, receipt)| {
            Ok(Attempt {
                id: id.into(),
                expected: decode(&expected)?,
                bundle,
                target,
                phase,
                generations: generations
                    .map(|raw| decode(&raw))
                    .transpose()?
                    .unwrap_or_default(),
                remote: remote.map(|raw| decode(&raw)).transpose()?,
                receipt: receipt.map(|raw| decode(&raw)).transpose()?,
            })
        },
    )
    .transpose()
}

fn state(catalog: &Catalog, instance: &str, bundle: &str) -> Result<(String, Option<Value>)> {
    let row = catalog.db.query_row(
        "SELECT backend,remote_commit FROM bucket_machine_storage WHERE instance_id=? AND bundle_digest=?",
        [instance,bundle], |row| Ok((row.get::<_,String>(0)?,row.get::<_,Option<String>>(1)?)),
    ).optional()?;
    match row {
        Some((backend, remote)) => Ok((backend, remote.map(|raw| decode(&raw)).transpose()?)),
        None => Ok(("file".into(), None)),
    }
}

fn project(backend: &str, remote: Option<&Value>, status: &str, attempt: Option<&str>) -> Value {
    let unsynced = matches!(status, "pending" | "unsynced");
    let mut output = json!({"backend":backend,"status":status,"unsynced":unsynced,
        "durability":if backend=="bucket" && remote.is_some() && !unsynced {"remote_committed"} else {"local_fsync"}});
    if let Some(id) = attempt {
        output["attempt_id"] = json!(id);
    }
    if let Some(remote) = remote {
        let mut reference = remote.clone();
        if let Some(commit) = reference
            .as_object_mut()
            .and_then(|fields| fields.remove("remote_committed_at"))
        {
            output["last_remote_commit"] = commit;
        }
        output["closure_digest"] = reference["closure_digest"].clone();
        output["remote_ref"] = reference;
    }
    output
}

fn active(catalog: &Catalog, instance: &str, bundle: &str) -> Result<Option<String>> {
    Ok(catalog
        .db
        .query_row(
            "SELECT attempt_id FROM bucket_storage_attempts WHERE instance_id=? AND bundle_digest=?
         AND target<>'automatic' AND phase NOT IN ('ready','failed')",
            [instance, bundle],
            |row| row.get(0),
        )
        .optional()?)
}

fn exact(
    catalog: &Catalog,
    bundle: &str,
    expected: &Expected,
) -> Result<(Option<String>, Option<String>)> {
    let (epoch, incarnation, operation) = binding(&catalog.db, "deep", &expected.instance_id)?;
    if epoch != expected.execution_epoch || incarnation != expected.incarnation_id {
        return Err(stale());
    }
    if let Some(id) = &incarnation {
        let live = catalog.execution(id)?;
        if !live.matches("deep", bundle, expected) || live.phase != "registered" {
            return Err(stale());
        }
    } else {
        let belongs: bool = catalog.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE route_id='deep' AND instance_id=?
             AND bundle_digest=? AND execution_epoch=? AND phase='exited')",
            params![expected.instance_id, bundle, epoch],
            |row| row.get(0),
        )?;
        if !belongs {
            return Err(stale());
        }
    }
    Ok((incarnation, operation))
}

fn cut_id(id: &str, activation: bool) -> String {
    managed::key(
        id,
        if activation {
            "bucket-attach"
        } else {
            "bucket-cut"
        },
        0,
    )
}

fn pin_id(id: &str) -> String {
    managed::key(id, "bucket-pin", 0)
}

fn snapshot_request(attempt: &Attempt, activation: bool) -> Request {
    let id = cut_id(&attempt.id, activation);
    let digest = format!("sha256:{:x}", Sha256::digest(id.as_bytes()));
    Request {
        protocol: PROTOCOL.into(),
        method: "ManagedStatePoint".into(),
        request_id: "bucket-cut".into(),
        route_id: Some("deep".into()),
        bundle_digest: Some(attempt.bundle.clone()),
        operation_id: Some(id),
        request_digest: Some(digest),
        expected: Some(attempt.expected.clone()),
        fd_table: vec![],
        payload: Value::Null,
    }
}

fn cut(
    catalog: &mut Catalog,
    boot: &str,
    attempt: &Attempt,
    activation: bool,
) -> Result<Option<Vec<String>>> {
    let request = snapshot_request(attempt, activation);
    let (_, current) = exact(catalog, &attempt.bundle, &attempt.expected)?;
    if current
        .as_deref()
        .is_some_and(|id| Some(id) != request.operation_id.as_deref())
    {
        return Err(Fault::new(
            "E_OPERATION_ACTIVE",
            "another operation holds the Bucket writer",
        ));
    }
    let op = crate::managed_fork::submit(
        catalog,
        boot,
        &request,
        "vm_snapshot",
        crate::managed_fork::Input {
            children: vec![],
            capture_id: None,
            mode: None,
            admission: None,
            memory_fork_backend: None,
        },
    )?;
    match op.phase.as_str() {
        "COMPLETED" => {
            let capture =
                catalog.require_statepoint(&managed::key(&op.operation_id, "point", 0))?;
            Ok(Some(capture.point.disk_generations))
        }
        "ABORTED" => Err(Fault::new(
            "E_STATE_CONFLICT",
            "Bucket could not capture the complete writer set",
        )),
        _ => Ok(None),
    }
}

fn finish(catalog: &mut Catalog, attempt: &Attempt, ok: bool) -> Result<()> {
    let (original, last) = state(catalog, &attempt.expected.instance_id, &attempt.bundle)?;
    let backend = if !ok || matches!(attempt.target.as_str(), "sync" | "automatic") {
        original.as_str()
    } else {
        &attempt.target
    };
    let remote = if ok {
        attempt.remote.as_ref().or(last.as_ref())
    } else {
        last.as_ref()
    };
    let receipt = project(
        backend,
        remote,
        if ok { "ready" } else { "failed" },
        Some(&attempt.id),
    );
    let tx = catalog.db.transaction()?;
    if ok {
        tx.execute(
            "INSERT INTO bucket_machine_storage VALUES(?,?,?,?) ON CONFLICT(instance_id,bundle_digest)
             DO UPDATE SET backend=excluded.backend,remote_commit=excluded.remote_commit",
            params![attempt.expected.instance_id,attempt.bundle,backend,remote.map(Value::to_string)],
        )?;
    }
    tx.execute(
        "UPDATE bucket_storage_attempts SET phase=?,receipt=? WHERE attempt_id=?",
        params![
            if ok { "ready" } else { "failed" },
            receipt.to_string(),
            attempt.id
        ],
    )?;
    release_pin(&tx, &attempt.id)?;
    tx.commit()?;
    for activation in [false, true] {
        let cut = cut_id(&attempt.id, activation);
        if let Some(record) = catalog.statepoint(&managed::key(&cut, "point", 0))? {
            if let Some(digest) = record.manifest_digest.as_deref() {
                // These captures exist solely to cut the live disks and are
                // never exposed as restore points to the platform.
                if let Err(error) = crate::statepoint_catalog::release_root(
                    catalog, &record, Some("deep"), Some(&attempt.bundle), digest,
                ) {
                    eprintln!("Bucket internal cut {cut} still retained: {}", error.message);
                }
            }
        }
    }
    Ok(())
}

fn release_pin(tx: &rusqlite::Transaction<'_>, attempt: &str) -> Result<()> {
    let pin = pin_id(attempt);
    tx.execute("UPDATE root_refs SET state='dropped',revision=revision+1 WHERE owner_kind='backup' AND owner_id=? AND state='active'",[&pin])?;
    tx.execute(
        "UPDATE native_backup_exports SET phase='released' WHERE backup_id=? AND phase='pinned'",
        [&pin],
    )?;
    Ok(())
}

fn commit(catalog: &mut Catalog, objects: &File, id: &str, response: Value) -> Result<()> {
    let Some(attempt) = get(catalog, id)?.filter(|a| a.phase == "upload") else {
        return Ok(());
    };
    let remote = response
        .get("commit")
        .filter(|value| {
            value["closure_digest"].as_str().is_some_and(valid_digest)
                && value["bundle_digest"] == attempt.bundle
                && value["reader_id"]
                    .as_str()
                    .is_some_and(|reader| !reader.is_empty())
                && value["disk_generations"] == json!(attempt.generations)
                && value["remote_committed_at"].as_str().is_some()
        })
        .ok_or_else(|| unavailable("Bucket commit differs from the admitted closure"))?;
    let mut layers = BTreeMap::new();
    for generation in &attempt.generations {
        for layer in catalog.block_closure(generation)? {
            layers.insert(layer.spec.resource_id.clone(), layer);
        }
    }
    let tx = catalog.db.transaction()?;
    for base in response["bases"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let id = base["generation_id"]
            .as_str()
            .and_then(|id| layers.get(id).map(|layer| (id, layer)))
            .ok_or_else(|| unavailable("Bucket index is outside the sealed closure"))?;
        let bytes = i64::try_from(
            crate::blocks::open_object(objects, id.1, false)?
                .metadata()
                .map_err(unavailable)?
                .len(),
        )
        .map_err(unavailable)?;
        if id.1.spec.mutable()
            || base["member_bytes"] != bytes
            || bytes <= 0
            || base["closure_digest"] != remote["closure_digest"]
            || !base["manifest_digest"].as_str().is_some_and(valid_digest)
            || !base["member_digest"].as_str().is_some_and(valid_digest)
        {
            return Err(unavailable("Bucket index differs from its sealed identity"));
        }
        let reference = json!({"generation_id":id.0,"closure_digest":base["closure_digest"],
            "manifest_digest":base["manifest_digest"]});
        tx.execute(
            "INSERT INTO bucket_online_bases VALUES(?,?,?,?) ON CONFLICT DO NOTHING",
            params![id.0, attempt.bundle, reference.to_string(), bytes],
        )?;
    }
    for id in layers.keys() {
        let indexed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM bucket_online_bases WHERE resource_id=? AND bundle_digest=?)",
            params![id,attempt.bundle],|row|row.get(0))?;
        if !indexed {
            return Err(unavailable(
                "Bucket commit lacks a sealed block range index",
            ));
        }
    }
    if attempt.target == "automatic" {
        tx.execute("UPDATE bucket_machine_storage SET remote_commit=? WHERE instance_id=? AND bundle_digest=? AND backend='bucket'",
            params![remote.to_string(),attempt.expected.instance_id,attempt.bundle])?;
        tx.execute(
            "UPDATE bucket_storage_attempts SET phase='ready',remote_commit=? WHERE attempt_id=?",
            params![remote.to_string(), attempt.id],
        )?;
        release_pin(&tx, &attempt.id)?;
    } else {
        tx.execute("UPDATE bucket_storage_attempts SET phase='activate',remote_commit=? WHERE attempt_id=?",
            params![remote.to_string(),attempt.id])?;
    }
    tx.commit()?;
    Ok(())
}

pub(crate) fn require_capture_commit(
    catalog: &Catalog,
    op: &Operation,
    record: &crate::statepoint_catalog::Record,
) -> Result<bool> {
    require_commit(catalog, op, &record.point.disk_generations)
}

pub(crate) fn require_commit(
    catalog: &Catalog,
    op: &Operation,
    generations: &[String],
) -> Result<bool> {
    if state(catalog, &op.instance_id, &op.bundle_digest)?.0 != "bucket" {
        return Ok(true);
    }
    let explicit: bool = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM bucket_storage_attempts WHERE instance_id=? AND bundle_digest=?
          AND target<>'automatic' AND phase NOT IN ('ready','failed'))",
        params![op.instance_id,op.bundle_digest],|row|row.get(0))?;
    // The explicit operation uploads its own first cut and only uses its
    // second cut to install ranges. These are ordinary managed snapshot IDs.
    if explicit {
        if let Some(id) = active(catalog, &op.instance_id, &op.bundle_digest)? {
            if op.operation_id == cut_id(&id, false) || op.operation_id == cut_id(&id, true) {
                return Ok(true);
            }
        }
    }
    let id = managed::key(&op.operation_id, "bucket-boundary", 0);
    if let Some(prior) = get(catalog, &id)? {
        if prior.generations != generations {
            return Err(unavailable("capture changed its immutable Bucket disk set"));
        }
        return Ok(prior.phase == "ready");
    }
    let expected = Expected {
        instance_id: op.instance_id.clone(),
        incarnation_id: op.expected_incarnation_id.clone(),
        execution_epoch: op.expected_execution_epoch,
    };
    catalog.db.execute("INSERT INTO bucket_storage_attempts
        (attempt_id,instance_id,bundle_digest,expected_json,target,phase,generation_ids) VALUES(?,?,?,?,'automatic','upload',?)",
        params![id,op.instance_id,op.bundle_digest,json!(expected).to_string(),json!(generations).to_string()])?;
    Ok(false)
}

pub(crate) struct Actor {
    socket: Option<PathBuf>,
    active: HashSet<String>,
    tx: mpsc::Sender<(String, Result<Value>)>,
    rx: mpsc::Receiver<(String, Result<Value>)>,
}

impl Actor {
    pub(crate) fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            socket: std::env::var_os("SMOLVM_WORKER_BUCKET_SOCKET").map(PathBuf::from),
            active: HashSet::new(),
            tx,
            rx,
        }
    }

    pub(crate) fn status(&self, catalog: &Catalog, request: &Request, admin: u32) -> Result<Value> {
        let (route, bundle, expected) = request.scope()?;
        if route != "deep" || expected.execution_epoch == 0 {
            return Err(Fault::new(
                "E_CAPABILITY_UNSUPPORTED",
                "Bucket storage needs a managed execution",
            ));
        }
        let mut expected = expected.clone();
        let (epoch, incarnation, _) = binding(&catalog.db, "deep", &expected.instance_id)?;
        if epoch == expected.execution_epoch && incarnation.is_none() {
            expected.incarnation_id = None;
        }
        exact(catalog, bundle, &expected)?;
        let (backend, remote) = state(catalog, &expected.instance_id, bundle)?;
        let pending = active(catalog, &expected.instance_id, bundle)?;
        if backend == "file" && pending.is_none() {
            self.ready(admin)?;
        }
        let status = if pending.is_some() {
            "pending"
        } else if backend == "bucket" && expected.incarnation_id.is_some() {
            "unsynced"
        } else if backend == "bucket" {
            "ready"
        } else {
            "local"
        };
        Ok(project(
            &backend,
            remote.as_ref(),
            status,
            pending.as_deref(),
        ))
    }

    fn ready(&self, admin: u32) -> Result<()> {
        let path = self.socket.as_deref().ok_or_else(|| {
            Fault::new(
                "E_CAPABILITY_UNSUPPORTED",
                "online Bucket broker is not configured",
            )
        })?;
        control(
            path,
            admin,
            json!({"method":"ready"}),
            Duration::from_secs(2),
        )
        .map(|_| ())
        .map_err(|_| {
            Fault::new(
                "E_CAPABILITY_UNSUPPORTED",
                "online Bucket broker is not available",
            )
        })
    }

    pub(crate) fn configure(
        &self,
        catalog: &Catalog,
        request: &Request,
        admin: u32,
    ) -> Result<Value> {
        let (route, bundle, expected) = request.scope()?;
        let input: Configure = request.payload()?;
        let target = match (input.backend.as_str(), input.sync) {
            ("", true) => "sync",
            ("bucket", false) => "bucket",
            ("file", false) => "file",
            _ => return Err(Fault::invalid("invalid Bucket storage command")),
        };
        if route != "deep" || !valid_id(&input.attempt_id) {
            return Err(Fault::invalid(
                "Bucket storage requires a stable attempt and deep route",
            ));
        }
        if let Some(existing) = get(catalog, &input.attempt_id)? {
            if existing.expected != *expected
                || existing.bundle != bundle
                || existing.target != target
            {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "Bucket storage attempt scope changed",
                ));
            }
            if let Some(result) = existing.receipt {
                return Ok(result);
            }
        } else {
            let (incarnation, operation) = exact(catalog, bundle, expected)?;
            let (backend, remote) = state(catalog, &expected.instance_id, bundle)?;
            if operation.is_some() || active(catalog, &expected.instance_id, bundle)?.is_some() {
                return Err(Fault::new(
                    "E_OPERATION_ACTIVE",
                    "another operation holds the Bucket writer",
                ));
            }
            if target == "sync" && backend != "bucket" {
                return Err(Fault::new(
                    "E_STATE_CONFLICT",
                    "only a Bucket writer can be synchronized remotely",
                ));
            }
            let mut ready = None;
            if target == "file" && (backend == "file" || incarnation.is_none()) {
                ready = Some(
                    project("file", remote.as_ref(), "ready", Some(&input.attempt_id)).to_string(),
                );
            } else {
                if target != "file" {
                    self.ready(admin)?;
                }
                if incarnation.is_none() {
                    return Err(Fault::new(
                        "E_CAPABILITY_UNSUPPORTED",
                        "Bucket conversion requires a registered running writer",
                    ));
                }
            }
            let tx = catalog.db.unchecked_transaction()?;
            tx.execute("INSERT INTO bucket_storage_attempts
                (attempt_id,instance_id,bundle_digest,expected_json,target,phase,receipt) VALUES(?,?,?,?,?,?,?)",
                params![input.attempt_id,expected.instance_id,bundle,json!(expected).to_string(),target,
                    if ready.is_some(){"ready"}else if target=="file"{"activate"}else{"capture"},ready])?;
            if let Some(receipt) = ready {
                tx.execute(
                    "INSERT INTO bucket_machine_storage VALUES(?,?,'file',?)
                    ON CONFLICT(instance_id,bundle_digest) DO UPDATE SET backend='file'",
                    params![
                        expected.instance_id,
                        bundle,
                        remote.as_ref().map(Value::to_string)
                    ],
                )?;
                tx.commit()?;
                return decode(&receipt);
            }
            tx.commit()?;
        }
        let (backend, remote) = state(catalog, &expected.instance_id, bundle)?;
        Ok(project(
            &backend,
            remote.as_ref(),
            "pending",
            Some(&input.attempt_id),
        ))
    }

    pub(crate) fn tick(
        &mut self,
        catalog: &mut Catalog,
        objects: &File,
        boot: &str,
        admin: u32,
    ) -> Result<()> {
        while let Ok((id, result)) = self.rx.try_recv() {
            self.active.remove(&id);
            let result = result.and_then(|response| commit(catalog, objects, &id, response));
            if let Err(error) = result {
                eprintln!("Bucket storage attempt {id} will retry: {}", error.message);
                catalog.db.execute(
                    "UPDATE bucket_storage_attempts SET retry_at=unixepoch()+3 WHERE attempt_id=?",
                    [id],
                )?;
            }
        }
        let ids = {
            let mut query = catalog.db.prepare(
                "SELECT attempt_id FROM bucket_storage_attempts
             WHERE phase IN ('capture','upload','activate') AND retry_at<=unixepoch()
             ORDER BY rowid",
            )?;
            let result = query
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            result
        };
        for id in ids {
            let Some(attempt) = get(catalog, &id)? else {
                continue;
            };
            let result = match attempt.phase.as_str() {
                "capture" | "activate" => {
                    match cut(catalog, boot, &attempt, attempt.phase == "activate") {
                        Ok(Some(mut generations)) if attempt.phase == "capture" => {
                            generations.sort();
                            generations.dedup();
                            catalog.db.execute("UPDATE bucket_storage_attempts SET phase='upload',generation_ids=? WHERE attempt_id=?",
                            params![json!(generations).to_string(),id])?;
                            Ok(())
                        }
                        Ok(Some(_)) => finish(catalog, &attempt, true),
                        Ok(None) => Ok(()),
                        Err(error)
                            if matches!(
                                error.code,
                                "E_STALE_EXECUTION"
                                    | "E_STATE_CONFLICT"
                                    | "E_CAPABILITY_UNSUPPORTED"
                            ) =>
                        {
                            eprintln!(
                                "Bucket storage attempt {id} could not complete its writer cut: {}",
                                error.message
                            );
                            finish(catalog, &attempt, false)
                        }
                        Err(error) => Err(error),
                    }
                }
                "upload" => self.upload(catalog, &attempt, admin),
                _ => Ok(()),
            };
            if let Err(error) = result {
                eprintln!("Bucket storage attempt {id} will retry: {}", error.message);
                catalog.db.execute(
                    "UPDATE bucket_storage_attempts SET retry_at=unixepoch()+3 WHERE attempt_id=?",
                    [id],
                )?;
            }
        }
        Ok(())
    }

    fn upload(&mut self, catalog: &Catalog, attempt: &Attempt, admin: u32) -> Result<()> {
        if self.active.contains(&attempt.id) || self.active.len() >= 2 {
            return Ok(());
        }
        let Some(socket) = self.socket.clone() else {
            return Err(unavailable("Bucket broker is not configured"));
        };
        let mut indexed = BTreeSet::new();
        for generation in &attempt.generations {
            for item in catalog.block_closure(generation)? {
                let id = item.spec.resource_id;
                let present:bool=catalog.db.query_row("SELECT EXISTS(SELECT 1 FROM bucket_online_bases WHERE resource_id=? AND bundle_digest=?)",
                    params![id,attempt.bundle],|row|row.get(0))?;
                if present {
                    indexed.insert(id);
                }
            }
        }
        let request = json!({"method":"commit","attempt_id":pin_id(&attempt.id),"bundle_digest":attempt.bundle,
            "generation_ids":attempt.generations,"indexed":indexed});
        let id = attempt.id.clone();
        self.active.insert(id.clone());
        let sender = self.tx.clone();
        thread::spawn(move || {
            let result = control(&socket, admin, request, Duration::from_secs(1800))
                .map(|(_, receipt)| receipt);
            let _ = sender.send((id, result));
        });
        Ok(())
    }

    pub(crate) fn ranges<'a>(
        &self,
        catalog: &Catalog,
        instance: &str,
        bundle: &str,
        operation: &str,
        resources: impl IntoIterator<Item = &'a str>,
        admin: u32,
    ) -> Result<BTreeMap<String, (u64, OwnedFd)>> {
        let mut ranges = BTreeMap::new();
        let Some(socket) = self.socket.as_deref() else {
            return Ok(ranges);
        };
        let (backend, _) = state(catalog, instance, bundle)?;
        let mut remote = backend == "bucket";
        let mut switching = false;
        if let Some(id) = active(catalog, instance, bundle)? {
            if operation == cut_id(&id, true) {
                let attempt = get(catalog, &id)?
                    .ok_or_else(|| unavailable("missing Bucket activation attempt"))?;
                remote = attempt.target != "file";
                switching = remote;
            }
        }
        if !remote {
            return Ok(ranges);
        }
        for id in resources {
            if ranges.contains_key(id) {
                continue;
            }
            let row:Option<(String,i64)>=catalog.db.query_row(
                "SELECT reference_json,member_bytes FROM bucket_online_bases WHERE resource_id=? AND bundle_digest=?",
                params![id,bundle],|row| Ok((row.get(0)?,row.get(1)?))).optional()?;
            if let Some((reference, bytes)) = row {
                let reference: Value = decode(&reference)?;
                match control(
                    socket,
                    admin,
                    json!({"method":"read","base":reference}),
                    Duration::from_secs(2),
                ) {
                    Ok((stream, _)) => {
                        ranges.insert(
                            id.to_owned(),
                            (u64::try_from(bytes).map_err(unavailable)?, stream.into()),
                        );
                    }
                    Err(error) if switching => return Err(error),
                    Err(_) => (),
                }
            }
        }
        Ok(ranges)
    }

    pub(crate) fn launch(
        &self,
        catalog: &Catalog,
        instance: &str,
        bundle: &str,
        operation: &str,
        layouts: &[DiskSet],
        admin: u32,
    ) -> Result<BTreeMap<String, (u64, OwnedFd)>> {
        self.ranges(
            catalog,
            instance,
            bundle,
            operation,
            layouts
                .iter()
                .flat_map(|set| &set.layers)
                .filter(|item| !item.spec.mutable())
                .map(|item| item.spec.resource_id.as_str()),
            admin,
        )
    }
}

fn control(
    path: &Path,
    admin: u32,
    command: Value,
    timeout: Duration,
) -> Result<(UnixStream, Value)> {
    let mut stream = UnixStream::from(crate::bucket_bases::connect(path, admin)?);
    stream
        .set_read_timeout(Some(timeout))
        .map_err(unavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(unavailable)?;
    writeln!(stream, "{command}").map_err(unavailable)?;
    let mut raw = String::new();
    BufReader::new(&mut stream)
        .take(256 << 10)
        .read_line(&mut raw)
        .map_err(unavailable)?;
    if !raw.ends_with('\n') {
        return Err(unavailable("Bucket broker returned an incomplete reply"));
    }
    let result: Value = decode(&raw)?;
    if result["ok"] != true {
        return Err(unavailable(
            result["error"]
                .as_str()
                .unwrap_or("Bucket broker request failed"),
        ));
    }
    stream.set_read_timeout(None).map_err(unavailable)?;
    Ok((stream, result))
}
