//! Recover native descriptor authority through the still-running VMM endpoint.

use super::Worker;
use crate::catalog::{Execution, Operation};
use crate::escrow_catalog::{self, LeaseRecord};
use crate::grants::{self, WriterGrant};
use crate::ipc::{self, Expected, Fault, FdEntry, Request, Result};
use crate::native_control::Endpoint;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;

type Identity = (u64, u64, u64);

fn request(op: &Operation, execution: &Execution, method: &str, payload: Value) -> Request {
    Request {
        protocol: ipc::PROTOCOL.to_owned(),
        method: method.to_owned(),
        request_id: "native-recovery".to_owned(),
        operation_id: Some(op.operation_id.clone()),
        request_digest: Some(op.request_digest.clone()),
        route_id: Some(execution.route_id.clone()),
        bundle_digest: Some(execution.bundle_digest.clone()),
        expected: Some(Expected {
            instance_id: execution.instance_id.clone(),
            incarnation_id: Some(execution.incarnation_id.clone()),
            execution_epoch: execution.execution_epoch,
        }),
        fd_table: Vec::new(),
        payload,
    }
}

fn identity(file: File) -> Result<Identity> {
    let meta = file
        .metadata()
        .map_err(crate::statepoint_capture::host_io)?;
    Ok((meta.dev(), meta.ino(), meta.len()))
}

fn fd_table<'a>(ids: impl IntoIterator<Item = &'a str>, role: &str) -> Vec<FdEntry> {
    ids.into_iter()
        .enumerate()
        .map(|(index, resource)| FdEntry {
            index,
            resource_id: resource.to_owned(),
            role: role.to_owned(),
        })
        .collect()
}

fn pending(db: &Connection, sql: &str) -> Result<Vec<(String, String)>> {
    let mut query = db.prepare(sql)?;
    let rows = query.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

impl Worker {
    fn recover_writer(&mut self, execution: &Execution, grant: &WriterGrant) -> Result<()> {
        let endpoint = Endpoint::load(&self.catalog.db, &execution.incarnation_id, &self.boot)?;
        let set = self
            .catalog
            .writer_set(&grant.operation_id)?
            .ok_or_else(|| grants::fence_unproven("native recovery has no writer reservation"))?;
        let mut backings = Vec::new();
        for head in &set.heads {
            let closure = self.catalog.block_closure(&head.head_resource_id)?;
            backings.push(identity(crate::blocks::open_object(
                &self.objects,
                &closure[0],
                true,
            )?)?);
        }
        let descriptors = endpoint
            .recover_descriptors("writer", &backings)?
            .ok_or_else(|| {
                grants::fence_unproven("live VMM cannot prove its complete writer OFD set")
            })?;
        self.verify_live_execution(execution)?;
        let op = self.catalog.operation(&grant.operation_id)?;
        let mut r = request(
            &op,
            execution,
            "ReconcileWriterSet",
            json!({
                "grant_id":grant.grant_id,"expected_revision":grant.revision
            }),
        );
        r.fd_table = fd_table(
            set.heads.iter().map(|head| head.head_resource_id.as_str()),
            "block_writer",
        );
        self.attach_writer_set(&r, execution, descriptors)?;
        Ok(())
    }

    fn recover_block_reader(&mut self, execution: &Execution, lease: &LeaseRecord) -> Result<()> {
        let endpoint = Endpoint::load(&self.catalog.db, &execution.incarnation_id, &self.boot)?;
        let layers = self.catalog.block_closure(&lease.resource_id)?;
        let mut backings = Vec::new();
        for layer in &layers {
            backings.push(identity(crate::blocks::open_object(
                &self.objects,
                layer,
                false,
            )?)?);
        }
        let descriptors = endpoint
            .recover_descriptors("reader", &backings)?
            .ok_or_else(|| {
                grants::fence_unproven("live VMM cannot prove its complete block reader closure")
            })?;
        self.verify_live_execution(execution)?;
        let op = self.catalog.operation(&lease.operation_id)?;
        let mut r = request(
            &op,
            execution,
            "ReconcileExecutionExports",
            json!({
                "lease_id":lease.lease_id,"expected_revision":lease.revision
            }),
        );
        r.fd_table = fd_table(
            layers.iter().map(|layer| layer.spec.resource_id.as_str()),
            "block_ancestor",
        );
        crate::blocks::reconcile_read(
            &mut self.catalog,
            &self.objects,
            &r,
            execution,
            descriptors,
        )?;
        Ok(())
    }

    fn recover_ram(
        &mut self,
        execution: &Execution,
        resource: &str,
        mut r: Request,
    ) -> Result<bool> {
        let endpoint = Endpoint::load(&self.catalog.db, &execution.incarnation_id, &self.boot)?;
        let identities = self.catalog.backing_identities(resource)?;
        if identities.is_empty() {
            return Err(Fault::new(
                "E_CATALOG",
                "retained RAM has no backing identities",
            ));
        }
        let ordered: Vec<_> = identities.values().copied().collect();
        let Some(descriptors) = endpoint.recover_descriptors("ram", &ordered)? else {
            self.verify_live_execution(execution)?;
            return Ok(false);
        };
        self.verify_live_execution(execution)?;
        let entries: Vec<_> = identities.keys().map(String::as_str).collect();
        let mut files = descriptors.into_iter();
        // Reuse the existing authenticated escrow checks and batch budget.
        for part in entries.chunks(ipc::MAX_FDS) {
            r.fd_table = fd_table(part.iter().copied(), "immutable_backing");
            let current: Vec<OwnedFd> = files.by_ref().take(part.len()).collect();
            self.escrow
                .reexport(&mut self.catalog, &r, execution, current)?;
        }
        Ok(true)
    }

    fn recover_reader(&mut self, execution: &Execution, lease: &LeaseRecord) -> Result<()> {
        if self.catalog.has_managed_block(&lease.resource_id)? {
            return self.recover_block_reader(execution, lease);
        }
        let op = self.catalog.operation(&lease.operation_id)?;
        let r = request(
            &op,
            execution,
            "ReconcileExecutionExports",
            json!({
                "lease_id":lease.lease_id,"expected_revision":lease.revision
            }),
        );
        if !self.recover_ram(execution, &lease.resource_id, r)? {
            self.catalog.update_lease(lease, lease.revision, true)?;
        }
        Ok(())
    }

    fn recover_publisher(&mut self, execution: &Execution, transfer: &str) -> Result<()> {
        let record = self
            .catalog
            .transfer(transfer)?
            .ok_or_else(|| Fault::new("E_CATALOG", "pending RAM transfer is missing"))?;
        let op = self.catalog.operation(&record.operation_id)?;
        let r = request(
            &op,
            execution,
            "ReconcileExecutionExports",
            json!({"transfer_id":transfer}),
        );
        if !self.recover_ram(execution, &record.resource_id, r)? {
            self.catalog.db.execute(
                "INSERT OR IGNORE INTO native_provider_absence VALUES(?,?)",
                params![record.resource_id, execution.incarnation_id],
            )?;
            escrow_catalog::lose_missing_without_provider(&self.catalog.db)?;
        }
        Ok(())
    }

    pub(super) fn recover_live_descriptors(&mut self) -> Result<()> {
        let health = self.catalog.health()?;
        if health["state"] != "recovering" {
            return Ok(());
        }
        self.reconnect_native_endpoints()?;
        let writers = pending(&self.catalog.db, "SELECT e.incarnation_id,g.grant_id
            FROM writer_grants g JOIN executions e USING(incarnation_id) JOIN native_endpoints n USING(incarnation_id)
            WHERE e.phase='registered' AND g.state='unknown' AND g.execution_epoch=e.execution_epoch")?;
        for (incarnation, grant) in writers {
            let e = self.catalog.execution(&incarnation)?;
            let grant = self
                .catalog
                .writer_grant(&grant)?
                .ok_or_else(|| Fault::new("E_CATALOG", "pending native writer grant is missing"))?;
            if let Err(error) = self.recover_writer(&e, &grant) {
                eprintln!("native recovery of writer {}: {error}", grant.grant_id);
            }
        }
        let readers = pending(&self.catalog.db, "SELECT e.incarnation_id,l.lease_id
            FROM fd_leases l JOIN executions e USING(incarnation_id) JOIN native_endpoints n USING(incarnation_id)
            WHERE e.phase='registered' AND l.state='unknown'")?;
        for (incarnation, lease) in readers {
            let e = self.catalog.execution(&incarnation)?;
            let lease = self.catalog.lease(&lease)?;
            if let Err(error) = self.recover_reader(&e, &lease) {
                eprintln!("native recovery of lease {}: {error}", lease.lease_id);
            }
        }
        let publishers = pending(&self.catalog.db, "SELECT e.incarnation_id,t.transfer_id
            FROM fd_transfers t JOIN executions e USING(incarnation_id) JOIN native_endpoints n USING(incarnation_id)
            WHERE e.phase='registered' AND t.state='missing'
              AND EXISTS(SELECT 1 FROM root_refs r WHERE r.owner_kind IN ('operation','fork_capture') AND r.state='active'
                    AND r.owner_id=t.operation_id AND r.resource_id=t.resource_id)
              AND NOT EXISTS(SELECT 1 FROM native_provider_absence a WHERE a.resource_id=t.resource_id AND a.incarnation_id=e.incarnation_id)")?;
        for (incarnation, transfer) in publishers {
            let e = self.catalog.execution(&incarnation)?;
            if let Err(error) = self.recover_publisher(&e, &transfer) {
                eprintln!("native recovery of transfer {transfer}: {error}");
            }
        }
        let confirmed_managed: bool = self.catalog.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM executions e
            JOIN native_endpoints n USING(incarnation_id) WHERE e.phase='registered')",
            [],
            |row| row.get(0),
        )?;
        if !confirmed_managed {
            return Ok(());
        }
        let session = health["broker_session_id"]
            .as_str()
            .ok_or_else(|| Fault::new("E_CATALOG", "native recovery session is missing"))?;
        match self.catalog.complete_recovery(session) {
            Ok(_) => Ok(()),
            Err(error) if error.code == "E_RECOVERING" => Ok(()),
            Err(error) => Err(error),
        }
    }
}
