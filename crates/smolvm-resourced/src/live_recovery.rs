//! Recover native descriptor authority through the still-running VMM endpoint.

use super::Worker;
use crate::catalog::{Execution, Operation};
use crate::escrow_catalog::{self, LeaseRecord};
use crate::grants::{self, WriterGrant};
use crate::ipc::{self, Expected, Fault, FdEntry, Request, Result};
use crate::native_control::Endpoint;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

#[path = "durable_reader_recovery.rs"]
mod durable_reader_recovery;

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
    fn recover_network(&mut self, execution: &Execution, attachment: &str) -> Result<()> {
        let lease = self.catalog.tap_lease(attachment)?;
        let evidence = self.catalog.recoverable_network_proof(&lease, execution)?;
        let held_migration = self.catalog.has_migration_source_gate(&lease)?;
        self.verify_live_execution(execution)?;
        let endpoint = Endpoint::load(&self.catalog.db, &execution.incarnation_id, &self.boot)?;
        let inventory = endpoint.inventory()?;
        let mut devices = inventory.devices.iter().filter(|dev| dev["virtio_type"] == 1);
        let uplink = json!({
            "device_id": lease.attachment.device_id,
            "attachment": lease.attachment_digest()?,
            "mac": lease.attachment.mac,
        });
        let original_guest = devices.next().is_some_and(|device| {
            device["device_id"] == lease.attachment.device_id && device["tap"][0] == uplink
        }) && devices.next().is_none();
        let settled = match inventory.source_disposition.as_str() {
            "RUNNING" => matches!(
                inventory.guest_gate.as_str(),
                "idle" | "released" | "aborted" | "expired_thawed" | "failed_thawed"
            ),
            "STANDBY" => inventory.guest_gate == "parked",
            "HELD" if held_migration => inventory.guest_gate == "parked",
            _ => false,
        };
        if !original_guest || !settled {
            return Err(grants::fence_unproven(
                "live VMM did not attest the published TAP and guest gate",
            ));
        }
        let pidfd = self.executions.get(&execution.incarnation_id).ok_or_else(|| {
            grants::fence_unproven("live VMM has no verified process handle")
        })?;
        let (router, port) =
            self.network.recover_port(&self.catalog, execution, &lease, &evidence, pidfd.as_fd(), held_migration)?;
        self.verify_live_execution(execution)?;
        self.network.adopt_recovered_port(&mut self.catalog, &lease, router, port, held_migration)
    }

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
        let capture: Option<String> = self.catalog.db.query_row(
            "SELECT capture_id FROM statepoint_restore_leases WHERE lease_id=?",
            [&lease.lease_id],
            |row| row.get(0),
        ).optional()?;
        if let Some(capture) = capture {
            return self.recover_statepoint_reader(execution, lease, &capture);
        }
        if self.catalog.has_managed_block(&lease.resource_id)? {
            return self.recover_block_reader(execution, lease);
        }
        if self.catalog.resource(&lease.resource_id)?["durability"] != "volatile" {
            return Err(grants::fence_unproven("unrecognized durable reader lease"));
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
        // A PID from an earlier host boot can never identify a live provider.
        // Finalization still has to acquire the recorded writer locks and fence
        // its other resources before dropping the execution's ownership.
        let previous_boot = {
            let mut query = self.catalog.db.prepare(
                "SELECT e.incarnation_id FROM executions e
                 WHERE e.phase='unknown' AND e.host_boot_id<>? AND (
                    EXISTS (SELECT 1 FROM native_endpoints n WHERE n.incarnation_id=e.incarnation_id)
                    OR EXISTS (SELECT 1 FROM managed_launches m JOIN operations o USING(operation_id)
                        WHERE m.incarnation_id=e.incarnation_id AND m.operation_id=e.last_operation_id
                          AND o.instance_id=e.instance_id AND o.route_id=e.route_id
                          AND o.bundle_digest=e.bundle_digest AND o.expected_execution_epoch+1=e.execution_epoch))",
            )?;
            let rows = query.query_map([&self.boot], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for incarnation in previous_boot {
            let execution = self.catalog.execution(&incarnation)?;
            if let Err(error) = self.finalize_scoped_execution(execution) {
                eprintln!("native recovery of previous-boot execution {incarnation}: {error}");
            }
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
        let attachments = pending(&self.catalog.db, "SELECT e.incarnation_id,t.attachment_id
            FROM network_tap_leases t JOIN executions e USING(incarnation_id)
            JOIN network_kernel_receipts k USING(lease_id)
            WHERE t.state='unknown' AND t.host_boot_id=e.host_boot_id AND t.execution_epoch=e.execution_epoch
              AND t.host_boot_id=(SELECT host_boot_id FROM worker_state)
              AND e.phase IN ('registered','exited')")?;
        let mut retired = false;
        for (incarnation, attachment) in attachments {
            let execution = self.catalog.execution(&incarnation)?;
            let attempt = if execution.phase == "exited" {
                let lease = self.catalog.tap_lease(&attachment)?;
                retired = true;
                self.network.retire_absent_port(&self.catalog, &lease)
            } else {
                self.recover_network(&execution, &attachment)
            };
            if let Err(error) = attempt {
                eprintln!("native network recovery of attachment {attachment}: {error}");
            }
        }
        if retired {
            self.network.cleanup_namespace_pins(&self.catalog)?;
        }
        if !self.catalog.can_complete_managed_recovery()? {
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
