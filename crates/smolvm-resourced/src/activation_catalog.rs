use crate::catalog::{Catalog, Execution, Operation};
use crate::ipc::{valid_digest, valid_id, Fault, Result};
use crate::network_lease_catalog::{AttachmentDescriptor, TapLease};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivationInput {
    pub capture_resource_id: String,
    pub capture_anchor: String,
    pub profile_digest: String,
    pub helper_digest: String,
    pub network: Option<NetworkInput>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkInput {
    pub source_attachment_id: String,
    pub target_attachment_id: String,
    pub dns_ipv4: Ipv4Addr,
    pub uplink_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ActivationBinding {
    pub input: ActivationInput,
    pub source_capture: SourceCapture,
    pub execution: ExecutionBinding,
    pub network: Option<NetworkBinding>,
    pub writer_set_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ExecutionBinding {
    pub route_id: String,
    pub bundle_digest: String,
    pub operation_id: String,
    pub instance_id: String,
    pub incarnation_id: String,
    pub epoch: i64,
    pub host_boot_id: String,
    pub pid: i32,
    pub pid_start_time: i64,
    pub uid: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct NetworkBinding {
    pub source: BoundTap,
    pub target: BoundTap,
    pub dns_ipv4: Ipv4Addr,
    pub uplink_name: String,
}

impl NetworkBinding {
    pub(crate) fn identity_bytes(&self) -> Result<[u8; 64]> {
        let old = &self.source.attachment;
        let new = &self.target.attachment;
        let mut wire = [0; 64];
        wire[..4].copy_from_slice(b"NET1");
        wire[4] = match new.mode.as_str() {
            "native" => 1,
            "fixed_internal" => 2,
            _ => return Err(Fault::invalid("unknown network profile")),
        };
        wire[5] = old.guest_prefix;
        wire[6] = new.guest_prefix;
        wire[8..14].copy_from_slice(&old.mac);
        wire[14..20].copy_from_slice(&new.mac);
        wire[20..24].copy_from_slice(&old.guest_ipv4.octets());
        wire[24..28].copy_from_slice(&new.guest_ipv4.octets());
        wire[28..32].copy_from_slice(&old.gateway_ipv4.octets());
        wire[32..36].copy_from_slice(&new.gateway_ipv4.octets());
        wire[36..40].copy_from_slice(&self.dns_ipv4.octets());
        let name = self.uplink_name.as_bytes();
        wire[40..40 + name.len()].copy_from_slice(name);
        Ok(wire)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct BoundTap {
    pub attachment: AttachmentDescriptor,
    pub lease_id: String,
    pub lease_revision: i64,
    pub attachment_digest: String,
}

#[derive(PartialEq, Eq)]
struct CaptureOrigin {
    incarnation: String,
    epoch: i64,
    digest: String,
}

fn capture_origin(db: &Connection, resource_id: &str) -> Result<CaptureOrigin> {
    db.query_row(
        "SELECT e.incarnation_id,e.execution_epoch,t.descriptor_digest
        FROM fd_transfers t JOIN executions e USING(incarnation_id) JOIN resources r USING(resource_id)
        WHERE t.resource_id=?1 AND t.state='committed' AND r.kind='descriptor' AND r.state='available' AND r.immutable=1
        UNION ALL
        SELECT e.incarnation_id,e.execution_epoch,p.manifest_digest
        FROM statepoints p JOIN executions e ON e.incarnation_id=p.source_incarnation_id
        JOIN resources r ON r.resource_id=p.representation_id
        WHERE p.representation_id=?1 AND p.phase IN ('durable','stop_committed','hibernated')
          AND r.state='available' AND r.immutable=1 AND r.durability='durable'",
        [resource_id],
        |r| Ok(CaptureOrigin {incarnation:r.get(0)?, epoch:r.get(1)?, digest:r.get(2)?}),
    ).optional()?.ok_or_else(|| Fault::new("E_FENCE_UNPROVEN", "network attestation requires committed immutable capture RAM"))
}

struct CapturedTap {
    origin: CaptureOrigin,
    bound: Option<BoundTap>,
}

fn captured_tap(db: &Connection, resource_id: &str) -> Result<Option<CapturedTap>> {
    let row: Option<(String, i64, String, Option<String>)> = db
        .query_row(
            "SELECT source_incarnation_id,source_execution_epoch,capture_digest,bound_tap_json
        FROM capture_network_attestations WHERE resource_id=?",
            [resource_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    row.map(|(incarnation, epoch, digest, bound)| {
        let bound = bound
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Fault::new("E_CATALOG", "invalid captured TAP attestation"))?;
        Ok(CapturedTap {
            origin: CaptureOrigin {
                incarnation,
                epoch,
                digest,
            },
            bound,
        })
    })
    .transpose()
}

fn tap_fence(reason: &'static str) -> Fault {
    Fault::new("E_FENCE_UNPROVEN", reason)
}

/// Pin the exact Worker network description while the immutable capture and
/// the captured execution's measured TAP are available to the Worker.
pub(crate) fn pin_source_tap(
    catalog: &Catalog,
    resource_id: &str,
    execution: &Execution,
    expects_network: bool,
) -> Result<()> {
    let origin = capture_origin(&catalog.db, resource_id)?;
    pin_capture_tap(catalog, resource_id, origin, execution, expects_network)
}

fn pin_capture_tap(
    catalog: &Catalog,
    resource_id: &str,
    origin: CaptureOrigin,
    execution: &Execution,
    expects_network: bool,
) -> Result<()> {
    if origin.incarnation != execution.incarnation_id || origin.epoch != execution.execution_epoch {
        return Err(tap_fence(
            "capture does not belong to this source execution",
        ));
    }
    if let Some(existing) = captured_tap(&catalog.db, resource_id)? {
        return if existing.origin == origin && existing.bound.is_some() == expects_network {
            Ok(())
        } else {
            Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "captured network attestation changed",
            ))
        };
    }
    if catalog.execution(&origin.incarnation)?.phase != "registered" {
        return Err(tap_fence("capture source is no longer registered"));
    }
    let bound = match (
        catalog.tap_leases_for_execution(execution)?.as_slice(),
        expects_network,
    ) {
        ([], false) => None,
        ([lease], true) if lease.state == "attached" => Some(BoundTap::try_from(lease.clone())?),
        _ => {
            return Err(tap_fence(
                "captured network does not match the source TAP inventory",
            ))
        }
    };
    store_captured_tap(&catalog.db, resource_id, &origin, bound.as_ref())
}

fn store_captured_tap(
    db: &Connection,
    resource_id: &str,
    origin: &CaptureOrigin,
    bound: Option<&BoundTap>,
) -> Result<()> {
    let json = bound
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| Fault::new("E_CATALOG", "cannot encode captured TAP attestation"))?;
    db.execute(
        "INSERT INTO capture_network_attestations VALUES(?,?,?,?,?)",
        params![
            resource_id,
            origin.incarnation,
            origin.epoch,
            origin.digest,
            json
        ],
    )?;
    Ok(())
}

fn statepoint_export_origin(
    db: &Connection,
    record: &crate::statepoint_catalog::Record,
) -> Result<(String, CaptureOrigin)> {
    db.query_row(
        "SELECT p.volatile_id,e.incarnation_id,e.execution_epoch,r.descriptor_digest
        FROM statepoints p JOIN resources r ON r.resource_id=p.volatile_id
        JOIN executions e ON e.incarnation_id=p.source_incarnation_id
        WHERE p.capture_id=?1 AND p.operation_id=?2 AND p.representation_id=?3
          AND p.phase IN ('exporting','durable') AND r.state='available' AND r.immutable=1
          AND r.durability='volatile' AND r.created_by_operation=?2
          AND json_extract(r.descriptor_json,'$.source_ram_digest')=?4
          AND json_extract(r.descriptor_json,'$.checkpoint_digest')=?5",
        params![
            record.export.capture_id,
            record.operation_id,
            record.point.representation_id,
            record.point.source_ram_digest,
            record.point.checkpoint_digest
        ],
        |r| {
            Ok((
                r.get(0)?,
                CaptureOrigin {
                    incarnation: r.get(1)?,
                    epoch: r.get(2)?,
                    digest: r.get(3)?,
                },
            ))
        },
    )
    .optional()?
    .ok_or_else(|| tap_fence("StatePoint volatile capture descriptor changed"))
}

/// Pin the captured network while a StatePoint's source is still held.
pub(crate) fn pin_statepoint_tap(
    catalog: &Catalog,
    record: &crate::statepoint_catalog::Record,
    execution: &Execution,
    expects_network: bool,
) -> Result<()> {
    if record.phase != "exporting" {
        return Err(tap_fence("StatePoint has passed the network capture phase"));
    }
    let (volatile, origin) = statepoint_export_origin(&catalog.db, record)?;
    pin_capture_tap(catalog, &volatile, origin, execution, expects_network)
}

/// Transfer the pinned source evidence inside the StatePoint publish transaction
/// after the immutable representation has been created and before volatile GC.
pub(crate) fn publish_statepoint_tap(
    tx: &Transaction<'_>,
    record: &crate::statepoint_catalog::Record,
    manifest_digest: &str,
) -> Result<()> {
    let (volatile, origin) = statepoint_export_origin(tx, record)?;
    let Some(captured) = captured_tap(tx, &volatile)? else {
        // StatePoints created before this attestation keep the legacy path.
        return Ok(());
    };
    let representation = &record.point.representation_id;
    let durable = capture_origin(tx, representation)?;
    if captured.origin != origin
        || durable.incarnation != origin.incarnation
        || durable.epoch != origin.epoch
        || durable.digest != manifest_digest
        || !valid_digest(manifest_digest)
    {
        return Err(tap_fence(
            "StatePoint capture and durable representation differ",
        ));
    }
    store_captured_tap(tx, representation, &durable, captured.bound.as_ref())
}

/// Construct the SGI2 intent from sealed source provenance and the target's
/// exact attached TAP. A no-network capture requires no target TAP.
pub(crate) fn captured_network_input(
    catalog: &Catalog,
    resource_id: &str,
    target: &Operation,
) -> Result<Option<Value>> {
    let origin = capture_origin(&catalog.db, resource_id)?;
    let source = catalog.execution(&origin.incarnation)?;
    if target.kind != "restore_target"
        || source.route_id != target.route_id
        || source.bundle_digest != target.bundle_digest
    {
        return Err(tap_fence(
            "captured network is outside the target route or bundle",
        ));
    }
    let bound = match captured_tap(&catalog.db, resource_id)? {
        Some(captured) if captured.origin == origin => captured.bound,
        Some(_) => {
            return Err(tap_fence(
                "captured network is outside the immutable source",
            ))
        }
        None => legacy_source_tap(catalog, &source)?,
    };
    let mut query = catalog.db.prepare(
        "SELECT attachment_id FROM network_tap_leases WHERE operation_id=? AND state<>'retired'",
    )?;
    let targets = query
        .query_map([&target.operation_id], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    match (bound, targets.as_slice()) {
        (None, []) => Ok(None),
        (Some(source), [id]) => {
            let tap = catalog.tap_lease(id)?;
            if tap.state != "attached"
                || tap.operation_id != target.operation_id
                || tap.route_id != target.route_id
                || tap.bundle_digest != target.bundle_digest
                || tap.instance_id != target.instance_id
                || tap.incarnation_id.is_none()
                || tap.execution_epoch != target.expected_execution_epoch.checked_add(1)
            {
                return Err(tap_fence(
                    "target TAP is not attached to the expected execution",
                ));
            }
            Ok(Some(serde_json::json!(NetworkInput {
                source_attachment_id: source.attachment.attachment_id,
                target_attachment_id: id.clone(),
                dns_ipv4: tap.attachment.gateway_ipv4,
                uplink_name: "eth0".into(),
            })))
        }
        _ => Err(tap_fence(
            "target TAP inventory differs from the captured network",
        )),
    }
}

fn legacy_source_tap(catalog: &Catalog, source: &Execution) -> Result<Option<BoundTap>> {
    match catalog.tap_leases_for_execution(source)?.as_slice() {
        [lease] if lease.state == "attached" => Ok(Some(BoundTap::try_from(lease.clone())?)),
        [] => {
            let had_port = catalog.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM network_tap_leases WHERE incarnation_id=? AND execution_epoch=?)",
                params![source.incarnation_id, source.execution_epoch],
                |row| row.get::<_, bool>(0),
            )?;
            if had_port {
                return Err(tap_fence(
                    "earlier networked capture lacks its source TAP attestation",
                ));
            }
            Ok(None)
        }
        _ => Err(tap_fence("capture needs its exact source TAP")),
    }
}

impl TryFrom<TapLease> for BoundTap {
    type Error = Fault;

    fn try_from(lease: TapLease) -> Result<Self> {
        Ok(Self {
            attachment_digest: hex::encode(lease.attachment_digest()?),
            attachment: lease.attachment,
            lease_id: lease.lease_id,
            lease_revision: lease.revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SourceCapture {
    descriptor_digest: String,
    incarnation_id: String,
    execution_epoch: i64,
    lease_id: String,
    lease_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ActivationReceipt {
    pub context_digest: String,
    pub challenge: String,
    pub binding: ActivationBinding,
    pub wire_digest: Option<String>,
    pub begin_revision: Option<i64>,
    pub commit_revision: Option<i64>,
    pub phase: String,
    pub decision: String,
    pub revision: i64,
    pub prior_revision: i64,
}

impl ActivationReceipt {
    pub fn matches(&self, execution: &Execution) -> bool {
        let binding = &self.binding.execution;
        binding.route_id == execution.route_id
            && binding.bundle_digest == execution.bundle_digest
            && binding.operation_id == execution.last_operation_id
            && binding.instance_id == execution.instance_id
            && binding.incarnation_id == execution.incarnation_id
            && binding.epoch == execution.execution_epoch
            && binding.host_boot_id == execution.host_boot_id
            && binding.pid == execution.pid
            && binding.pid_start_time == execution.pid_start_time
            && binding.uid == execution.uid
    }
}

pub(crate) fn install(db: &Connection) -> Result<()> {
    db.execute_batch(include_str!("schema_target_activations.sql"))?;
    Ok(())
}

pub(crate) fn recover(db: &Connection) -> Result<()> {
    db.execute(
        "UPDATE target_activations SET phase='unknown', prior_revision=revision, revision=revision+1
         WHERE phase NOT IN ('released','failed_held','unknown')",
        [],
    )?;
    Ok(())
}

pub(crate) fn record_exit(db: &Connection, incarnation: &str) -> Result<()> {
    db.execute(
        "UPDATE target_activations SET phase='failed_held', prior_revision=revision, revision=revision+1
         WHERE incarnation_id=? AND phase NOT IN ('released','failed_held')",
        [incarnation],
    )?;
    Ok(())
}

pub(crate) fn fixed_hex<const LEN: usize>(value: &str) -> Result<[u8; LEN]> {
    let mut bytes = [0; LEN];
    if hex::decode_to_slice(value, &mut bytes).is_err() || bytes == [0; LEN] {
        return Err(Fault::invalid(
            "invalid nonzero fixed-width identity binding",
        ));
    }
    Ok(bytes)
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| Fault::invalid("invalid activation binding"))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn source_capture(
    catalog: &Catalog,
    input: &ActivationInput,
    execution: &Execution,
) -> Result<SourceCapture> {
    if !valid_id(&input.capture_resource_id)
        || !valid_digest(&input.profile_digest)
        || !valid_digest(&input.helper_digest)
    {
        return Err(Fault::invalid("invalid capture or Guest profile identity"));
    }
    fixed_hex::<16>(&input.capture_anchor)?;
    let capture = catalog
        .db
        .query_row(
            "SELECT transfer.descriptor_digest,source.incarnation_id,source.execution_epoch,
                lease.lease_id,lease.revision
         FROM fd_transfers transfer
         JOIN resources resource USING(resource_id)
         JOIN executions source ON source.incarnation_id=transfer.incarnation_id
         JOIN fd_leases lease USING(resource_id)
         WHERE transfer.resource_id=?1 AND transfer.state='committed'
           AND resource.kind='descriptor' AND resource.state='available' AND resource.immutable=1
           AND lease.incarnation_id=?2 AND lease.operation_id=?3 AND lease.state='attached'
           AND source.bundle_digest=?4 AND source.incarnation_id<>?2 AND source.route_id=?5
         UNION ALL
         SELECT p.manifest_digest,source.incarnation_id,source.execution_epoch,lease.lease_id,lease.revision
         FROM statepoints p
         JOIN resources resource ON resource.resource_id=p.representation_id
         JOIN executions source ON source.incarnation_id=p.source_incarnation_id
         JOIN fd_leases lease ON lease.resource_id=p.representation_id
         WHERE p.representation_id=?1 AND (
             p.phase='hibernated' OR (p.phase='durable' AND json_extract(p.export_json,'$.purpose')='checkpoint')
         ) AND resource.state='available' AND resource.immutable=1 AND resource.durability='durable'
           AND lease.incarnation_id=?2 AND lease.operation_id=?3 AND lease.state='attached'
           AND source.bundle_digest=?4 AND source.incarnation_id<>?2 AND source.route_id=?5
           AND json_extract(p.point_json,'$.capture_anchor')=?6
           AND json_extract(p.point_json,'$.helper_digest')=?7
         ORDER BY 4 LIMIT 1",
            params![
                input.capture_resource_id,
                execution.incarnation_id,
                execution.last_operation_id,
                execution.bundle_digest,
                execution.route_id,
                input.capture_anchor,
                input.helper_digest,
            ],
            |row| {
                Ok(SourceCapture {
                    descriptor_digest: row.get(0)?,
                    incarnation_id: row.get(1)?,
                    execution_epoch: row.get(2)?,
                    lease_id: row.get(3)?,
                    lease_revision: row.get(4)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| {
            Fault::new(
                "E_FENCE_UNPROVEN",
                "sealed source RAM has no attached lease on this distinct restored execution",
            )
        })?;
    Ok(capture)
}

fn writer_digest(catalog: &Catalog, execution: &Execution) -> Result<String> {
    let mut evidence: Vec<Value> = Vec::new();
    for grant in catalog.grants_for_execution(execution)? {
        if grant.state != "attached" || !grant.belongs_to(&execution.last_operation_id, execution) {
            return Err(Fault::new(
                "E_FENCE_UNPROVEN",
                "writer set is not attached to this launch",
            ));
        }
        let set = catalog
            .writer_set(&grant.operation_id)?
            .ok_or_else(|| Fault::new("E_FENCE_UNPROVEN", "missing attached writer heads"))?;
        evidence.push(serde_json::json!([grant.grant_id, grant.revision, set]));
    }
    digest(&evidence)
}

fn network_binding(
    catalog: &Catalog,
    resource: &str,
    input: Option<&NetworkInput>,
    source: &SourceCapture,
    execution: &Execution,
) -> Result<Option<NetworkBinding>> {
    let pinned = captured_tap(&catalog.db, resource)?;
    let has_attestation = pinned.is_some();
    let old = if let Some(pinned) = pinned {
        if pinned.origin.incarnation != source.incarnation_id
            || pinned.origin.epoch != source.execution_epoch
            || pinned.origin.digest != source.descriptor_digest
        {
            return Err(tap_fence(
                "pinned network is outside the immutable source capture",
            ));
        }
        pinned.bound
    } else {
        // Older low-level activations may still use the exact live source lease.
        let original = catalog.execution(&source.incarnation_id)?;
        if original.execution_epoch != source.execution_epoch {
            return Err(tap_fence("source lease is outside the capture epoch"));
        }
        legacy_source_tap(catalog, &original)?
    };
    let targets = catalog.tap_leases_for_execution(execution)?;
    match (old, targets.as_slice(), input) {
        (None, [], None) => Ok(None),
        (Some(old), [new], Some(input)) => {
            if input.source_attachment_id == input.target_attachment_id
                || !valid_id(&input.source_attachment_id)
                || !valid_id(&input.target_attachment_id)
                || input.uplink_name.is_empty()
                || input.uplink_name.len() >= libc::IFNAMSIZ
                || !input
                    .uplink_name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
                || input.uplink_name == "lo"
                || input.dns_ipv4.is_unspecified()
                || input.dns_ipv4.is_loopback()
                || input.dns_ipv4.is_multicast()
                || input.dns_ipv4.is_broadcast()
            {
                return Err(Fault::invalid("invalid target network identity intent"));
            }
            if new.state != "attached"
                || old.attachment.attachment_id != input.source_attachment_id
                || new.attachment.attachment_id != input.target_attachment_id
                || old.attachment.mode != new.attachment.mode
                || old.attachment.device_id != new.attachment.device_id
                || old.attachment.mac == new.attachment.mac
                || old.attachment.private_ipv4 == new.attachment.private_ipv4
                || (has_attestation
                    && (input.dns_ipv4 != new.attachment.gateway_ipv4
                        || input.uplink_name != "eth0"))
            {
                return Err(tap_fence(
                    "source and target TAP leases do not match the fork placement",
                ));
            }
            Ok(Some(NetworkBinding {
                source: old,
                target: BoundTap::try_from(new.clone())?,
                dns_ipv4: input.dns_ipv4,
                uplink_name: input.uplink_name.clone(),
            }))
        }
        _ => Err(tap_fence("activation must cover each side's managed TAP")),
    }
}

impl Catalog {
    pub(crate) fn activation_binding(
        &self,
        input: ActivationInput,
        execution: &Execution,
    ) -> Result<ActivationBinding> {
        let source_capture = source_capture(self, &input, execution)?;
        let world = ExecutionBinding {
            route_id: execution.route_id.clone(),
            bundle_digest: execution.bundle_digest.clone(),
            operation_id: execution.last_operation_id.clone(),
            instance_id: execution.instance_id.clone(),
            incarnation_id: execution.incarnation_id.clone(),
            epoch: execution.execution_epoch,
            host_boot_id: execution.host_boot_id.clone(),
            pid: execution.pid,
            pid_start_time: execution.pid_start_time,
            uid: execution.uid,
        };
        let writer_set_digest = writer_digest(self, execution)?;
        let network = network_binding(
            self,
            &input.capture_resource_id,
            input.network.as_ref(),
            &source_capture,
            execution,
        )?;
        Ok(ActivationBinding {
            input,
            source_capture,
            execution: world,
            network,
            writer_set_digest,
        })
    }

    pub(crate) fn activation_digest(&self, binding: &ActivationBinding) -> Result<String> {
        digest(&("smolvm-target-activation/1", binding))
    }

    pub(crate) fn activation(&self, operation_id: &str) -> Result<ActivationReceipt> {
        self.db.query_row(
            "SELECT context_digest,challenge,binding_json,wire_digest,begin_revision,commit_revision,phase,decision,prior_revision,revision
             FROM target_activations WHERE operation_id=?",
            [operation_id],
            |row| {
                let binding: String = row.get(2)?;
                let binding = serde_json::from_str(&binding).map_err(|error|
                    rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error)))?;
                Ok(ActivationReceipt {
                    context_digest: row.get(0)?, challenge: row.get(1)?, binding, wire_digest: row.get(3)?,
                    begin_revision: row.get(4)?, commit_revision: row.get(5)?,
                    phase: row.get(6)?, decision: row.get(7)?, prior_revision: row.get(8)?, revision: row.get(9)?,
                })
            },
        ).optional()?.ok_or_else(|| Fault::new("E_NOT_FOUND", "target activation was not prepared"))
    }

    pub(crate) fn store_activation(
        &self,
        binding: &ActivationBinding,
        nonce: [u8; 16],
    ) -> Result<ActivationReceipt> {
        let execution = &binding.execution;
        let context = self.activation_digest(binding)?;
        let binding_data = serde_json::to_string(binding)
            .map_err(|_| Fault::invalid("invalid activation binding"))?;
        self.db.execute(
            "INSERT INTO target_activations
             SELECT ?1,?2,?3,?4,?5,broker_session_id,host_boot_id,?6,?7,?8,NULL,NULL,NULL,'authority_prepared','none',0,1
             FROM worker_state WHERE host_boot_id=?9",
            params![execution.operation_id, execution.bundle_digest, execution.instance_id, execution.incarnation_id,
                execution.epoch, context, hex::encode(nonce), binding_data, execution.host_boot_id],
        )?;
        self.activation(&execution.operation_id)
    }

    pub(crate) fn transition_activation(
        &self,
        record: &ActivationReceipt,
        phase: &str,
        decision: &str,
        wire: Option<&str>,
    ) -> Result<ActivationReceipt> {
        let id = &record.binding.execution.operation_id;
        let updated = self.db.execute(
            "UPDATE target_activations SET phase=?1,decision=?2,wire_digest=COALESCE(?3,wire_digest),
             begin_revision=CASE WHEN ?3 IS NOT NULL THEN COALESCE(begin_revision,revision) ELSE begin_revision END,
             commit_revision=CASE WHEN ?2='commit' THEN COALESCE(commit_revision,revision) ELSE commit_revision END,
             prior_revision=revision,revision=revision+1 WHERE operation_id=?4 AND revision=?5",
            params![phase, decision, wire, id, record.revision],
        )?;
        if updated != 1 {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "activation revision changed",
            ));
        }
        self.activation(id)
    }
}
