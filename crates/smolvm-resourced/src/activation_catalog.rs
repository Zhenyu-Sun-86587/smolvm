use crate::catalog::{Catalog, Execution};
use crate::ipc::{valid_digest, valid_id, Fault, Result};
use crate::network_lease_catalog::{AttachmentDescriptor, TapLease};
use rusqlite::{params, Connection, OptionalExtension};
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct BoundTap {
    pub attachment: AttachmentDescriptor,
    pub lease_id: String,
    pub lease_revision: i64,
    pub attachment_digest: String,
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
         ORDER BY lease.lease_id LIMIT 1",
            params![
                input.capture_resource_id,
                execution.incarnation_id,
                execution.last_operation_id,
                execution.bundle_digest,
                execution.route_id
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
    input: Option<&NetworkInput>,
    source: &SourceCapture,
    execution: &Execution,
) -> Result<Option<NetworkBinding>> {
    let count = |incarnation: &str, epoch: i64| {
        catalog.db.query_row(
            "SELECT count(*) FROM network_tap_leases WHERE incarnation_id=? AND execution_epoch=?
             AND state!='retired'",
            params![incarnation, epoch],
            |row| row.get::<_, i64>(0),
        )
    };
    match (
        count(&execution.incarnation_id, execution.execution_epoch)?,
        count(&source.incarnation_id, source.execution_epoch)?,
        input,
    ) {
        (0, 0, None) => Ok(None),
        (1, 1, Some(input)) => {
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
            let old = catalog.tap_lease(&input.source_attachment_id)?;
            let new = catalog.tap_lease(&input.target_attachment_id)?;
            if new.state != "attached"
                || !new.matches(execution)
                || old.state != "attached"
                || old.incarnation_id.as_deref() != Some(source.incarnation_id.as_str())
                || old.execution_epoch != Some(source.execution_epoch)
                || old.attachment.mode != new.attachment.mode
                || old.attachment.device_id != new.attachment.device_id
                || old.attachment.mac == new.attachment.mac
                || old.attachment.private_ipv4 == new.attachment.private_ipv4
            {
                return Err(Fault::new(
                    "E_FENCE_UNPROVEN",
                    "source and target TAP leases do not match the fork placement",
                ));
            }
            Ok(Some(NetworkBinding {
                source: old.try_into()?,
                target: new.try_into()?,
                dns_ipv4: input.dns_ipv4,
                uplink_name: input.uplink_name.clone(),
            }))
        }
        _ => Err(Fault::new(
            "E_FENCE_UNPROVEN",
            "activation must cover each side's managed TAP",
        )),
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
        let network = network_binding(self, input.network.as_ref(), &source_capture, execution)?;
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
