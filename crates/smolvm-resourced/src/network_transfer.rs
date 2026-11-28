//! Target TAP publication fence. The platform migration journal owns the
//! owner decision and calls this Worker only after the source is fenced.

use crate::activation_runtime::{self, ActivationRuntime};
use crate::catalog::{Catalog, Execution};
use crate::ipc::{valid_id, Expected, Fault, Request, Result};
use crate::network_lease_catalog::{AttachmentDescriptor, TapLease};
use crate::network_memberships::{self, Membership};
use crate::network_runtime::NetworkRuntime;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Transfer {
    pub machine_id: String,
    pub source_worker_id: String,
    pub target_worker_id: String,
    pub expected_owner_epoch: i64,
    pub target_execution_epoch: i64,
    pub attachment_id: String,
    pub attachment_revision: i64,
    pub target_attachment_id: String,
    pub target_attachment_revision: i64,
    pub policy_revision: i64,
    pub migration_id: String,
    pub network_mode: String,
    pub private_ipv4: Ipv4Addr,
    pub guest_ipv4: Ipv4Addr,
    pub guest_gateway_ipv4: Ipv4Addr,
    pub guest_prefix: u8,
    pub guest_mac: [u8; 6],
    pub route_domain_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerDecision {
    migration_id: String,
    previous_owner_epoch: i64,
    owner_epoch: i64,
    owner_worker_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub transfer: Transfer,
    pub membership: Option<Membership>,
    pub owner_decision: Option<OwnerDecision>,
    pub source_fence: Option<SourceFence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FenceInput {
    transfer: Transfer,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceFence {
    transfer: Transfer,
    migration_id: String,
    machine_id: String,
    source_worker_id: String,
    expected_owner_epoch: i64,
    source_execution_epoch: i64,
    source_instance_id: String,
    source_incarnation_id: String,
    source_attachment_id: String,
    source_attachment_revision: i64,
    route_domain_id: String,
    private_ipv4: Ipv4Addr,
}

impl SourceFence {
    pub(crate) fn binds(&self, expected: &Expected) -> bool {
        self.source_instance_id == expected.instance_id
            && self.source_execution_epoch == expected.execution_epoch
            && expected.incarnation_id.as_deref() == Some(&self.source_incarnation_id)
    }

    fn matches(&self, transfer: &Transfer) -> bool {
        &self.transfer == transfer
            && self.migration_id == transfer.migration_id
            && self.machine_id == transfer.machine_id
            && self.source_worker_id == transfer.source_worker_id
            && self.expected_owner_epoch == transfer.expected_owner_epoch
            && self.source_execution_epoch > 0
            && valid_id(&self.source_instance_id)
            && valid_id(&self.source_incarnation_id)
            && self.source_attachment_id == transfer.attachment_id
            && self.source_attachment_revision == transfer.attachment_revision
            && self.route_domain_id == transfer.route_domain_id
            && self.private_ipv4 == transfer.private_ipv4
    }
}

pub(crate) fn fence_source(
    catalog: &Catalog,
    execution: &Execution,
    network: &mut NetworkRuntime,
    input: FenceInput,
) -> Result<SourceFence> {
    catalog.ready()?;
    let transfer = input.transfer;
    if transfer.network_mode != "native"
        || execution.route_id != "deep"
        || !network.overlay().has_peer(
            &transfer.route_domain_id,
            &transfer.source_worker_id,
            &transfer.target_worker_id,
        )
        || !valid_id(&transfer.machine_id)
        || !valid_id(&transfer.migration_id)
        || transfer.expected_owner_epoch < 1
        || transfer.attachment_revision < 1
        || transfer.policy_revision < 1
    {
        return Err(Fault::invalid(
            "source fence requires an explicit native overlay transfer",
        ));
    }

    let receipt = source_receipt(execution, &transfer);

    // The retired TAP and its prior kernel publication receipt are durable.
    // Retrying after source exit or Worker restart returns the same fence.
    if source_retired(catalog, execution, &transfer)? {
        save_source_hold(catalog, execution, &transfer)?;
        return Ok(receipt);
    }
    if !network.overlay().permits_source_fence(&transfer, execution) {
        return Err(conflict());
    }
    let lease = catalog.tap_lease(&transfer.attachment_id)?;
    if !lease.matches(execution)
        || lease.state != "attached"
        || lease.gate != "open"
        || lease.revision != transfer.attachment_revision
        || !source_descriptor(&lease.attachment, &transfer)
        || catalog.network_kernel_proof(&lease)?.is_none()
        || network_memberships::lookup(&catalog.db, &execution.instance_id)?.policy_revision
            != transfer.policy_revision
    {
        return Err(fenced());
    }

    save_source_hold(catalog, execution, &transfer)?;
    network.retire_port(catalog, &lease)?;
    if !source_retired(catalog, execution, &transfer)? {
        return Err(fenced());
    }
    Ok(receipt)
}

pub(crate) fn source_receipt(execution: &Execution, transfer: &Transfer) -> SourceFence {
    SourceFence {
        transfer: transfer.clone(),
        migration_id: transfer.migration_id.clone(),
        machine_id: transfer.machine_id.clone(),
        source_worker_id: transfer.source_worker_id.clone(),
        expected_owner_epoch: transfer.expected_owner_epoch,
        source_execution_epoch: execution.execution_epoch,
        source_instance_id: execution.instance_id.clone(),
        source_incarnation_id: execution.incarnation_id.clone(),
        source_attachment_id: transfer.attachment_id.clone(),
        source_attachment_revision: transfer.attachment_revision,
        route_domain_id: transfer.route_domain_id.clone(),
        private_ipv4: transfer.private_ipv4,
    }
}

fn save_source_hold(catalog: &Catalog, execution: &Execution, transfer: &Transfer) -> Result<()> {
    // The source slice must retain the stable address across retries, Worker
    // restarts, and withdrawal snapshots. M13 retires the address when the
    // logical machine no longer owns it.
    let encoded = encoded(transfer)?;
    catalog.db.execute(
        "INSERT OR IGNORE INTO network_overlay_source_fences
         (migration_id,route_domain_id,private_ipv4,source_incarnation_id,transfer_json)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            transfer.migration_id,
            transfer.route_domain_id,
            u32::from(transfer.private_ipv4),
            execution.incarnation_id,
            encoded
        ],
    )?;
    let matches = catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_overlay_source_fences
         WHERE migration_id=?1 AND source_incarnation_id=?2 AND transfer_json=?3)",
        params![transfer.migration_id, execution.incarnation_id, encoded],
        |row| row.get::<_, bool>(0),
    )?;
    if !matches {
        return Err(conflict());
    }
    Ok(())
}

pub(crate) fn source_descriptor(attachment: &AttachmentDescriptor, transfer: &Transfer) -> bool {
    attachment.attachment_id == transfer.attachment_id
        && attachment.route_domain_id == transfer.route_domain_id
        && attachment.mode == transfer.network_mode
        && attachment.private_ipv4 == transfer.private_ipv4
        && attachment.guest_ipv4 == transfer.guest_ipv4
        && attachment.gateway_ipv4 == transfer.guest_gateway_ipv4
        && attachment.guest_prefix == transfer.guest_prefix
        && attachment.mac == transfer.guest_mac
}

fn source_retired(catalog: &Catalog, execution: &Execution, transfer: &Transfer) -> Result<bool> {
    let recorded: Option<String> = catalog
        .db
        .query_row(
            "SELECT t.descriptor_json FROM network_tap_leases t
         JOIN network_kernel_receipts k USING(lease_id)
         WHERE t.attachment_id=?1 AND t.incarnation_id=?2 AND t.execution_epoch=?3
           AND t.operation_id=?4 AND t.instance_id=?5 AND t.state='retired'
           AND t.revision=?6+1 AND k.published_revision<=?6
           AND NOT EXISTS(SELECT 1 FROM network_tap_leases active
                          WHERE active.attachment_id=t.attachment_id AND active.state<>'retired')",
            params![
                transfer.attachment_id,
                execution.incarnation_id,
                execution.execution_epoch,
                execution.last_operation_id,
                execution.instance_id,
                transfer.attachment_revision
            ],
            |row| row.get(0),
        )
        .optional()?;
    recorded
        .map(|raw| {
            serde_json::from_str(&raw)
                .map(|attachment| source_descriptor(&attachment, transfer))
                .map_err(|_| Fault::new("E_CATALOG", "cannot read source overlay fence"))
        })
        .transpose()
        .map(|value| value.unwrap_or(false))
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Receipt {
    pub transfer: Transfer,
    pub state: String,
    pub activation_revision: i64,
    pub published: bool,
}

struct Journal {
    operation_id: String,
    transfer: Transfer,
    activation_revision: i64,
    decision: Option<OwnerDecision>,
    phase: String,
}

fn conflict() -> Fault {
    Fault::new(
        "E_STALE_REVISION",
        "network transfer identity or revision changed",
    )
}

fn fenced() -> Fault {
    Fault::new(
        "E_FENCE_UNPROVEN",
        "network transfer is awaiting the committed owner decision",
    )
}

fn stale() -> Fault {
    Fault::new(
        "E_STALE_EXECUTION",
        "network transfer belongs to another target execution",
    )
}

fn encoded<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|_| Fault::new("E_CATALOG", "cannot encode network transfer receipt"))
}

fn journal(catalog: &Catalog, migration: &str) -> Result<Option<Journal>> {
    let raw = catalog.db.query_row(
        "SELECT operation_id,intent_json,decision_json,phase FROM network_transfers WHERE migration_id=?",
        [migration],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?, row.get::<_, String>(3)?)),
    ).optional()?;
    raw.map(|(operation_id, raw, decision, phase)| {
        let bad = |_| Fault::new("E_CATALOG", "invalid stored network transfer");
        let (transfer, activation_revision) = serde_json::from_str(&raw).map_err(bad)?;
        let decision = decision
            .map(|value| serde_json::from_str(&value).map_err(bad))
            .transpose()?;
        Ok(Journal {
            operation_id,
            transfer,
            activation_revision,
            decision,
            phase,
        })
    })
    .transpose()
}

fn validates_target(transfer: &Transfer, execution: &Execution, lease: &TapLease) -> bool {
    execution.execution_epoch == transfer.target_execution_epoch
        && lease.matches(execution)
        && lease.state == "attached"
        && lease.revision == transfer.target_attachment_revision
        && target_descriptor(transfer, &lease.attachment)
}

pub(crate) fn target_descriptor(transfer: &Transfer, attachment: &AttachmentDescriptor) -> bool {
    [
        &transfer.machine_id,
        &transfer.source_worker_id,
        &transfer.target_worker_id,
        &transfer.migration_id,
        &transfer.attachment_id,
        &transfer.target_attachment_id,
        &transfer.route_domain_id,
    ]
    .into_iter()
    .all(|id| valid_id(id))
        && transfer.source_worker_id != transfer.target_worker_id
        && transfer.expected_owner_epoch > 0
        && transfer.attachment_revision > 0
        && transfer.policy_revision > 0
        && attachment.attachment_id == transfer.target_attachment_id
        && attachment.route_domain_id == transfer.route_domain_id
        && attachment.mode == transfer.network_mode
        && attachment.private_ipv4 == transfer.private_ipv4
        && attachment.guest_ipv4 == transfer.guest_ipv4
        && attachment.gateway_ipv4 == transfer.guest_gateway_ipv4
        && attachment.guest_prefix == transfer.guest_prefix
        && attachment.mac == transfer.guest_mac
}

impl OwnerDecision {
    pub(crate) fn migration(transfer: &Transfer, owner_epoch: i64) -> Self {
        Self {
            migration_id: transfer.migration_id.clone(),
            previous_owner_epoch: transfer.expected_owner_epoch,
            owner_epoch,
            owner_worker_id: transfer.target_worker_id.clone(),
        }
    }

    fn matches(&self, transfer: &Transfer) -> bool {
        self.migration_id == transfer.migration_id
            && self.previous_owner_epoch == transfer.expected_owner_epoch
            && transfer.expected_owner_epoch.checked_add(1) == Some(self.owner_epoch)
            && self.owner_worker_id == transfer.target_worker_id
    }
}

pub(crate) fn guard_matches(
    db: &rusqlite::Connection,
    operation: &str,
    attachment: &str,
    migration: &str,
) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_transfer_guards
         WHERE operation_id=?1 AND attachment_id=?2 AND migration_id=?3)",
        params![operation, attachment, migration],
        |row| row.get(0),
    )?)
}

pub(crate) fn awaiting_owner(catalog: &Catalog, operation: &str) -> Result<bool> {
    Ok(catalog.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM network_transfer_guards g
                       LEFT JOIN network_transfers t USING(operation_id)
                       WHERE g.operation_id=? AND coalesce(t.phase,'')<>'committed')",
        [operation],
        |row| row.get(0),
    )?)
}

pub(crate) fn permit_activation(catalog: &Catalog, operation: &str) -> Result<()> {
    if awaiting_owner(catalog, operation)? {
        return Err(fenced());
    }
    Ok(())
}

pub(crate) fn authorize_overlay_commit(
    overlay: &crate::network::overlay::Overlay,
    transfer: &Transfer,
    source_fence: Option<&SourceFence>,
) -> Result<()> {
    if !overlay.has_peer(
        &transfer.route_domain_id,
        &transfer.target_worker_id,
        &transfer.source_worker_id,
    ) || !source_fence.is_some_and(|proof| proof.matches(transfer))
        || !overlay.withdrawn(&transfer.machine_id, transfer.private_ipv4)
    {
        return Err(fenced());
    }
    Ok(())
}

pub(crate) fn prepare_cold(
    catalog: &Catalog,
    network: &mut NetworkRuntime,
    operation: &str,
    transfer: &Transfer,
    membership: &Membership,
) -> Result<Receipt> {
    let lease = catalog.tap_lease(&transfer.target_attachment_id)?;
    if lease.operation_id != operation
        || lease.state != "quarantined"
        || lease.gate != "closed"
        || lease.revision.checked_add(2) != Some(transfer.target_attachment_revision)
        || !target_descriptor(transfer, &lease.attachment)
        || !guard_matches(
            &catalog.db,
            operation,
            &transfer.target_attachment_id,
            &transfer.migration_id,
        )?
        || membership.policy_revision != transfer.policy_revision
    {
        return Err(fenced());
    }
    if let Some(prior) = journal(catalog, &transfer.migration_id)? {
        if prior.operation_id != operation
            || prior.transfer != *transfer
            || prior.phase != "prepared"
            || network_memberships::lookup(&catalog.db, &lease.instance_id)? != *membership
        {
            return Err(conflict());
        }
        return Ok(migration_receipt(prior, false));
    }
    network.apply_membership(catalog, &lease.instance_id, membership)?;
    catalog.db.execute(
        "INSERT INTO network_transfers(migration_id,operation_id,intent_json,phase)
         VALUES(?1,?2,?3,'prepared')",
        params![
            transfer.migration_id,
            operation,
            encoded(&(transfer, lease.revision))?
        ],
    )?;
    Ok(migration_receipt(
        require_journal(catalog, transfer, operation)?,
        false,
    ))
}

fn require_journal(catalog: &Catalog, transfer: &Transfer, operation: &str) -> Result<Journal> {
    let entry = journal(catalog, &transfer.migration_id)?.ok_or_else(fenced)?;
    if entry.transfer != *transfer || entry.operation_id != operation {
        return Err(conflict());
    }
    Ok(entry)
}

fn migration_receipt(entry: Journal, published: bool) -> Receipt {
    Receipt {
        transfer: entry.transfer,
        state: entry.phase,
        activation_revision: entry.activation_revision,
        published,
    }
}

pub(crate) fn authorize_cold(
    catalog: &Catalog,
    operation: &str,
    transfer: &Transfer,
    decision: &OwnerDecision,
) -> Result<()> {
    crate::machine_migration::permit_target_activation(catalog, operation)?;
    let prior = require_journal(catalog, transfer, operation)?;
    if !decision.matches(transfer)
        || !matches!(prior.phase.as_str(), "prepared" | "committed")
        || prior
            .decision
            .as_ref()
            .is_some_and(|saved| saved != decision)
    {
        return Err(fenced());
    }
    if prior.phase == "prepared" {
        let lease = catalog.tap_lease(&transfer.target_attachment_id)?;
        if lease.state != "quarantined"
            || lease.gate != "closed"
            || lease.operation_id != operation
            || lease.revision != prior.activation_revision
            || !target_descriptor(transfer, &lease.attachment)
            || network_memberships::lookup(&catalog.db, &lease.instance_id)?.policy_revision
                != transfer.policy_revision
        {
            return Err(fenced());
        }
        catalog.db.execute(
            "UPDATE network_transfers SET phase='committed',decision_json=? WHERE migration_id=? AND phase='prepared'",
            params![encoded(decision)?, transfer.migration_id],
        )?;
    }
    Ok(())
}

pub(crate) fn permit_initial_migration_publication(
    catalog: &Catalog,
    execution: &Execution,
    lease: &TapLease,
) -> Result<()> {
    let migration: Option<String> = catalog
        .db
        .query_row(
            "SELECT migration_id FROM network_transfer_guards WHERE operation_id=?",
            [&execution.last_operation_id],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(migration) = migration {
        let entry = journal(catalog, &migration)?.ok_or_else(fenced)?;
        if entry.phase != "committed"
            || entry.operation_id != execution.last_operation_id
            || !validates_target(&entry.transfer, execution, lease)
            || network_memberships::lookup(&catalog.db, &execution.instance_id)?.policy_revision
                != entry.transfer.policy_revision
        {
            return Err(fenced());
        }
    }
    Ok(())
}

pub(crate) fn observe_cold(
    catalog: &Catalog,
    operation: &str,
    transfer: &Transfer,
    execution: &Execution,
) -> Result<Receipt> {
    let entry = require_journal(catalog, transfer, operation)?;
    let lease = catalog.tap_lease(&transfer.target_attachment_id)?;
    if entry.phase != "committed"
        || !validates_target(transfer, execution, &lease)
        || lease.gate != "open"
        || catalog.network_kernel_proof(&lease)?.is_none()
    {
        return Err(fenced());
    }
    Ok(migration_receipt(entry, true))
}

pub(crate) fn abort_migration(
    catalog: &Catalog,
    transfer: &Transfer,
    operation: &str,
) -> Result<Receipt> {
    crate::machine_migration::permit_target_abort(catalog, operation)?;
    let entry = require_journal(catalog, transfer, operation)?;
    if entry.phase == "committed" {
        return Err(fenced());
    }
    // The caller has already proved writer/relay exit. A retired or absent
    // lease is the only state that can attest an aborted transfer.
    match catalog.tap_lease(&transfer.target_attachment_id) {
        Err(error) if error.code == "E_NOT_FOUND" => (),
        Err(error) => return Err(error),
        Ok(_) => return Err(fenced()),
    }
    if entry.phase == "prepared" {
        catalog.db.execute(
            "UPDATE network_transfers SET phase='aborted' WHERE migration_id=? AND phase='prepared'",
            [&transfer.migration_id],
        )?;
    }
    Ok(migration_receipt(
        require_journal(catalog, transfer, operation)?,
        false,
    ))
}

pub(crate) fn handle(
    catalog: &Catalog,
    execution: &Execution,
    request: &Request,
    network: &mut NetworkRuntime,
    activations: &ActivationRuntime,
    verify_process: impl Fn() -> Result<()>,
) -> Result<Receipt> {
    catalog.ready()?;
    let input: Input = request.payload()?;
    let activation = activation_runtime::receipt(catalog, execution, request)?;
    let transfer = input.transfer;
    let lease = catalog.tap_lease(&transfer.target_attachment_id)?;
    if !validates_target(&transfer, execution, &lease) {
        return Err(stale());
    }
    let target = activation.binding.network.as_ref().ok_or_else(stale)?;
    if target.target.lease_id != lease.lease_id || target.target.lease_revision != lease.revision {
        return Err(stale());
    }
    let operation = &execution.last_operation_id;
    if !guard_matches(
        &catalog.db,
        operation,
        &transfer.target_attachment_id,
        &transfer.migration_id,
    )? {
        return Err(fenced());
    }
    let overlay = transfer.network_mode == "native";
    if overlay
        && request.method == "PrepareTransfer"
        && !network.overlay().has_peer(
            &transfer.route_domain_id,
            &transfer.target_worker_id,
            &transfer.source_worker_id,
        )
    {
        return Err(Fault::new(
            "E_OVERLAY_UNAVAILABLE",
            "cross-Worker native transfer requires the same configured overlay domain",
        ));
    }
    let prior = journal(catalog, &transfer.migration_id)?;
    if prior
        .as_ref()
        .is_some_and(|row| row.transfer != transfer || &row.operation_id != operation)
    {
        return Err(conflict());
    }
    let preparing = request.method == "PrepareTransfer";
    let committing = request.method == "CommitTransfer";
    if preparing != input.membership.is_some()
        || committing != input.owner_decision.is_some()
        || (committing && overlay) != input.source_fence.is_some()
    {
        return Err(Fault::invalid(
            "network transfer inputs do not match the requested step",
        ));
    }
    let (state, activation_revision, published) = match request.method.as_str() {
        "PrepareTransfer" => {
            let membership = input.membership.as_ref().ok_or_else(conflict)?;
            if membership.policy_revision != transfer.policy_revision {
                return Err(conflict());
            }
            if let Some(prior) = prior {
                if prior.phase != "prepared"
                    || network_memberships::lookup(&catalog.db, &execution.instance_id)?
                        != *membership
                {
                    return Err(conflict());
                }
                ("prepared", prior.activation_revision, false)
            } else {
                if activation.phase != "identity_ready" || lease.gate != "closed" {
                    return Err(fenced());
                }
                network.apply_membership(catalog, &execution.instance_id, membership)?;
                catalog.db.execute(
                    "INSERT INTO network_transfers(migration_id,operation_id,intent_json,phase)
                     VALUES(?1,?2,?3,'prepared')",
                    params![
                        transfer.migration_id,
                        operation,
                        encoded(&(&transfer, activation.revision))?
                    ],
                )?;
                ("prepared", activation.revision, false)
            }
        }
        "CheckReady" => {
            let prior = prior.ok_or_else(fenced)?;
            if prior.phase == "prepared"
                && (activation.phase != "identity_ready"
                    || lease.gate != "closed"
                    || network_memberships::lookup(&catalog.db, &execution.instance_id)?
                        .policy_revision
                        != transfer.policy_revision)
            {
                return Err(fenced());
            }
            let published = prior.phase == "committed"
                && activation.phase == "released"
                && lease.gate == "open";
            (
                match prior.phase.as_str() {
                    "prepared" => "prepared",
                    "committed" => "committed",
                    _ => "aborted",
                },
                prior.activation_revision,
                published,
            )
        }
        "CommitTransfer" => {
            crate::machine_migration::permit_target_activation(catalog, operation)?;
            let prior = prior.ok_or_else(fenced)?;
            let decision = input.owner_decision.as_ref().ok_or_else(fenced)?;
            if !decision.matches(&transfer)
                || (overlay
                    && !input
                        .source_fence
                        .as_ref()
                        .is_some_and(|proof| proof.matches(&transfer)))
                || prior.phase == "aborted"
                || prior
                    .decision
                    .as_ref()
                    .is_some_and(|known| known != decision)
                || network_memberships::lookup(&catalog.db, &execution.instance_id)?.policy_revision
                    != transfer.policy_revision
            {
                return Err(fenced());
            }
            if prior.phase == "prepared" {
                if overlay {
                    authorize_overlay_commit(
                        network.overlay(),
                        &transfer,
                        input.source_fence.as_ref(),
                    )?;
                }
                if activation.phase != "identity_ready"
                    || activation.revision != prior.activation_revision
                    || lease.gate != "closed"
                {
                    return Err(fenced());
                }
                catalog.db.execute(
                    "UPDATE network_transfers SET phase='committed',decision_json=? WHERE migration_id=? AND phase='prepared'",
                    params![encoded(decision)?, transfer.migration_id],
                )?;
            }
            let commit = request.derived(
                "CommitActivation",
                json!({"expected_revision":prior.activation_revision}),
            );
            let observed =
                activations.commit(catalog, network, execution, &commit, verify_process)?;
            (
                "committed",
                prior.activation_revision,
                observed.phase == "released",
            )
        }
        "AbortTransfer" => {
            crate::machine_migration::permit_target_abort(catalog, operation)?;
            let prior = prior.ok_or_else(fenced)?;
            if prior.phase == "committed" {
                return Err(fenced());
            }
            if prior.phase == "prepared" {
                if lease.gate != "closed" {
                    return Err(fenced());
                }
                network.close_target(target)?;
                catalog.db.execute(
                    "UPDATE network_transfers SET phase='aborted' WHERE migration_id=? AND phase='prepared'",
                    [&transfer.migration_id],
                )?;
            }
            ("aborted", prior.activation_revision, false)
        }
        _ => return Err(Fault::invalid("unknown network transfer step")),
    };
    Ok(Receipt {
        transfer,
        state: state.into(),
        activation_revision,
        published,
    })
}
