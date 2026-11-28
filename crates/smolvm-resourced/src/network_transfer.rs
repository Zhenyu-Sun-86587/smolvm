//! Target TAP publication fence. The platform migration journal owns the
//! owner decision and calls this Worker only after the source is fenced.

use crate::activation_runtime::{self, ActivationRuntime};
use crate::catalog::{Catalog, Execution};
use crate::ipc::{valid_id, Fault, Request, Result};
use crate::network_lease_catalog::TapLease;
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
}

#[derive(Serialize)]
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
    let attachment = &lease.attachment;
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
        && execution.execution_epoch == transfer.target_execution_epoch
        && lease.matches(execution)
        && lease.state == "attached"
        && lease.revision == transfer.target_attachment_revision
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
    let prior = journal(catalog, &transfer.migration_id)?;
    if prior
        .as_ref()
        .is_some_and(|row| row.transfer != transfer || &row.operation_id != operation)
    {
        return Err(conflict());
    }
    let preparing = request.method == "PrepareTransfer";
    let committing = request.method == "CommitTransfer";
    if preparing != input.membership.is_some() || committing != input.owner_decision.is_some() {
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
            let prior = prior.ok_or_else(fenced)?;
            let decision = input.owner_decision.as_ref().ok_or_else(fenced)?;
            if !decision.matches(&transfer)
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
