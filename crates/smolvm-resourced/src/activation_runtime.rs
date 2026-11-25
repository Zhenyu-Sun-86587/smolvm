//! Target identity and activation are driven only over the measured VMM's private authority.

use crate::activation_authority::{IdentityPhase, TargetAuthority, FRAME_SIZE, NETWORK_FRAME_SIZE};
use crate::activation_catalog::{fixed_hex, ActivationInput, ActivationReceipt};
use crate::catalog::{Catalog, Execution};
use crate::ipc::{Fault, Request, Result};
use crate::network_runtime::NetworkRuntime;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::os::fd::OwnedFd;

#[derive(Default)]
pub(crate) struct ActivationRuntime {
    authorities: HashMap<String, TargetAuthority>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Begin {
    frame_hex: String,
    expected_revision: i64,
}

fn check_revision(actual: i64, expected: i64) -> Result<()> {
    if expected == actual {
        return Ok(());
    }
    Err(Fault::new("E_STALE_REVISION", "target activation changed"))
}

fn held() -> Fault {
    Fault::new(
        "E_FENCE_UNPROVEN",
        "target activation is held or its private authority is unavailable",
    )
}

pub(crate) fn receipt(
    catalog: &Catalog,
    execution: &Execution,
    request: &Request,
) -> Result<ActivationReceipt> {
    let operation = catalog.matching_operation(request)?;
    if operation.operation_id != execution.last_operation_id || operation.kind != "restore_target" {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "operation is outside this target activation",
        ));
    }
    let receipt = catalog.activation(&execution.last_operation_id)?;
    if !receipt.matches(execution) {
        return Err(Fault::new(
            "E_STALE_EXECUTION",
            "activation belongs to another execution",
        ));
    }
    Ok(receipt)
}

fn verify_binding(
    catalog: &Catalog,
    execution: &Execution,
    record: &ActivationReceipt,
) -> Result<()> {
    let current = catalog.activation_binding(record.binding.input.clone(), execution)?;
    if catalog.activation_digest(&current)? == record.context_digest {
        return Ok(());
    }
    Err(Fault::new(
        "E_STALE_REVISION",
        "capture, network or writer binding changed",
    ))
}

impl ActivationRuntime {
    pub(crate) fn prepare(
        &mut self,
        catalog: &Catalog,
        execution: &Execution,
        request: &Request,
    ) -> Result<ActivationReceipt> {
        catalog.ready()?;
        let operation = catalog.active_operation(request)?;
        if operation.kind != "restore_target"
            || operation.operation_id != execution.last_operation_id
        {
            return Err(Fault::new(
                "E_STALE_EXECUTION",
                "operation is outside this target activation",
            ));
        }
        let input: ActivationInput = request.payload()?;
        let binding = catalog.activation_binding(input, execution)?;
        let context = catalog.activation_digest(&binding)?;
        match receipt(catalog, execution, request) {
            Ok(record) if record.context_digest == context => return Ok(record),
            Ok(_) => {
                return Err(Fault::new(
                    "E_IDEMPOTENCY_CONFLICT",
                    "activation binding changed",
                ))
            }
            Err(error) if error.code == "E_NOT_FOUND" => {}
            Err(error) => return Err(error),
        }
        let mut challenge = [0; 16];
        getrandom::fill(&mut challenge)
            .map_err(|_| Fault::new("E_HOST_IO", "cannot generate activation challenge"))?;
        let authority = TargetAuthority::new(
            challenge,
            execution.execution_epoch as u64,
            fixed_hex(&context)?,
        )?;
        let record = catalog.store_activation(&binding, challenge)?;
        self.authorities
            .insert(execution.last_operation_id.clone(), authority);
        Ok(record)
    }

    pub(crate) fn offer(
        &self,
        catalog: &Catalog,
        execution: &Execution,
        request: &Request,
    ) -> Result<(ActivationReceipt, OwnedFd)> {
        let record = receipt(catalog, execution, request)?;
        let revision: Revision = request.payload()?;
        match record.phase.as_str() {
            "authority_prepared" => check_revision(record.revision, revision.expected_revision)?,
            "offered" => check_revision(record.prior_revision, revision.expected_revision)?,
            _ => return Err(held()),
        }
        verify_binding(catalog, execution, &record)?;
        let fd = self.authority(&record)?.duplicate_for_vmm()?;
        let record = if record.phase == "authority_prepared" {
            catalog.transition_activation(&record, "offered", "none", None)?
        } else {
            record
        };
        Ok((record, fd))
    }

    pub(crate) fn begin(
        &mut self,
        catalog: &Catalog,
        execution: &Execution,
        request: &Request,
    ) -> Result<ActivationReceipt> {
        let record = receipt(catalog, execution, request)?;
        let data: Begin = request.payload()?;
        let frame = match &record.binding.network {
            None => fixed_hex::<FRAME_SIZE>(&data.frame_hex)?.to_vec(),
            Some(network) => {
                let frame = fixed_hex::<NETWORK_FRAME_SIZE>(&data.frame_hex)?;
                if frame[FRAME_SIZE..] != network.identity_bytes()? {
                    return Err(Fault::new(
                        "E_STALE_EXECUTION",
                        "Guest identity frame differs from the bound source or target network",
                    ));
                }
                frame.to_vec()
            }
        };
        let hash = hex::encode(Sha256::digest(&frame));
        if record
            .wire_digest
            .as_ref()
            .is_some_and(|digest| digest != &hash)
        {
            return Err(Fault::new(
                "E_IDEMPOTENCY_CONFLICT",
                "identity frame changed",
            ));
        }
        match record.phase.as_str() {
            "offered" => check_revision(record.revision, data.expected_revision)?,
            "applying" => check_revision(
                record.begin_revision.ok_or_else(held)?,
                data.expected_revision,
            )?,
            "identity_ready" | "committing" | "policy_armed" | "released" => {
                check_revision(
                    record.begin_revision.ok_or_else(held)?,
                    data.expected_revision,
                )?;
                return Ok(record);
            }
            _ => return Err(held()),
        }
        verify_binding(catalog, execution, &record)?;
        let authority = self
            .authorities
            .get_mut(&execution.last_operation_id)
            .ok_or_else(held)?;
        authority.check_frame(&frame)?;
        let record = if record.phase == "offered" {
            catalog.transition_activation(&record, "applying", "none", Some(&hash))?
        } else {
            record
        };
        let phase = authority.begin(&frame)?;
        Self::observe_held(catalog, &record, phase)
    }

    pub(crate) fn poll(
        &self,
        catalog: &Catalog,
        network: &NetworkRuntime,
        execution: &Execution,
        request: &Request,
        verify_process: impl Fn() -> Result<()>,
    ) -> Result<ActivationReceipt> {
        let record = receipt(catalog, execution, request)?;
        if !matches!(
            record.phase.as_str(),
            "applying" | "identity_ready" | "committing" | "policy_armed"
        ) {
            return Ok(record);
        }
        verify_binding(catalog, execution, &record)?;
        let phase = self.authority(&record)?.status()?;
        self.observe_activation(catalog, network, &record, phase, verify_process)
    }

    pub(crate) fn commit(
        &self,
        catalog: &Catalog,
        network: &NetworkRuntime,
        execution: &Execution,
        request: &Request,
        verify_process: impl Fn() -> Result<()>,
    ) -> Result<ActivationReceipt> {
        let mut record = receipt(catalog, execution, request)?;
        let revision: Revision = request.payload()?;
        match record.phase.as_str() {
            "identity_ready" => check_revision(record.revision, revision.expected_revision)?,
            "committing" | "policy_armed" | "released" => {
                check_revision(
                    record.commit_revision.ok_or_else(held)?,
                    revision.expected_revision,
                )?;
            }
            _ => return Err(held()),
        }
        if record.phase == "released" {
            return Ok(record);
        }
        verify_binding(catalog, execution, &record)?;
        let authority = self.authority(&record)?;
        if record.phase == "identity_ready" {
            let phase = authority.status()?;
            if phase != IdentityPhase::IdentityReady {
                Self::observe_held(catalog, &record, phase)?;
                return Err(held());
            }
            verify_process()?;
            // The caller's decision is durable before policy installation or Guest release.
            record = catalog.transition_activation(&record, "committing", "commit", None)?;
        }
        if let Some(binding) = &record.binding.network {
            if record.phase == "committing" {
                network.arm_target(binding)?;
                record = catalog.transition_activation(&record, "policy_armed", "commit", None)?;
            }
        }
        verify_process()?;
        let phase = authority.release()?;
        self.observe_activation(catalog, network, &record, phase, verify_process)
    }

    fn observe_activation(
        &self,
        catalog: &Catalog,
        network: &NetworkRuntime,
        record: &ActivationReceipt,
        observed: IdentityPhase,
        verify_process: impl Fn() -> Result<()>,
    ) -> Result<ActivationReceipt> {
        if observed != IdentityPhase::Released {
            return Self::observe_held(catalog, record, observed);
        }
        if record.decision != "commit" {
            return Err(held());
        }
        verify_process()?;
        match &record.binding.network {
            None if record.phase == "committing" => {
                catalog.transition_activation(record, "released", "commit", None)
            }
            Some(binding) if record.phase == "policy_armed" => {
                let published = network.publish_target(binding).and_then(|()| {
                    verify_process()?;
                    catalog.transition_activation(record, "released", "commit", None)
                });
                if published.is_err() && network.close_target(binding).is_err() {
                    catalog.transition_activation(record, "unknown", "commit", None)?;
                }
                published
            }
            _ => Err(held()),
        }
    }

    fn observe_held(
        catalog: &Catalog,
        record: &ActivationReceipt,
        observed: IdentityPhase,
    ) -> Result<ActivationReceipt> {
        let phase = match (record.phase.as_str(), observed) {
            ("applying", IdentityPhase::IdentityReady) => "identity_ready",
            (_, IdentityPhase::FailedHeld) => "failed_held",
            ("applying", IdentityPhase::Applying)
            | ("identity_ready", IdentityPhase::IdentityReady)
            | (
                "committing" | "policy_armed",
                IdentityPhase::Activating | IdentityPhase::IdentityReady,
            ) => return Ok(record.clone()),
            _ => return Err(held()),
        };
        catalog.transition_activation(record, phase, &record.decision, None)
    }

    fn authority(&self, record: &ActivationReceipt) -> Result<&TargetAuthority> {
        self.authorities
            .get(&record.binding.execution.operation_id)
            .ok_or_else(held)
    }

    pub(crate) fn forget(&mut self, execution: &Execution) {
        self.authorities.remove(&execution.last_operation_id);
    }
}
