//! Scoped WorkerResource/1 TAP handoff to an authenticated VMM.

use crate::client::QueryError;
use crate::ipc::{self, FdEntry, PROTOCOL};
pub use crate::network_lease_catalog::{AttachmentDescriptor, TapLease};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::os::fd::OwnedFd;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerNetworkScope {
    pub socket: PathBuf,
    pub bundle_digest: String,
    pub operation_id: String,
    pub request_digest: String,
    pub instance_id: String,
    pub incarnation_id: String,
    pub execution_epoch: i64,
    pub attachment_id: String,
}

#[derive(Deserialize)]
struct Response {
    protocol: String,
    request_id: Option<String>,
    result: Option<TapLease>,
    error: Option<QueryError>,
    #[serde(default)]
    fd_table: Vec<FdEntry>,
}

impl WorkerNetworkScope {
    pub fn acquire(&self) -> Result<(TapLease, OwnedFd), QueryError> {
        let (response, mut fds) = self.call(
            "AcquireNetworkAttachment",
            json!({"attachment_id":self.attachment_id}),
        )?;
        if fds.len() != 1
            || response.fd_table.len() != 1
            || response.fd_table[0].index != 0
            || response.fd_table[0].role != "network_tap"
            || response.fd_table[0].resource_id != self.attachment_id
        {
            return Err(protocol("expected one matching TAP descriptor"));
        }
        let lease = self.checked_lease(response)?;
        if !matches!(lease.state.as_str(), "offered" | "attached") || lease.gate != "closed" {
            return Err(protocol(
                "Worker did not offer a quarantined network attachment",
            ));
        }
        Ok((lease, fds.pop().expect("one checked descriptor")))
    }

    pub fn acknowledge(&self, lease: &TapLease) -> Result<TapLease, QueryError> {
        let (response, fds) = self.call(
            "AckNetworkAttachment",
            json!({
                "attachment_id": self.attachment_id,
                "lease_id": lease.lease_id,
                "expected_revision": if lease.state == "attached" { lease.revision - 1 } else { lease.revision },
            }),
        )?;
        if !fds.is_empty() || !response.fd_table.is_empty() {
            return Err(protocol("unexpected descriptor in network acknowledgement"));
        }
        let attached = self.checked_lease(response)?;
        if attached.state != "attached"
            || attached.gate != "closed"
            || attached.lease_id != lease.lease_id
            || attached.attachment != lease.attachment
            || attached.broker_session_id != lease.broker_session_id
        {
            return Err(protocol("network acknowledgement changed the lease"));
        }
        Ok(attached)
    }

    /// Publish the acknowledged lease of a cold execution. A restored target
    /// can open its port only through the private Guest activation authority.
    pub fn publish_initial(&self, lease: &TapLease) -> Result<TapLease, QueryError> {
        let (response, fds) = self.call(
            "PublishInitialNetworkAttachment",
            json!({
                "attachment_id": self.attachment_id,
                "lease_id": lease.lease_id,
                "expected_revision": lease.revision,
            }),
        )?;
        if !fds.is_empty() || !response.fd_table.is_empty() {
            return Err(protocol("unexpected descriptor in network publication"));
        }
        let published = self.checked_lease(response)?;
        if published.state != "attached"
            || published.gate != "open"
            || published.lease_id != lease.lease_id
            || published.revision != lease.revision
            || published.attachment != lease.attachment
            || published.broker_session_id != lease.broker_session_id
        {
            return Err(protocol("network publication changed the lease"));
        }
        Ok(published)
    }

    fn checked_lease(&self, mut response: Response) -> Result<TapLease, QueryError> {
        let lease = response
            .result
            .take()
            .ok_or_else(|| protocol("missing network lease result"))?;
        if lease.route_id != "deep"
            || lease.bundle_digest != self.bundle_digest
            || lease.operation_id != self.operation_id
            || lease.instance_id != self.instance_id
            || lease.incarnation_id.as_deref() != Some(&self.incarnation_id)
            || lease.execution_epoch != Some(self.execution_epoch)
            || lease.attachment.attachment_id != self.attachment_id
            || lease.attachment.schema != "NetworkAttachment/1"
            || !ipc::valid_id(&lease.lease_id)
            || lease.revision < 1
        {
            return Err(protocol(
                "Worker replied with a different network execution or attachment",
            ));
        }
        Ok(lease)
    }

    fn call(&self, method: &str, payload: Value) -> Result<(Response, Vec<OwnedFd>), QueryError> {
        if !self.socket.is_absolute() || self.execution_epoch <= 0 {
            return Err(protocol(
                "network launch requires a private Worker socket and active epoch",
            ));
        }
        let request = json!({
            "protocol": PROTOCOL,
            "request_id": method,
            "method": method,
            "route_id": "deep",
            "bundle_digest": self.bundle_digest,
            "operation_id": self.operation_id,
            "request_digest": self.request_digest,
            "expected": {
                "instance_id": self.instance_id,
                "incarnation_id": self.incarnation_id,
                "execution_epoch": self.execution_epoch,
            },
            "payload": payload,
        });
        let socket = ipc::connect(&self.socket).map_err(transport)?;
        if ipc::peer(&socket).map_err(transport)?.uid != 0 {
            return Err(protocol(
                "network attachment requires the privileged Worker peer",
            ));
        }
        ipc::send(&socket, request.to_string().as_bytes()).map_err(transport)?;
        let packet = ipc::receive_packet(&socket).map_err(|error| QueryError {
            code: error.code.to_owned(),
            message: error.message,
        })?;
        let mut response: Response = serde_json::from_slice(&packet.body)
            .map_err(|_| protocol("invalid network response"))?;
        if response.protocol != PROTOCOL || response.request_id.as_deref() != Some(method) {
            return Err(protocol("network response is outside this request"));
        }
        if let Some(error) = response.error.take() {
            return Err(error);
        }
        Ok((response, packet.descriptors))
    }
}

fn protocol(message: &str) -> QueryError {
    QueryError {
        code: "E_PROTOCOL_UNSUPPORTED".to_owned(),
        message: message.to_owned(),
    }
}

fn transport(error: std::io::Error) -> QueryError {
    QueryError {
        code: "E_RESOURCED_UNAVAILABLE".to_owned(),
        message: error.to_string(),
    }
}
