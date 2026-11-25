//! Synchronous one-shot WorkerResource/1 queries for local control processes.

pub use crate::catalog::Operation as OperationReceipt;
use crate::ipc::{self, valid_digest, valid_id, PROTOCOL};
use serde::Deserialize;
use serde_json::json;
use std::{fmt, path::Path};

const ROUTE: &str = "deep";

#[derive(Clone, Debug, Deserialize)]
pub struct QueryError {
    pub code: String,
    pub message: String,
}

impl QueryError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for QueryError {}

#[derive(Deserialize)]
struct Response {
    protocol: String,
    request_id: Option<String>,
    result: Option<OperationReceipt>,
    error: Option<QueryError>,
}

/// Confirm that the privileged Worker and its Serve place VMMs in the same ancestor.
pub fn verify_worker_slice(socket_path: &Path) -> Result<(), QueryError> {
    let transport =
        |error: std::io::Error| QueryError::new("E_RESOURCED_UNAVAILABLE", error.to_string());
    let configured = crate::worker_scope::configured_slice()
        .map_err(|error| QueryError::new("E_INVALID_REQUEST", error.to_string()))?;
    let socket = ipc::connect(socket_path).map_err(transport)?;
    let peer = ipc::peer(&socket).map_err(transport)?;
    if peer.uid != 0 {
        return Err(QueryError::new(
            "E_PERMISSION_DENIED",
            "Worker slice authority requires a privileged local peer",
        ));
    }
    let request_id = "worker-slice";
    let request = json!({"protocol":PROTOCOL,"method":"Health","request_id":request_id});
    socket
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(transport)?;
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .map_err(transport)?;
    ipc::send(&socket, request.to_string().as_bytes()).map_err(transport)?;
    let bytes =
        ipc::receive(&socket).map_err(|error| QueryError::new(error.code, error.message))?;
    let response: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| QueryError::new("E_PROTOCOL_UNSUPPORTED", error.to_string()))?;
    if response["protocol"] != PROTOCOL
        || response["request_id"] != request_id
        || !response["result"].is_object()
        || response.get("error").is_some()
    {
        return Err(QueryError::new(
            "E_PROTOCOL_UNSUPPORTED",
            "Worker slice query did not receive a valid Health reply",
        ));
    }
    // Earlier Workers used the fixed default slice and have no override.
    let observed = response["result"].get("vm_slice").map_or(
        Some(crate::worker_scope::DEFAULT_SLICE),
        serde_json::Value::as_str,
    );
    if observed != Some(configured) {
        return Err(QueryError::new(
            "E_STATE_CONFLICT",
            "Serve and Worker VM slice settings differ",
        ));
    }
    Ok(())
}

/// Query one operation on the downstream Linux route using the caller's configured bundle digest.
pub fn query_operation(
    socket_path: &Path,
    bundle_digest: &str,
    operation_id: &str,
) -> Result<OperationReceipt, QueryError> {
    if !valid_id(operation_id) || !valid_digest(bundle_digest) {
        return Err(QueryError::new(
            "E_INVALID_REQUEST",
            "invalid operation ID or bundle digest",
        ));
    }
    let request_id = "query-operation";
    let request = json!({
        "protocol":PROTOCOL, "method":"QueryOperation", "request_id":request_id,
        "route_id":ROUTE, "bundle_digest":bundle_digest, "operation_id":operation_id,
    });
    let transport =
        |error: std::io::Error| QueryError::new("E_RESOURCED_UNAVAILABLE", error.to_string());
    let socket = ipc::connect(socket_path).map_err(transport)?;
    // One Worker serializes catalog mutations and executable measurement. A
    // read can legitimately queue behind a VMM registration or a disk import.
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(20)))
        .map_err(transport)?;
    ipc::send(&socket, request.to_string().as_bytes()).map_err(transport)?;
    let bytes = ipc::receive(&socket).map_err(|e| {
        let code = if e.code == "E_TRANSPORT" {
            "E_RESOURCED_UNAVAILABLE"
        } else {
            e.code
        };
        QueryError::new(code, e.message)
    })?;
    decode_receipt(&bytes, request_id, bundle_digest, operation_id)
}

fn decode_receipt(
    bytes: &[u8],
    request_id: &str,
    bundle_digest: &str,
    operation_id: &str,
) -> Result<OperationReceipt, QueryError> {
    let response: Response = serde_json::from_slice(bytes)
        .map_err(|e| QueryError::new("E_PROTOCOL_UNSUPPORTED", e.to_string()))?;
    if response.protocol != PROTOCOL || response.request_id.as_deref() != Some(request_id) {
        return Err(QueryError::new(
            "E_PROTOCOL_UNSUPPORTED",
            "operation query response did not match its request",
        ));
    }
    match (response.result, response.error) {
        (Some(receipt), None)
            if receipt.route_id == ROUTE
                && receipt.bundle_digest == bundle_digest
                && receipt.operation_id == operation_id =>
        {
            Ok(receipt)
        }
        (Some(_), None) => Err(QueryError::new(
            "E_NOT_FOUND",
            "operation receipt is outside the requested scope",
        )),
        (None, Some(error)) => Err(error),
        _ => Err(QueryError::new(
            "E_PROTOCOL_UNSUPPORTED",
            "invalid operation query response",
        )),
    }
}
