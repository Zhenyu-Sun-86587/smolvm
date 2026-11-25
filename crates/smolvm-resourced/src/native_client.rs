//! Typed Worker operations used by the local Serve and registered VMM processes.
use crate::client::{OperationReceipt, QueryError};
pub use crate::ipc::Expected as ExecutionRef;
use crate::ipc::{self, valid_digest, valid_id, PROTOCOL};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub operation_id: String,
    pub request_digest: String,
    pub expected: ExecutionRef,
    pub kind: String,
    #[serde(default = "empty")]
    pub parameters: Value,
}
fn empty() -> Value {
    json!({})
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cancellation {
    pub request_digest: String,
    pub expected: ExecutionRef,
    pub expected_revision: i64,
}

#[derive(Serialize, Deserialize)]
pub struct Binding {
    pub instance_id: String,
    pub incarnation_id: Option<String>,
    pub execution_epoch: i64,
    pub active_operation_id: Option<String>,
}
impl Binding {
    pub fn expected(&self) -> ExecutionRef {
        ExecutionRef {
            instance_id: self.instance_id.clone(),
            incarnation_id: self.incarnation_id.clone(),
            execution_epoch: self.execution_epoch,
        }
    }
}
pub struct Client<'a> {
    pub socket: &'a Path,
    pub bundle: &'a str,
}
fn fault(code: &str, msg: impl ToString) -> QueryError {
    QueryError {
        code: code.into(),
        message: msg.to_string(),
    }
}

impl Client<'_> {
    fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        expected: Option<&ExecutionRef>,
        id: Option<(&str, &str)>,
        payload: Value,
    ) -> Result<T, QueryError> {
        if !self.socket.is_absolute() || !valid_digest(self.bundle) {
            return Err(fault(
                "E_INVALID_REQUEST",
                "invalid Worker endpoint or bundle",
            ));
        }
        if id.is_some_and(|(id, digest)| !valid_id(id) || !valid_digest(digest)) {
            return Err(fault("E_INVALID_REQUEST", "invalid operation identity"));
        }
        let packet = json!({"protocol":PROTOCOL,"request_id":method,"method":method,"route_id":"deep","bundle_digest":self.bundle,"expected":expected,
            "operation_id":id.map(|v|v.0),"request_digest":id.map(|v|v.1),"payload":payload});
        let bytes = serde_json::to_vec(&packet).map_err(|e| fault("E_INVALID_REQUEST", e))?;
        if bytes.len() > ipc::MAX_PACKET {
            return Err(fault(
                "E_RESOURCE_LIMIT",
                "Worker request exceeds packet limit",
            ));
        }
        let transport = |e| fault("E_RESOURCED_UNAVAILABLE", e);
        let socket = ipc::connect(self.socket).map_err(transport)?;
        if ipc::peer(&socket).map_err(transport)?.uid != 0 {
            return Err(fault(
                "E_PERMISSION_DENIED",
                "native operations require the privileged Worker endpoint",
            ));
        }
        ipc::send(&socket, &bytes).map_err(transport)?;
        let raw = ipc::receive(&socket).map_err(|e| fault(e.code, e.message))?;
        #[derive(Deserialize)]
        struct Answer<T> {
            protocol: String,
            request_id: Option<String>,
            result: Option<T>,
            error: Option<QueryError>,
        }
        let reply: Answer<T> =
            serde_json::from_slice(&raw).map_err(|e| fault("E_PROTOCOL_UNSUPPORTED", e))?;
        if reply.protocol != PROTOCOL || reply.request_id.as_deref() != Some(method) {
            return Err(fault(
                "E_PROTOCOL_UNSUPPORTED",
                "wrong Worker response envelope",
            ));
        }
        match (reply.result, reply.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(error),
            _ => Err(fault("E_PROTOCOL_UNSUPPORTED", "invalid Worker result")),
        }
    }
    pub fn binding(&self, instance: &str) -> Result<Binding, QueryError> {
        let r: Binding = self.call(
            "QueryInstanceBinding",
            None,
            None,
            json!({"instance_id":instance}),
        )?;
        if r.instance_id != instance || r.execution_epoch < 0 {
            return Err(fault("E_PROTOCOL_UNSUPPORTED", "wrong Worker instance"));
        }
        Ok(r)
    }
    pub fn inventory(&self, expected: &ExecutionRef) -> Result<Value, QueryError> {
        let r: Value = self.call("QueryNativeInventory", Some(expected), None, empty())?;
        if r["execution"]["bundle_digest"] != self.bundle
            || r["execution"]["instance_id"] != expected.instance_id
            || r["execution"]["execution_epoch"] != expected.execution_epoch
            || r["execution"]["incarnation_id"].as_str() != expected.incarnation_id.as_deref()
            || r["inventory"]["protocol"] != "CaptureControl/1"
        {
            return Err(fault("E_PROTOCOL_UNSUPPORTED", "inventory scope mismatch"));
        }
        Ok(r)
    }
    pub fn submit(&self, input: &Submission) -> Result<OperationReceipt, QueryError> {
        self.receipt(
            "SubmitNativeOperation",
            &input.operation_id,
            &input.request_digest,
            &input.expected,
            json!({"kind":input.kind,"parameters":input.parameters}),
        )
    }
    pub fn cancel(&self, id: &str, input: &Cancellation) -> Result<OperationReceipt, QueryError> {
        self.receipt(
            "CancelNativeOperation",
            id,
            &input.request_digest,
            &input.expected,
            json!({"expected_revision":input.expected_revision}),
        )
    }
    fn receipt(
        &self,
        method: &str,
        id: &str,
        digest: &str,
        expected: &ExecutionRef,
        payload: Value,
    ) -> Result<OperationReceipt, QueryError> {
        let r: OperationReceipt = self.call(method, Some(expected), Some((id, digest)), payload)?;
        if r.operation_id != id
            || r.request_digest != digest
            || r.bundle_digest != self.bundle
            || r.route_id != "deep"
            || r.instance_id != expected.instance_id
            || r.expected_execution_epoch != expected.execution_epoch
            || r.expected_incarnation_id != expected.incarnation_id
        {
            return Err(fault(
                "E_PROTOCOL_UNSUPPORTED",
                "Worker operation scope mismatch",
            ));
        }
        Ok(r)
    }
}
