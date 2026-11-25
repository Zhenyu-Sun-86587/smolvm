//! Typed Worker operations used by the local Serve and registered VMM processes.
use crate::client::{OperationReceipt, QueryError};
pub use crate::ipc::Expected as ExecutionRef;
use crate::ipc::{self, PROTOCOL, valid_digest, valid_id};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::os::fd::OwnedFd;
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
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub operation_id: String,
    pub request_digest: String,
    pub execution: ExecutionRef,
}

#[derive(Deserialize)]
struct Permit {
    launch_permit: String,
}
fn fault(code: &str, msg: impl ToString) -> QueryError {
    QueryError {
        code: code.into(),
        message: msg.to_string(),
    }
}

impl Client<'_> {
    pub fn register_bundle(&self, exe_hash: &str) -> Result<(), QueryError> {
        let r: Value = self.call(
            "RegisterBundle",
            None,
            None,
            json!({"executable_sha256":exe_hash}),
        )?;
        if r["bundle_digest"] != self.bundle || r["executable_sha256"] != exe_hash {
            return Err(fault("E_PROTOCOL_UNSUPPORTED", "wrong registered bundle"));
        }
        Ok(())
    }
    pub fn begin_launch(
        &self,
        prior: &ExecutionRef,
        launch: &Launch,
    ) -> Result<OperationReceipt, QueryError> {
        let begin = || {
            self.receipt(
                "BeginOperation",
                &launch.operation_id,
                &launch.request_digest,
                prior,
                json!({"kind":"launch"}),
            )
        };
        match begin() {
            Err(e) if e.code == "E_RECOVERING" => {
                let health: Value = self.call("Health", None, None, empty())?;
                let session = health["broker_session_id"]
                    .as_str()
                    .ok_or_else(|| fault("E_PROTOCOL_UNSUPPORTED", "missing recovery session"))?;
                let _: Value = self.call(
                    "CompleteRecovery",
                    None,
                    None,
                    json!({"broker_session_id":session}),
                )?;
                begin()
            }
            outcome => outcome,
        }
    }
    pub fn issue_permit(&self, launch: &Launch, pid: i32, uid: u32) -> Result<String, QueryError> {
        let permit: Permit = self.call(
            "IssueLaunchPermit",
            Some(&launch.execution),
            Some((&launch.operation_id, &launch.request_digest)),
            json!({"pid":pid,"uid":uid}),
        )?;
        Ok(permit.launch_permit)
    }
    pub fn register(&self, launch: &Launch, permit: &str) -> Result<(), QueryError> {
        let r: Value = self.call(
            "RegisterExecution",
            Some(&launch.execution),
            Some((&launch.operation_id, &launch.request_digest)),
            json!({"launch_permit":permit}),
        )?;
        let execution = &r["execution"];
        if execution["pid"] != std::process::id()
            || execution["uid"] != unsafe { libc::geteuid() }
            || execution["bundle_digest"] != self.bundle
            || execution["instance_id"] != launch.execution.instance_id
            || execution["incarnation_id"].as_str() != launch.execution.incarnation_id.as_deref()
            || execution["execution_epoch"] != launch.execution.execution_epoch
        {
            return Err(fault(
                "E_PROTOCOL_UNSUPPORTED",
                "wrong registered execution",
            ));
        }
        Ok(())
    }
    pub fn bind_control(&self, launch: &Launch, path: &Path) -> Result<(), QueryError> {
        let r: Value = self.call(
            "BindNativeControl",
            Some(&launch.execution),
            None,
            json!({"control_socket":path}),
        )?;
        if r["execution"]["incarnation_id"].as_str() != launch.execution.incarnation_id.as_deref()
            || r["inventory"]["protocol"] != "CaptureControl/1"
        {
            return Err(fault(
                "E_PROTOCOL_UNSUPPORTED",
                "wrong native control binding",
            ));
        }
        Ok(())
    }
    pub fn fence_exit(&self, expected: &ExecutionRef) -> Result<(), QueryError> {
        let r: Value = self.call("FinalizeExecutionExit", Some(expected), None, empty())?;
        if r["incarnation_id"].as_str() != expected.incarnation_id.as_deref()
            || r["phase"] != "exited"
        {
            return Err(fault(
                "E_FENCE_UNPROVEN",
                "Worker could not confirm execution exit",
            ));
        }
        Ok(())
    }
    pub fn finish_launch(
        &self,
        launch: &Launch,
        binding: &ExecutionRef,
        abort: bool,
        revision: i64,
    ) -> Result<(), QueryError> {
        let r: OperationReceipt = self.call(
            "FinishOperation",
            Some(binding),
            Some((&launch.operation_id, &launch.request_digest)),
            json!({"abort":abort,"expected_revision":revision}),
        )?;
        if r.operation_id != launch.operation_id
            || r.request_digest != launch.request_digest
            || r.bundle_digest != self.bundle
            || r.phase != if abort { "ABORTED" } else { "COMPLETED" }
        {
            return Err(fault("E_PROTOCOL_UNSUPPORTED", "wrong launch decision"));
        }
        Ok(())
    }
    fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        expected: Option<&ExecutionRef>,
        id: Option<(&str, &str)>,
        payload: Value,
    ) -> Result<T, QueryError> {
        let (result, table, descriptors) = self.call_packet(method, expected, id, payload)?;
        if !table.is_empty() || !descriptors.is_empty() {
            return Err(fault(
                "E_PROTOCOL_UNSUPPORTED",
                "unexpected Worker descriptor",
            ));
        }
        Ok(result)
    }
    fn call_packet<T: DeserializeOwned>(
        &self,
        method: &str,
        expected: Option<&ExecutionRef>,
        id: Option<(&str, &str)>,
        payload: Value,
    ) -> Result<(T, Vec<ipc::FdEntry>, Vec<OwnedFd>), QueryError> {
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
        // The broker hashes the complete running executable for enrollment.
        // This one-shot client can wait for that proof on a busy host without
        // increasing the server-side timeout for untrusted inbound packets.
        if matches!(
            method,
            "IssueLaunchPermit" | "RegisterExecution" | "BindNativeControl"
        ) {
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(20)))
                .map_err(transport)?;
        }
        if ipc::peer(&socket).map_err(transport)?.uid != 0 {
            return Err(fault(
                "E_PERMISSION_DENIED",
                "native operations require the privileged Worker endpoint",
            ));
        }
        ipc::send(&socket, &bytes).map_err(transport)?;
        let raw = ipc::receive_packet(&socket).map_err(|e| fault(e.code, e.message))?;
        #[derive(Deserialize)]
        struct Answer<T> {
            protocol: String,
            request_id: Option<String>,
            result: Option<T>,
            error: Option<QueryError>,
            #[serde(default)]
            fd_table: Vec<ipc::FdEntry>,
        }
        let reply: Answer<T> =
            serde_json::from_slice(&raw.body).map_err(|e| fault("E_PROTOCOL_UNSUPPORTED", e))?;
        if reply.protocol != PROTOCOL || reply.request_id.as_deref() != Some(method) {
            return Err(fault(
                "E_PROTOCOL_UNSUPPORTED",
                "wrong Worker response envelope",
            ));
        }
        match (reply.result, reply.error) {
            (Some(result), None) => Ok((result, reply.fd_table, raw.descriptors)),
            (None, Some(error)) => Err(error),
            _ => Err(fault("E_PROTOCOL_UNSUPPORTED", "invalid Worker result")),
        }
    }
    pub fn open_guest_agent(&self, expected: &ExecutionRef) -> Result<OwnedFd, QueryError> {
        let incarnation = expected
            .incarnation_id
            .as_deref()
            .filter(|id| valid_id(id))
            .ok_or_else(|| {
                fault(
                    "E_INVALID_REQUEST",
                    "Guest Agent requires an execution incarnation",
                )
            })?;
        if expected.execution_epoch < 1 || !valid_id(&expected.instance_id) {
            return Err(fault(
                "E_INVALID_REQUEST",
                "Guest Agent requires a live execution",
            ));
        }
        let (execution, table, mut descriptors): (Value, _, _) =
            self.call_packet("OpenGuestAgent", Some(expected), None, empty())?;
        if execution["route_id"] != "deep"
            || execution["bundle_digest"] != self.bundle
            || execution["instance_id"] != expected.instance_id
            || execution["incarnation_id"] != incarnation
            || execution["execution_epoch"] != expected.execution_epoch
            || execution["phase"] != "registered"
            || descriptors.len() != 1
            || table.len() != 1
            || table[0].index != 0
            || table[0].role != "guest_agent"
            || table[0].resource_id != incarnation
        {
            return Err(fault(
                "E_PROTOCOL_UNSUPPORTED",
                "Guest Agent descriptor scope differs from the verified execution",
            ));
        }
        Ok(descriptors.pop().expect("one checked descriptor"))
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
