//! Private Guest management on the Worker-verified current VMM stream.
use axum::{
    Json, Router,
    extract::{Path, State},
    response::Response,
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use smolvm_resourced::{client::QueryError, native_client::ExecutionRef};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use crate::{agent::AgentClient, platform::uds::UdsStream};

const MAX_PAYLOAD: usize = 512 * 1024;

pub(super) fn router() -> Router<PathBuf> {
    Router::new()
        .route(
            "/api/v1/runtime-ext/v1/instances/{id}/guest/ping",
            post(ping),
        )
        .route(
            "/api/v1/runtime-ext/v1/instances/{id}/guest/exec",
            post(exec),
        )
        .route(
            "/api/v1/runtime-ext/v1/instances/{id}/guest/upload",
            post(upload),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scoped<T> {
    expected: ExecutionRef,
    request: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ping {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exec {
    command: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    cwd: Option<String>,
    stdin: Option<String>,
    timeout_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    path: String,
    data: String,
    mode: Option<u32>,
}

#[derive(Serialize)]
struct Reply {
    execution: ExecutionRef,
    result: Value,
}

fn invalid(message: &str) -> QueryError {
    QueryError {
        code: "E_INVALID_REQUEST".into(),
        message: message.into(),
    }
}

fn unavailable(_error: crate::Error) -> QueryError {
    QueryError {
        code: "E_GUEST_MANAGEMENT_UNAVAILABLE".into(),
        message: "could not finish a Guest Agent request on this execution".into(),
    }
}

async fn run<T: Send + 'static>(
    socket: PathBuf,
    instance: String,
    input: Scoped<T>,
    action: impl FnOnce(&mut AgentClient, T) -> Result<Value, QueryError> + Send + 'static,
) -> Response {
    super::native(socket, move |worker| {
        if instance != input.expected.instance_id {
            return Err(invalid(
                "Guest Agent execution is outside the requested instance",
            ));
        }
        super::launch::require_own(&instance)?;
        let fd = worker.open_guest_agent(&input.expected)?;
        let stream = UdsStream::from_socket(socket2::Socket::from(fd));
        let mut agent = AgentClient::over_connected(stream).map_err(unavailable)?;
        let result = action(&mut agent, input.request)?;
        Ok(Reply {
            execution: input.expected,
            result,
        })
    })
    .await
}

async fn ping(
    State(socket): State<PathBuf>,
    Path(id): Path<String>,
    Json(input): Json<Scoped<Ping>>,
) -> Response {
    run(socket, id, input, |agent, _| {
        let (protocol, capabilities) = agent.ping_info().map_err(unavailable)?;
        Ok(json!({"protocol": protocol, "capabilities": capabilities}))
    })
    .await
}

async fn exec(
    State(socket): State<PathBuf>,
    Path(id): Path<String>,
    Json(input): Json<Scoped<Exec>>,
) -> Response {
    run(socket, id, input, |agent, input| {
        if input.command.first().is_none_or(|first| first.is_empty()) || !(1..=120).contains(&input.timeout_seconds) ||
            input.stdin.as_ref().is_some_and(|stdin| stdin.len() > MAX_PAYLOAD) {
            return Err(invalid("invalid Guest command, input or timeout"));
        }
        let (code, stdout, stderr) = agent.vm_exec(
            input.command, input.env.into_iter().collect(), input.cwd,
            Some(Duration::from_secs(input.timeout_seconds)), input.stdin,
        ).map_err(unavailable)?;
        if stdout.len().saturating_add(stderr.len()) > MAX_PAYLOAD {
            return Err(QueryError { code: "E_RESOURCE_LIMIT".into(), message: "Guest command output exceeds the private API response limit".into() });
        }
        Ok(json!({"exit_code": code, "stdout": STANDARD.encode(stdout), "stderr": STANDARD.encode(stderr)}))
    }).await
}

async fn upload(
    State(socket): State<PathBuf>,
    Path(id): Path<String>,
    Json(input): Json<Scoped<Upload>>,
) -> Response {
    run(socket, id, input, |agent, input| {
        if !input.path.starts_with('/')
            || input.path.contains('\0')
            || input.mode.is_some_and(|mode| mode > 0o777)
            || input.data.len() > MAX_PAYLOAD.div_ceil(3) * 4
        {
            return Err(invalid("invalid Guest file path, mode or data length"));
        }
        let data = STANDARD
            .decode(input.data)
            .map_err(|_| invalid("Guest file data must be base64"))?;
        if data.len() > MAX_PAYLOAD {
            return Err(invalid("Guest file exceeds the private API payload limit"));
        }
        if !agent.supports_capability(smolvm_protocol::SYSTEM_FILE_WRITE_CAPABILITY).map_err(unavailable)? {
            return Err(QueryError {
                code: "E_CAPABILITY_UNSUPPORTED".into(),
                message: "the guest does not advertise System file writes".into(),
            });
        }
        agent.write_system_file(&input.path, &data, input.mode).map_err(unavailable)?;
        Ok(json!({"bytes_written": data.len()}))
    })
    .await
}
