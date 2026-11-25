//! Deep Runtime Bundle negotiation over the existing full Serve listener.
use crate::api::error::ApiError;
use axum::Json;
use sha2::{Digest, Sha256};
use smolvm_runtime_protocol::Handshake;
use std::{
    fs::File,
    io::{BufReader, Read},
};

static CAPABILITIES: tokio::sync::OnceCell<Handshake> = tokio::sync::OnceCell::const_new();
#[cfg(feature = "deep-runtime")]
mod guest_agent;
#[cfg(feature = "deep-runtime")]
pub(crate) mod launch;
#[cfg(all(target_os = "linux", feature = "deep-runtime"))]
pub(crate) mod managed;

fn installed_profile() -> Result<(Handshake, serde_json::Value, String), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let root = exe.parent().ok_or("missing bundle directory")?;
    let file = File::open(root.join("runtime-bundle.json"))
        .map_err(|_| "no installed RuntimeBundle/1 manifest")?;
    const LIMIT: u64 = 16 << 20;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > LIMIT {
        return Err("bundle manifest exceeds size limit".into());
    }
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut running = BufReader::new(File::open("/proc/self/exe").map_err(|e| e.to_string())?);
    std::io::copy(&mut running, &mut hash).map_err(|e| e.to_string())?;
    let binary_hash = format!("{:x}", hash.finalize());
    let handshake = smolvm_runtime_protocol::handshake(manifest.clone(), &binary_hash)
        .map_err(str::to_owned)?;
    #[cfg(feature = "deep-runtime")]
    let handshake = Handshake {
        capabilities: handshake
            .capabilities
            .into_iter()
            .map(|(name, mut value)| {
                if name == "boot.system" && value.supported && !launch::worker_configured() {
                    value.supported = false;
                    value.status = "unavailable".into();
                    value.reason_code = "WORKER_NOT_CONFIGURED".into();
                    value.contract_version = None;
                    value.verified_profile = None;
                }
                (name, value)
            })
            .collect(),
        runtime_instance_id: Some(
            crate::deep_state::instance_id().ok_or("missing deep Serve state identity")?,
        ),
        ..handshake
    };
    Ok((handshake, manifest, binary_hash))
}
fn installed() -> Result<Handshake, String> {
    installed_profile().map(|(handshake, _, _)| handshake)
}

pub(crate) async fn capabilities() -> Result<Json<&'static Handshake>, ApiError> {
    CAPABILITIES
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(installed)
                .await
                .map_err(ApiError::internal)?
                .map_err(ApiError::Unavailable)
        })
        .await
        .map(Json)
}

/// Read durable receipts from the operator-selected Worker on the private Serve socket.
pub fn worker_operations_router(socket: std::path::PathBuf) -> axum::Router {
    let router = axum::Router::new().route(
        "/api/v1/runtime-ext/v1/operations/{id}",
        axum::routing::get(operation),
    );
    #[cfg(feature = "deep-runtime")]
    let router = router
        .route(
            "/api/v1/runtime-ext/v1/operations",
            axum::routing::post(submit),
        )
        .route("/api/v1/runtime-ext/v1/operations/{id}/retry", axum::routing::post(retry_fork))
        .route(
            "/api/v1/runtime-ext/v1/operations/{id}/cancel",
            axum::routing::post(cancel),
        )
        .route(
            "/api/v1/runtime-ext/v1/instances/{id}/inventory",
            axum::routing::get(inventory),
        )
        .route(
            "/api/v1/runtime-ext/v1/machines/{name}/execution",
            axum::routing::get(machine_execution),
        )
        .route(
            "/api/v1/runtime-ext/v1/volumes",
            axum::routing::post(apply_volume),
        )
        .route(
            "/api/v1/runtime-ext/v1/volumes/{id}",
            axum::routing::get(volume),
        )
        .merge(guest_agent::router());
    #[cfg(all(target_os = "linux", feature = "deep-runtime"))]
    let router = {
        managed::dispatch(socket.clone());
        router.route(
            "/api/v1/runtime-ext/v1/machines/{name}/binding",
            axum::routing::get(machine_binding),
        )
    };
    router.with_state(socket)
}

#[cfg(feature = "deep-runtime")]
async fn apply_volume(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    Json(input): Json<smolvm_resourced::native_client::ProductVolumeMutation>,
) -> axum::response::Response {
    native(socket, move |client| {
        if let Some(instance) = input
            .command
            .get("instance_id")
            .and_then(serde_json::Value::as_str)
        {
            launch::require_own(instance)?;
        }
        client.apply_product_volume(&input)
    })
    .await
}

#[cfg(feature = "deep-runtime")]
async fn volume(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(owner): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    native(socket, move |client| {
        client.product_volume(&id, owner.get("owner_id").map(String::as_str).unwrap_or(""))
    })
    .await
}
#[cfg(feature = "deep-runtime")]
async fn machine_execution(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    native(socket, move |client| {
        let instance = launch::instance_id(&name)?;
        let binding = client.binding(&instance)?;
        if binding.incarnation_id.is_none() {
            return Err(smolvm_resourced::client::QueryError {
                code: "E_NOT_FOUND".into(),
                message: "machine has no registered execution".into(),
            });
        }
        let expected = binding.expected();
        if let Err(observation) = client.inventory(&expected) {
            if client.fence_exit(&expected).is_err() {
                return Err(observation);
            }
            return Err(smolvm_resourced::client::QueryError {
                code: "E_NOT_FOUND".into(),
                message: "machine execution has exited".into(),
            });
        }
        Ok(expected)
    })
    .await
}

async fn operation(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};
    let handshake = match capabilities().await {
        Ok(Json(handshake)) => handshake,
        Err(err) => return err.into_response(),
    };
    let response = tokio::task::spawn_blocking(move || {
        smolvm_resourced::client::query_operation(&socket, &handshake.bundle_digest, &id)
    })
    .await;
    match response {
        Ok(Ok(receipt)) => {
            #[cfg(feature = "deep-runtime")]
            if (receipt.native.is_some() || receipt.instance_id.starts_with("i-"))
                && launch::require_own(&receipt.instance_id).is_err()
            {
                return (StatusCode::NOT_FOUND, Json(serde_json::json!({"code":"E_NOT_FOUND","error":"unknown operation in this Serve"}))).into_response();
            }
            Json(receipt).into_response()
        }
        Ok(Err(err)) => {
            let status = match err.code.as_str() {
                "E_NOT_FOUND" => StatusCode::NOT_FOUND,
                "E_INVALID_REQUEST" => StatusCode::BAD_REQUEST,
                "E_PERMISSION_DENIED" => StatusCode::FORBIDDEN,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            (
                status,
                Json(serde_json::json!({"code": err.code, "error": err.message})),
            )
                .into_response()
        }
        Err(err) => ApiError::internal(err).into_response(),
    }
}

#[cfg(feature = "deep-runtime")]
async fn native<T: serde::Serialize + Send + 'static>(
    socket: std::path::PathBuf,
    action: impl FnOnce(
            &smolvm_resourced::native_client::Client,
        ) -> Result<T, smolvm_resourced::client::QueryError>
        + Send
        + 'static,
) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};
    let handshake = match capabilities().await {
        Ok(Json(h)) => h,
        Err(e) => return e.into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        action(&smolvm_resourced::native_client::Client {
            socket: &socket,
            bundle: &handshake.bundle_digest,
        })
    })
    .await;
    match result {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(err)) => {
            let status = match err.code.as_str() {
                "E_INVALID_REQUEST" => StatusCode::BAD_REQUEST,
                "E_NOT_FOUND" => StatusCode::NOT_FOUND,
                "E_PERMISSION_DENIED" => StatusCode::FORBIDDEN,
                "E_CAPABILITY_UNSUPPORTED" | "E_NATIVE_UNBOUND" => StatusCode::UNPROCESSABLE_ENTITY,
                "E_IDEMPOTENCY_CONFLICT"
                | "E_STALE_EXECUTION"
                | "E_OPERATION_IN_PROGRESS"
                | "E_STATE_CONFLICT"
                | "E_VOLUME_BUSY"
                | "E_VOLUME_GENERATION_MISMATCH"
                | "E_ALREADY_COMMITTED"
                | "E_STALE_REVISION" => StatusCode::CONFLICT,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            (
                status,
                Json(serde_json::json!({"code":err.code,"error":err.message})),
            )
                .into_response()
        }
        Err(error) => ApiError::internal(error).into_response(),
    }
}
#[cfg(feature = "deep-runtime")]
async fn submit(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    Json(input): Json<smolvm_resourced::native_client::Submission>,
) -> axum::response::Response {
    native(socket, move |client| {
        launch::require_own(&input.expected.instance_id)?;
        if matches!(input.kind.as_str(), "independent_fork" | "fork_batch" | "hibernate" | "vm_snapshot" | "vm_rollback") {
            return client.submit_fork(&input);
        }
        if input.kind == "launch" {
            launch::ensure_binding(client, &input.expected.instance_id)?;
            return client.managed_submit(&input);
        }
        client.submit(&input)
    })
    .await
}
#[cfg(feature = "deep-runtime")]
async fn retry_fork(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(input): Json<smolvm_resourced::native_client::Cancellation>,
) -> axum::response::Response {
    native(socket, move |client| {
        launch::require_own(&input.expected.instance_id)?;
        client.retry_fork(&id, &input)
    }).await
}
#[cfg(feature = "deep-runtime")]
async fn cancel(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(input): Json<smolvm_resourced::native_client::Cancellation>,
) -> axum::response::Response {
    native(socket, move |client| {
        launch::require_own(&input.expected.instance_id)?;
        client.cancel(&id, &input)
    })
    .await
}
#[cfg(feature = "deep-runtime")]
async fn inventory(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    native(socket, move |client| {
        launch::require_own(&id)?;
        client.inventory(&client.binding(&id)?.expected())
    })
    .await
}

#[cfg(all(target_os = "linux", feature = "deep-runtime"))]
async fn machine_binding(
    axum::extract::State(socket): axum::extract::State<std::path::PathBuf>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    native(socket, move |client| {
        let id = launch::instance_id(&name)?;
        let current = launch::ensure_binding(client, &id)?;
        if current.incarnation_id.is_some() && client.fence_exit(&current.expected()).is_ok() {
            return client.binding(&id);
        }
        Ok(current)
    })
    .await
}
