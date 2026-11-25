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

fn installed() -> Result<Handshake, String> {
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
    let manifest = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut running = BufReader::new(File::open("/proc/self/exe").map_err(|e| e.to_string())?);
    std::io::copy(&mut running, &mut hash).map_err(|e| e.to_string())?;
    let handshake = smolvm_runtime_protocol::handshake(manifest, &format!("{:x}", hash.finalize()))
        .map_err(str::to_owned)?;
    #[cfg(feature = "deep-runtime")]
    let handshake = Handshake {
        runtime_instance_id: Some(
            crate::deep_state::instance_id().ok_or("missing deep Serve state identity")?,
        ),
        ..handshake
    };
    Ok(handshake)
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
    axum::Router::new()
        .route(
            "/api/v1/runtime-ext/v1/operations/{id}",
            axum::routing::get(operation),
        )
        .with_state(socket)
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
        Ok(Ok(receipt)) => Json(receipt).into_response(),
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
