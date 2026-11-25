use clap::Subcommand;
use serde::{de::DeserializeOwned, Serialize};
use smolvm_resourced::client::OperationReceipt;
use smolvm_runtime_protocol::Handshake;
use std::{io, path::PathBuf, time::Duration};

#[derive(Subcommand, Debug)]
pub enum RuntimeCmd {
    /// Print the handshake returned by the selected Serve instance
    Capabilities {
        /// Unix socket of the deep Serve instance
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
    },
    /// Inspect operations registered with the Worker
    #[command(subcommand)]
    Operation(OperationCmd),
}

#[derive(Subcommand, Debug)]
pub enum OperationCmd {
    /// Read a durable receipt for this bundle
    Inspect {
        /// Operation ID returned on submission
        id: String,
        /// Unix socket of the deep Serve instance
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
    },
}

impl RuntimeCmd {
    pub fn run(self) -> crate::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        match self {
            Self::Capabilities { socket } => {
                print_json(runtime.block_on(query::<Handshake>(socket, &["capabilities"]))?)
            }
            Self::Operation(OperationCmd::Inspect { id, socket }) => {
                if id.is_empty() || id == "." || id == ".." {
                    return Err(crate::Error::config(
                        "inspect operation",
                        "invalid operation ID",
                    ));
                }
                print_json(
                    runtime.block_on(query::<OperationReceipt>(socket, &["operations", &id]))?,
                )
            }
        }
    }
}

fn print_json(value: impl Serialize) -> crate::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &value).map_err(io::Error::other)?;
    std::io::Write::write_all(&mut out, b"\n")?;
    Ok(())
}

async fn query<T: DeserializeOwned>(socket: PathBuf, parts: &[&str]) -> crate::Result<T> {
    let failed = |reason: String| crate::Error::command_failed("query runtime", reason);
    let mut url =
        reqwest::Url::parse("http://localhost/api/v1/runtime-ext/v1").expect("static URL");
    url.path_segments_mut().expect("HTTP URL").extend(parts);
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| failed(err.to_string()))?;
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|err| failed(err.to_string()))?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| failed(err.to_string()))?
    {
        if bytes.len() + chunk.len() > 1 << 20 {
            return Err(failed("Serve response exceeds 1 MiB".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        #[derive(serde::Deserialize)]
        struct Detail {
            code: String,
            error: String,
        }
        let message = match serde_json::from_slice::<Detail>(&bytes) {
            Ok(detail) => format!(
                "Serve returned {status} ({}): {}",
                detail.code, detail.error
            ),
            Err(_) => format!("Serve returned {status}"),
        };
        return Err(failed(message));
    }
    serde_json::from_slice(&bytes).map_err(|err| failed(err.to_string()))
}
