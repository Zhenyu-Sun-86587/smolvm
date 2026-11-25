use clap::Subcommand;
use serde::{de::DeserializeOwned, Serialize};
use smolvm_resourced::client::OperationReceipt;
use smolvm_runtime_protocol::Handshake;
use std::{io, path::PathBuf, time::Duration};

#[cfg(feature = "deep-runtime")]
#[derive(clap::Args, Debug)]
pub struct NativeMachineCmd {
    /// Named machine in this deep Serve
    #[arg(long)]
    name: String,
    /// Unix socket of the private Serve
    #[arg(long, env = "SMOLVM_SERVE_SOCKET")]
    socket: PathBuf,
    /// Reuse this ID when retrying a submitted transition
    #[arg(long)]
    operation_id: Option<String>,
}
#[cfg(feature = "deep-runtime")]
#[derive(clap::Args, Debug)]
pub struct StandbyCmd {
    #[command(flatten)]
    machine: NativeMachineCmd,
    /// Use the VMM-only standby boundary
    #[arg(long)]
    raw: bool,
}
#[cfg(feature = "deep-runtime")]
impl StandbyCmd {
    pub fn run(self) -> crate::Result<()> {
        self.machine.run(
            "standby",
            serde_json::json!({"mode": if self.raw {"raw"} else {"managed"}}),
        )
    }
}
#[cfg(feature = "deep-runtime")]
impl NativeMachineCmd {
    pub fn wake(self) -> crate::Result<()> {
        self.run("wake", serde_json::json!({}))
    }
    fn run(self, kind: &str, parameters: serde_json::Value) -> crate::Result<()> {
        use sha2::{Digest, Sha256};
        use smolvm_resourced::native_client::{ExecutionRef, Submission};
        crate::data::validate_vm_name(&self.name, "machine")
            .map_err(|e| crate::Error::config("native operation", e))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let expected: ExecutionRef = runtime.block_on(query(
            self.socket.clone(),
            &["machines", &self.name, "execution"],
        ))?;
        let id = match self.operation_id {
            Some(id) => id,
            None => {
                let mut random = [0u8; 16];
                getrandom::fill(&mut random).map_err(io::Error::other)?;
                hex::encode(random)
            }
        };
        let intent =
            serde_json::to_vec(&(&id, &expected, kind, &parameters)).map_err(io::Error::other)?;
        let input = Submission {
            operation_id: id.clone(),
            request_digest: format!("sha256:{:x}", Sha256::digest(intent)),
            expected,
            kind: kind.into(),
            parameters,
        };
        let payload = serde_json::to_value(input).map_err(io::Error::other)?;
        let receipt = runtime
            .block_on(request::<OperationReceipt>(
                self.socket,
                &["operations"],
                Some(payload),
            ))
            .map_err(|error| {
                crate::Error::command_failed("submit native operation", format!("{id}: {error}"))
            })?;
        print_json(receipt)
    }
}
#[derive(Subcommand, Debug)]
pub enum RuntimeCmd {
    /// Print the handshake returned by the selected Serve instance
    Capabilities {
        /// Unix socket of the deep Serve instance
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
    },
    #[cfg(feature = "deep-runtime")]
    /// Discover the registered execution of a named machine
    Execution {
        name: String,
        #[arg(long)]
        socket: PathBuf,
    },
    #[cfg(feature = "deep-runtime")]
    /// Inspect the devices and source disposition observed by the VMM
    Inventory {
        instance_id: String,
        #[arg(long)]
        socket: PathBuf,
    },
    /// Inspect operations registered with the Worker
    #[command(subcommand)]
    Operation(OperationCmd),
}

#[derive(Subcommand, Debug)]
pub enum OperationCmd {
    #[cfg(feature = "deep-runtime")]
    /// Submit a scoped operation envelope from a JSON file
    Submit {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
    #[cfg(feature = "deep-runtime")]
    /// Cancel a pending operation using its execution and revision
    Cancel {
        id: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        socket: PathBuf,
    },
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
            #[cfg(feature = "deep-runtime")]
            Self::Execution { name, socket } => print_json(runtime.block_on(query::<
                smolvm_resourced::native_client::ExecutionRef,
            >(
                socket,
                &["machines", &name, "execution"],
            ))?),
            #[cfg(feature = "deep-runtime")]
            Self::Inventory {
                instance_id,
                socket,
            } => print_json(runtime.block_on(query::<serde_json::Value>(
                socket,
                &["instances", &instance_id, "inventory"],
            ))?),
            #[cfg(feature = "deep-runtime")]
            Self::Operation(OperationCmd::Submit { input, socket }) => {
                let input: smolvm_resourced::native_client::Submission = read_input(&input)?;
                print_json(runtime.block_on(request::<OperationReceipt>(
                    socket,
                    &["operations"],
                    Some(serde_json::to_value(input).map_err(io::Error::other)?),
                ))?)
            }
            #[cfg(feature = "deep-runtime")]
            Self::Operation(OperationCmd::Cancel { id, input, socket }) => {
                let input: smolvm_resourced::native_client::Cancellation = read_input(&input)?;
                print_json(runtime.block_on(request::<OperationReceipt>(
                    socket,
                    &["operations", &id, "cancel"],
                    Some(serde_json::to_value(input).map_err(io::Error::other)?),
                ))?)
            }
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
#[cfg(feature = "deep-runtime")]
fn read_input<T: DeserializeOwned>(path: &std::path::Path) -> crate::Result<T> {
    use std::io::Read;
    let mut body = Vec::new();
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut body)?;
    if body.len() > 65536 {
        return Err(crate::Error::config(
            "read operation",
            "input exceeds 64 KiB",
        ));
    }
    serde_json::from_slice(&body).map_err(|e| crate::Error::config("read operation", e.to_string()))
}

fn print_json(value: impl Serialize) -> crate::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &value).map_err(io::Error::other)?;
    std::io::Write::write_all(&mut out, b"\n")?;
    Ok(())
}

async fn query<T: DeserializeOwned>(socket: PathBuf, parts: &[&str]) -> crate::Result<T> {
    request(socket, parts, None).await
}
async fn request<T: DeserializeOwned>(
    socket: PathBuf,
    parts: &[&str],
    body: Option<serde_json::Value>,
) -> crate::Result<T> {
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
    let builder = if let Some(payload) = body {
        client.post(url).json(&payload)
    } else {
        client.get(url)
    };
    let mut response = builder
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
