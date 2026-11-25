use clap::Subcommand;
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
}

impl RuntimeCmd {
    pub fn run(self) -> crate::Result<()> {
        let Self::Capabilities { socket } = self;
        let handshake = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(capabilities(socket))?;
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &handshake).map_err(io::Error::other)?;
        std::io::Write::write_all(&mut out, b"\n")?;
        Ok(())
    }
}

async fn capabilities(socket: PathBuf) -> crate::Result<Handshake> {
    let failed = |reason: String| crate::Error::command_failed("runtime capabilities", reason);
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| failed(err.to_string()))?;
    let mut response = client
        .get("http://localhost/api/v1/runtime-ext/v1/capabilities")
        .send()
        .await
        .map_err(|err| failed(err.to_string()))?;
    if !response.status().is_success() {
        return Err(failed(format!("Serve returned {}", response.status())));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| failed(err.to_string()))?
    {
        if bytes.len() + chunk.len() > 1 << 20 {
            return Err(failed("Serve handshake exceeds 1 MiB".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|err| failed(err.to_string()))
}
