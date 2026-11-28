//! Private System boot delivery from the original Serve to its exact VMM.
use super::{launch, native};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use smolvm_resourced::boot_environment::{self as protocol, Attempt, Delivery};
use smolvm_resourced::client::QueryError;
use smolvm_resourced::managed::Plan;
use smolvm_resourced::native_client::{Client, Launch, Submission};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_PENDING: usize = 64;
const GREETING: &[u8; 10] = b"SMOLBOOT1\n";
const DELIVERY: &[u8; 4] = b"ENV1";
const APPLIED: &[u8; 2] = b"OK";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    launch: Submission,
    environment: Attempt,
    nonce: String,
    values: BTreeMap<String, String>,
}

struct Pending {
    attempt: Attempt,
    request_digest: String,
    instance: String,
    preceding_epoch: i64,
    delivery: Delivery,
}

type PendingDeliveries = BTreeMap<String, Pending>;
static PENDING: OnceLock<Mutex<PendingDeliveries>> = OnceLock::new();

fn pending() -> std::sync::MutexGuard<'static, PendingDeliveries> {
    let mut pending = PENDING
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap();
    pending.retain(|_, entry| !entry.attempt.expired());
    pending
}

fn matches(entry: &Pending, plan: &Plan) -> bool {
    plan.boot_environment.as_ref() == Some(&entry.attempt)
        && entry.request_digest == plan.launch.request_digest
        && entry.instance == plan.launch.execution.instance_id
        && entry.preceding_epoch.checked_add(1) == Some(plan.launch.execution.execution_epoch)
}

pub(super) fn reap() {
    drop(pending());
}

pub(super) fn received(plan: &Plan) -> bool {
    pending()
        .get(&plan.launch.operation_id)
        .is_some_and(|entry| matches(entry, plan))
}

pub(super) fn take(plan: &Plan) -> Option<Delivery> {
    let mut pending = pending();
    let id = &plan.launch.operation_id;
    if pending.get(id).is_some_and(|entry| matches(entry, plan)) {
        return pending.remove(id).map(|entry| entry.delivery);
    }
    None
}

fn fault(code: &str, message: &str) -> QueryError {
    QueryError {
        code: code.into(),
        message: message.into(),
    }
}

pub(super) async fn probe(State(socket): State<PathBuf>) -> Response {
    native(socket, |client| client.boot_environment()).await
}

pub(super) async fn submit(State(socket): State<PathBuf>, body: axum::body::Bytes) -> Response {
    let Ok(input) = serde_json::from_slice::<Input>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(
                json!({"code":"E_INVALID_REQUEST","error":"Invalid boot environment request"}),
            ),
        )
            .into_response();
    };
    drop(body);
    native(socket, move |client| {
        let launch = input.launch;
        launch::require_own(&launch.expected.instance_id)?;
        if launch.kind != "launch"
            || launch.expected.incarnation_id.is_some()
            || !protocol::matches(&input.environment, &input.nonce, &input.values)
        {
            return Err(fault(
                "E_INVALID_REQUEST",
                "boot environment does not match its launch commitment",
            ));
        }
        launch::ensure_binding(client, &launch.expected.instance_id)?;
        {
            let pending = pending();
            if pending.len() >= MAX_PENDING && !pending.contains_key(&launch.operation_id) {
                return Err(fault(
                    "E_RESOURCE_LIMIT",
                    "too many pending boot environment deliveries",
                ));
            }
        }
        let receipt = client.submit_boot_environment(&launch, &input.environment)?;
        let mut pending = pending();
        if receipt.phase != "NEW" {
            pending.remove(&launch.operation_id);
        } else if !input.environment.expired()
            && (pending.len() < MAX_PENDING || pending.contains_key(&launch.operation_id))
        {
            let delivery = Delivery {
                revision: input.environment.revision,
                values: input.values,
            };
            pending.insert(
                launch.operation_id,
                Pending {
                    attempt: input.environment,
                    request_digest: launch.request_digest,
                    instance: launch.expected.instance_id,
                    preceding_epoch: launch.expected.execution_epoch,
                    delivery,
                },
            );
        }
        Ok(receipt)
    })
    .await
}

fn socket(control: &Path) -> PathBuf {
    // The Guest loader temporarily owns the standard Agent port during
    // sysinit. Keep the existing port layout so parked readers can rebind it.
    control.with_file_name("agent.sock")
}

pub(super) fn start(
    client: &Client<'_>,
    launch: &Launch,
    attempt: &Attempt,
    delivery: Delivery,
    control: &Path,
) -> std::io::Result<()> {
    let worker = client.socket.to_owned();
    let bundle = client.bundle.to_owned();
    let launch = launch.clone();
    let attempt = attempt.clone();
    let socket = socket(control);
    // Nothing is written to the Guest disk, kernel command line, or a host
    // environment. The listener is inside this incarnation's private directory.
    std::thread::Builder::new()
        .name("guest-boot-env".into())
        .spawn(move || {
            let client = Client {
                socket: &worker,
                bundle: &bundle,
            };
            if deliver(&socket, delivery, &attempt).is_err()
                || !acknowledge(&client, &launch, &attempt)
            {
                eprintln!("System Guest boot environment was not confirmed");
                // The Worker fences this VMM before recording the launch as aborted.
                std::process::exit(1);
            }
        })?;
    Ok(())
}

fn acknowledge(client: &Client<'_>, launch: &Launch, attempt: &Attempt) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .acknowledge_boot_environment(launch, attempt.revision)
            .is_ok()
        {
            return true;
        }
        if attempt.expired() || Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn deliver(path: &Path, delivery: Delivery, attempt: &Attempt) -> std::io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(75);
    let mut socket = loop {
        let stream = UnixStream::connect(path).and_then(|mut stream| {
            stream.set_read_timeout(Some(Duration::from_secs(1)))?;
            let mut hello = [0; GREETING.len()];
            stream.read_exact(&mut hello)?;
            if &hello != GREETING {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            Ok(stream)
        });
        if let Ok(stream) = stream {
            break stream;
        }
        if attempt.expired() || Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        std::thread::sleep(Duration::from_millis(150));
    };
    if attempt.expired() {
        return Err(std::io::ErrorKind::TimedOut.into());
    }
    let mut body = serde_json::to_vec(&delivery).map_err(|_| std::io::ErrorKind::InvalidData)?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let result = socket
        .write_all(DELIVERY)
        .and_then(|()| socket.write_all(&(body.len() as u32).to_be_bytes()))
        .and_then(|()| socket.write_all(&body));
    body.fill(0);
    result?;
    drop(delivery);
    let mut acknowledgement = [0; APPLIED.len()];
    socket.read_exact(&mut acknowledgement)?;
    if &acknowledgement != APPLIED {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn socket_fits_the_maximum_managed_incarnation_path() {
        let control = Path::new("/run/smolvm-custom/managed")
            .join("a".repeat(32))
            .join(format!("vmm-{}", "b".repeat(32)))
            .join("c.sock");
        let environment = socket(&control);
        assert_eq!(environment.parent(), control.parent());
        assert!(environment.as_os_str().as_bytes().len() <= 107);
    }
}
