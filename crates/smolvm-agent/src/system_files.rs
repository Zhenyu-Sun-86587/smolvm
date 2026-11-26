//! Bounded transfer methods for the System Agent's VM filesystem.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::path::Path;

use smolvm_protocol::{
    error_codes, AgentRequest, AgentResponse, WorkloadTarget, FILE_TRANSFER_MAX_TOTAL,
};

use super::{
    collect_directory_entries, io_target, open_regular_vm_file, process, send_data_chunks_body,
    send_data_eof, send_response, with_keepalive, ConnectionPermit, ConnectionSemaphore, ReadWrite,
    WireStream, WriteSession, FILE_FINALIZE_KEEPALIVE,
};

const MAX_UPLOAD: u64 = 64 * 1024 * 1024;
const CHUNK_SIZE: usize = 256 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 4096;
const FILE_TOO_LARGE: &str = "FILE_TOO_LARGE";
static SLOTS: std::sync::LazyLock<ConnectionSemaphore> =
    std::sync::LazyLock::new(|| ConnectionSemaphore::new(8));

pub(super) struct Upload {
    file: WriteSession,
    _permit: ConnectionPermit,
}

pub(super) fn handle(
    stream: &mut WireStream<impl ReadWrite>,
    request: AgentRequest,
    upload: &mut Option<Upload>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = match request {
        AgentRequest::ListDirectory {
            path,
            target: Some(WorkloadTarget::Vm),
        } if valid_path(&path, true) => match slot() {
            Ok(_permit) => list(&path),
            Err(error) => error,
        },
        AgentRequest::FileRead {
            path,
            target: Some(WorkloadTarget::Vm),
        } if valid_path(&path, false) => match slot() {
            Ok(_permit) => return download(stream, &path),
            Err(error) => error,
        },
        AgentRequest::FileWriteBegin {
            path,
            total_size,
            target: Some(WorkloadTarget::Vm),
            mode: None,
            uid: None,
            gid: None,
        } if valid_path(&path, false) => match begin(path, total_size) {
            Ok(staged) => {
                *upload = Some(staged);
                AgentResponse::Ok { data: None }
            }
            Err(error) => error,
        },
        AgentRequest::FileWriteChunk { data, done } => match upload.take() {
            Some(staged) => write(stream, upload, staged, &data, done),
            None => invalid("no System file upload is staged on this connection"),
        },
        _ => invalid("System file request requires an absolute path and explicit VM target"),
    };
    send_response(stream, &response)
}

fn valid_path(path: &str, directory: bool) -> bool {
    if path == "/" {
        return directory;
    }
    path.len() <= 4096
        && !path.contains('\0')
        && path.strip_prefix('/').is_some_and(|rest| {
            rest.split('/')
                .all(|component| !component.is_empty() && component != "." && component != "..")
        })
}

fn invalid(message: &str) -> AgentResponse {
    AgentResponse::error(message, error_codes::INVALID_REQUEST)
}

fn slot() -> Result<ConnectionPermit, AgentResponse> {
    SLOTS.try_acquire().ok_or_else(|| {
        AgentResponse::error(
            "too many active System file requests",
            error_codes::RESOURCE_LIMIT,
        )
    })
}

fn io_error(message: String, err: io::Error) -> AgentResponse {
    let code = if err.kind() == io::ErrorKind::NotFound {
        error_codes::NOT_FOUND
    } else {
        error_codes::FILE_IO_FAILED
    };
    AgentResponse::error(format!("{message}: {err}"), code)
}

fn list(path: &str) -> AgentResponse {
    let mut read = match std::fs::read_dir(path) {
        Ok(read) => read,
        Err(err) => return io_error(format!("could not list directory {path}"), err),
    };
    let entries = collect_directory_entries(read.by_ref().take(MAX_DIRECTORY_ENTRIES));
    if read.next().is_some() {
        return AgentResponse::error(
            format!("directory exceeds the {MAX_DIRECTORY_ENTRIES}-entry limit"),
            error_codes::RESOURCE_LIMIT,
        );
    }
    AgentResponse::ok_with_data(serde_json::json!({ "entries": entries }))
}

fn download(
    stream: &mut WireStream<impl ReadWrite>,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (file, size) = match open_regular_vm_file(path, &io_target::IoRoot::Vm) {
        Ok(opened) => opened,
        Err(error) => return send_response(stream, &error),
    };
    let too_large = || AgentResponse::error("download exceeds the 4 GiB limit", FILE_TOO_LARGE);
    if size > FILE_TRANSFER_MAX_TOTAL {
        return send_response(stream, &too_large());
    }
    let mut bounded = file.take(FILE_TRANSFER_MAX_TOTAL);
    send_data_chunks_body(
        stream,
        &mut bounded,
        CHUNK_SIZE,
        "failed to read file",
        error_codes::FILE_IO_FAILED,
    )?;
    // Check for growth at the byte limit before issuing the terminal receipt.
    if bounded.limit() == 0 {
        let mut extra = [0];
        match bounded.into_inner().read_exact(&mut extra) {
            Ok(()) => return send_response(stream, &too_large()),
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {}
            Err(err) => {
                return send_response(stream, &io_error(format!("could not read {path}"), err))
            }
        }
    }
    send_data_eof(stream)
}

fn ensure_regular_destination(path: &Path) -> Result<(), AgentResponse> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(AgentResponse::error(
            format!(
                "upload destination is not a regular file: {}",
                path.display()
            ),
            error_codes::FILE_IO_FAILED,
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_error(
            format!("could not inspect {}", path.display()),
            err,
        )),
    }
}

fn begin(path: String, total_size: u64) -> Result<Upload, AgentResponse> {
    if total_size > MAX_UPLOAD {
        return Err(AgentResponse::error(
            "upload exceeds the 64 MiB limit",
            FILE_TOO_LARGE,
        ));
    }
    let permit = slot()?;
    let destination = Path::new(&path);
    ensure_regular_destination(destination)?;
    // The parent must already exist. Before commit only the staging file is
    // allowed to change, and closing the stream drops it.
    let file = WriteSession::open(
        path.clone(),
        Some(destination.to_path_buf()),
        None,
        None,
        None,
        total_size,
        io_target::IoRoot::Vm,
    )
    .map_err(|err| io_error(format!("could not stage upload to {path}"), err))?;
    Ok(Upload {
        file,
        _permit: permit,
    })
}

fn write(
    stream: &mut WireStream<impl ReadWrite>,
    upload: &mut Option<Upload>,
    mut staged: Upload,
    data: &[u8],
    done: bool,
) -> AgentResponse {
    if done {
        if !data.is_empty() {
            return invalid("System file commit must use an empty terminal frame");
        }
        let client = stream.as_raw_fd();
        return with_keepalive(stream, FILE_FINALIZE_KEEPALIVE, move || {
            let target = staged.file.guest_path.clone();
            let response = staged.file.finalize_checked(|| {
                if process::is_peer_closed(client) {
                    return Err(AgentResponse::error(
                        "System file client disconnected before commit",
                        error_codes::FILE_IO_FAILED,
                    ));
                }
                ensure_regular_destination(Path::new(&target))
            });
            match response {
                AgentResponse::Ok { .. } => AgentResponse::ok_with_data(
                    serde_json::json!({ "bytes_written": staged.file.bytes_written }),
                ),
                error => error,
            }
        });
    }
    if data.is_empty() || data.len() > CHUNK_SIZE {
        return invalid("System file chunk must carry 1 through 262144 bytes");
    }
    if let Err(error) = staged.file.write_chunk(data) {
        return error;
    }
    *upload = Some(staged);
    AgentResponse::Ok { data: None }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use super::*;
    use crate::{handle_connection, AgentMode};

    fn send(stream: &mut UnixStream, request: &AgentRequest) {
        stream
            .write_all(&smolvm_protocol::encode_message(request).unwrap())
            .unwrap();
    }

    fn receive(stream: &mut UnixStream) -> AgentResponse {
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut data = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut data).unwrap();
        serde_json::from_slice(&data).unwrap()
    }

    fn connect() -> (UnixStream, std::thread::JoinHandle<()>) {
        let (host, mut guest) = UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let task = std::thread::spawn(move || {
            handle_connection(&mut guest, AgentMode::SystemService).unwrap();
        });
        (host, task)
    }

    fn begin_request(path: String, total_size: u64) -> AgentRequest {
        AgentRequest::FileWriteBegin {
            path,
            total_size,
            target: Some(WorkloadTarget::Vm),
            mode: None,
            uid: None,
            gid: None,
        }
    }

    #[test]
    fn system_transfer_round_trips_and_keeps_the_original_until_commit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("test.bin");
        std::fs::write(&path, b"original").unwrap();
        let path_str = path.to_string_lossy().into_owned();
        let data: Vec<u8> = (0..700 * 1024).map(|i| (i % 256) as u8).collect();

        let (mut host, agent) = connect();
        send(&mut host, &AgentRequest::Ping);
        assert!(matches!(
            receive(&mut host),
            AgentResponse::Pong { capabilities, .. }
                if capabilities.iter().any(|name| name == smolvm_protocol::SYSTEM_FILE_TRANSFER_CAPABILITY)
        ));
        send(
            &mut host,
            &begin_request(path_str.clone(), data.len() as u64),
        );
        assert!(matches!(receive(&mut host), AgentResponse::Ok { .. }));
        for chunk in data.chunks(CHUNK_SIZE) {
            send(
                &mut host,
                &AgentRequest::FileWriteChunk {
                    data: chunk.to_vec(),
                    done: false,
                },
            );
            assert!(matches!(receive(&mut host), AgentResponse::Ok { .. }));
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        send(
            &mut host,
            &AgentRequest::FileWriteChunk {
                data: vec![],
                done: true,
            },
        );
        assert!(matches!(
            receive(&mut host),
            AgentResponse::Ok { data: Some(receipt) } if receipt["bytes_written"] == data.len()
        ));
        send(
            &mut host,
            &AgentRequest::ListDirectory {
                path: directory.path().to_string_lossy().into_owned(),
                target: Some(WorkloadTarget::Vm),
            },
        );
        assert!(matches!(
            receive(&mut host),
            AgentResponse::Ok { data: Some(listing) }
                if listing["entries"].as_array().is_some_and(|entries| entries.len() == 1)
                && listing["entries"][0]["name"] == "test.bin"
        ));
        send(
            &mut host,
            &AgentRequest::FileRead {
                path: path_str,
                target: Some(WorkloadTarget::Vm),
            },
        );
        let mut downloaded = Vec::new();
        loop {
            let AgentResponse::DataChunk { mut data, done } = receive(&mut host) else {
                panic!("expected a download data chunk");
            };
            assert!(data.len() <= CHUNK_SIZE);
            downloaded.append(&mut data);
            if done {
                break;
            }
        }
        assert_eq!(downloaded, data);
        drop(host);
        agent.join().unwrap();
    }

    #[test]
    fn system_transfer_rejects_non_vm_requests_and_drops_uncommitted_staging() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("file");
        std::fs::write(&path, b"original").unwrap();
        let path_str = path.to_string_lossy().into_owned();
        let (mut host, agent) = connect();

        send(
            &mut host,
            &AgentRequest::FileRead {
                path: path_str.clone(),
                target: None,
            },
        );
        assert!(matches!(
            receive(&mut host),
            AgentResponse::Error { code: Some(code), .. } if code == error_codes::INVALID_REQUEST
        ));
        send(&mut host, &begin_request(path_str.clone(), MAX_UPLOAD + 1));
        assert!(matches!(
            receive(&mut host),
            AgentResponse::Error { code: Some(code), .. } if code == FILE_TOO_LARGE
        ));
        send(&mut host, &begin_request(path_str, MAX_UPLOAD));
        assert!(matches!(receive(&mut host), AgentResponse::Ok { .. }));
        send(
            &mut host,
            &AgentRequest::FileWriteChunk {
                data: vec![1],
                done: false,
            },
        );
        assert!(matches!(receive(&mut host), AgentResponse::Ok { .. }));

        drop(host);
        agent.join().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
