//! Bounded transfer methods for the System Agent's VM filesystem.

pub(super) mod v2;

use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{fchown, MetadataExt, OpenOptionsExt, PermissionsExt};
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
    _staging: tempfile::TempDir,
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

fn regular_destination(path: &Path) -> Result<Option<Metadata>, AgentResponse> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_file() => Ok(Some(metadata)),
        Ok(_) => Err(AgentResponse::error(
            format!(
                "upload destination is not a regular file: {}",
                path.display()
            ),
            error_codes::FILE_IO_FAILED,
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
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
    let destination = Path::new(&path).to_path_buf();
    regular_destination(&destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("System upload destination requires a parent directory"))?;
    // Keep the staging inode in a private directory on the destination
    // filesystem. Applying final ownership and mode cannot expose staged data.
    let staging = tempfile::Builder::new()
        .prefix(".smolvm-upload.")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .map_err(|err| io_error(format!("could not stage upload to {path}"), err))?;
    let tmp_path = staging.path().join("data");
    let tmp_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|err| io_error(format!("could not stage upload to {path}"), err))?;
    let file = WriteSession {
        guest_path: path,
        target: Some(destination),
        tmp_path,
        tmp_file,
        mode: None,
        uid: None,
        gid: None,
        bytes_written: 0,
        total_size,
        root: io_target::IoRoot::Vm,
    };
    Ok(Upload {
        file,
        _staging: staging,
        _permit: permit,
    })
}

fn prepare_permissions(file: &File, destination: &Path) -> Result<(), AgentResponse> {
    let metadata_error = |err| {
        io_error(
            format!("could not apply permissions for {}", destination.display()),
            err,
        )
    };
    let mut mode = 0o600;
    if let Some(target) = regular_destination(destination)? {
        let staged = file.metadata().map_err(metadata_error)?;
        let uid = (staged.uid() != target.uid()).then(|| target.uid());
        let gid = (staged.gid() != target.gid()).then(|| target.gid());
        if uid.is_some() || gid.is_some() {
            fchown(file, uid, gid).map_err(metadata_error)?;
        }
        // Preserve access and execute bits. A replacement cannot inherit
        // privileged execution bits from the prior contents.
        mode = target.mode() & 0o777;
    }
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(metadata_error)?;
    file.sync_all().map_err(metadata_error)
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
            let response = staged.file.finalize_checked(|file, target| {
                prepare_permissions(file, target)?;
                if process::is_peer_closed(client) {
                    return Err(AgentResponse::error(
                        "System file client disconnected before commit",
                        error_codes::FILE_IO_FAILED,
                    ));
                }
                Ok(())
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
    fn system_transfer_stages_privately_and_preserves_ordinary_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let (mut host, agent) = connect();
        for (name, original_mode, final_mode) in [
            ("private", Some(0o600), 0o600),
            ("program", Some(0o6751), 0o751),
            ("new", None, 0o600),
        ] {
            let target = directory.path().join(name);
            let original_owner = original_mode.map(|mode| {
                std::fs::write(&target, b"old").unwrap();
                if target.metadata().unwrap().uid() == 0 {
                    std::os::unix::fs::chown(&target, Some(65534), Some(65534)).unwrap();
                }
                std::fs::set_permissions(&target, Permissions::from_mode(mode)).unwrap();
                let metadata = target.metadata().unwrap();
                (metadata.uid(), metadata.gid())
            });

            send(
                &mut host,
                &begin_request(target.to_string_lossy().into_owned(), 1),
            );
            assert!(matches!(receive(&mut host), AgentResponse::Ok { .. }));
            send(
                &mut host,
                &AgentRequest::FileWriteChunk {
                    data: vec![42],
                    done: false,
                },
            );
            assert!(matches!(receive(&mut host), AgentResponse::Ok { .. }));

            let staging = std::fs::read_dir(directory.path())
                .unwrap()
                .find_map(|entry| {
                    let entry = entry.unwrap();
                    entry.file_type().unwrap().is_dir().then(|| entry.path())
                })
                .unwrap();
            assert_eq!(staging.metadata().unwrap().mode() & 0o777, 0o700);
            assert_eq!(
                staging.join("data").metadata().unwrap().mode() & 0o777,
                0o600
            );
            if original_mode.is_some() {
                assert_eq!(std::fs::read(&target).unwrap(), b"old");
            } else {
                assert!(!target.exists());
            }

            send(
                &mut host,
                &AgentRequest::FileWriteChunk {
                    data: vec![],
                    done: true,
                },
            );
            assert!(matches!(
                receive(&mut host),
                AgentResponse::Ok { data: Some(receipt) } if receipt["bytes_written"] == 1
            ));
            assert!(!staging.exists());
            assert_eq!(std::fs::read(&target).unwrap(), [42]);
            let metadata = target.metadata().unwrap();
            assert_eq!(metadata.mode() & 0o7777, final_mode);
            if let Some(owner) = original_owner {
                assert_eq!((metadata.uid(), metadata.gid()), owner);
            }
        }
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

    use smolvm_protocol::system_files_v2::{BytePath, Overwrite, Request as FileRequest};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    fn byte_path(path: &Path) -> BytePath {
        BytePath(path.as_os_str().as_bytes().to_vec())
    }

    fn v2_send(stream: &mut UnixStream, request: FileRequest) {
        send(stream, &AgentRequest::SystemFilesV2 { request });
    }

    fn v2_data(stream: &mut UnixStream, request: FileRequest) -> serde_json::Value {
        v2_send(stream, request);
        match receive(stream) {
            AgentResponse::Ok { data } => data.unwrap_or(serde_json::Value::Null),
            other => panic!("expected v2 receipt, got {other:?}"),
        }
    }

    fn v2_upload(
        stream: &mut UnixStream,
        path: &Path,
        data: &[u8],
        archive: bool,
        finish: bool,
    ) -> AgentResponse {
        use sha2::{Digest, Sha256};
        assert!(v2_data(
            stream,
            FileRequest::WriteBegin {
                path: byte_path(path),
                size: data.len() as u64,
                sha256: format!("{:x}", Sha256::digest(data)),
                overwrite: Overwrite::Replace,
                follow: false,
                archive,
            }
        )
        .is_null());
        for chunk in data.chunks(CHUNK_SIZE) {
            assert!(v2_data(
                stream,
                FileRequest::WriteChunk {
                    data: chunk.to_vec()
                }
            )
            .is_null());
        }
        if !finish {
            return AgentResponse::ok_with_data(serde_json::Value::Null);
        }
        v2_send(stream, FileRequest::WriteCommit);
        loop {
            let response = receive(stream);
            if !matches!(response, AgentResponse::Progress { .. }) {
                return response;
            }
        }
    }

    fn v2_stream(stream: &mut UnixStream, request: FileRequest) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        v2_send(stream, request);
        let mut result = Vec::new();
        loop {
            match receive(stream) {
                AgentResponse::DataChunk { data, done: false } => result.extend(data),
                AgentResponse::Ok {
                    data: Some(receipt),
                } => {
                    assert_eq!(receipt["bytes"], result.len());
                    assert_eq!(receipt["sha256"], format!("{:x}", Sha256::digest(&result)));
                    return result;
                }
                other => panic!("expected v2 chunk or receipt, got {other:?}"),
            }
        }
    }

    #[test]
    fn system_transfer_v2_round_trips_bytes_range_and_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let name = std::ffi::OsString::from_vec(b"binary-\xff".to_vec());
        let target = directory.path().join(name);
        let payload: Vec<_> = (0..700 * 1024).map(|i| (i % 251) as u8).collect();
        let (mut host, agent) = connect();
        send(&mut host, &AgentRequest::Ping);
        assert!(
            matches!(receive(&mut host), AgentResponse::Pong { version: 1, capabilities }
            if capabilities.iter().any(|cap| cap == smolvm_protocol::system_files_v2::CAPABILITY))
        );
        let result = v2_upload(&mut host, &target, &payload, false, true);
        assert!(
            matches!(result, AgentResponse::Ok { data: Some(receipt) } if receipt["bytes"] == payload.len())
        );

        let listing = v2_data(
            &mut host,
            FileRequest::List {
                path: byte_path(directory.path()),
                limit: 1,
                after: None,
            },
        );
        let got: BytePath =
            serde_json::from_value(listing["items"][0]["path_bytes"].clone()).unwrap();
        assert_eq!(got.0, byte_path(&target).0);
        assert_eq!(
            v2_stream(
                &mut host,
                FileRequest::Read {
                    path: got,
                    offset: 17,
                    length: Some(314_159),
                }
            ),
            payload[17..314_176]
        );
        assert!(matches!(
            v2_upload(&mut host, &target, b"replacement", false, false),
            AgentResponse::Ok { .. }
        ));
        drop(host);
        agent.join().unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), payload);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn system_transfer_v2_archival_replacement_and_link_semantics() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("tree");
        let payload = b"\x00binary\xff";
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("data"), payload).unwrap();
        std::fs::hard_link(target.join("data"), target.join("hard")).unwrap();
        symlink("data", target.join("link")).unwrap();
        let (mut host, agent) = connect();
        let archive = v2_stream(
            &mut host,
            FileRequest::Archive {
                path: byte_path(&target),
            },
        );
        std::fs::write(target.join("old-only"), b"old").unwrap();
        let receipt = v2_upload(&mut host, directory.path(), &archive, true, true);
        assert!(
            matches!(receipt, AgentResponse::Ok { data: Some(receipt) } if receipt["bytes"] == archive.len())
        );
        let data = target.join("data");
        assert_eq!(std::fs::read(&data).unwrap(), payload);
        assert_eq!(
            std::fs::metadata(&data).unwrap().ino(),
            std::fs::metadata(target.join("hard")).unwrap().ino()
        );
        assert!(!target.join("old-only").exists());
        assert_eq!(
            v2_data(
                &mut host,
                FileRequest::Stat {
                    path: byte_path(&target.join("link")),
                    follow: false
                }
            )["type"],
            "symlink"
        );
        assert_eq!(
            v2_data(
                &mut host,
                FileRequest::Stat {
                    path: byte_path(&target.join("link")),
                    follow: true
                }
            )["type"],
            "file"
        );
        v2_data(
            &mut host,
            FileRequest::Remove {
                path: byte_path(&target.join("link")),
                recursive: true,
            },
        );
        assert_eq!(std::fs::read(&data).unwrap(), payload);
        let mut corrupt = archive;
        let last = corrupt.len() - 1;
        corrupt[last] = 1;
        let receipt = v2_upload(&mut host, directory.path(), &corrupt, true, true);
        assert!(
            matches!(receipt, AgentResponse::Error { code: Some(code), .. } if code == "FILE_ARCHIVE_INVALID")
        );
        assert!(!target.join("link").exists());
        drop(host);
        agent.join().unwrap();
    }
}
