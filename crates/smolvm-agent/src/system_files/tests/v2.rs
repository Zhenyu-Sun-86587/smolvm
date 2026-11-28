use super::*;
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
    let got: BytePath = serde_json::from_value(listing["items"][0]["path_bytes"].clone()).unwrap();
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
fn system_transfer_v2_rejects_special_files_before_opening() {
    let directory = tempfile::tempdir().unwrap();
    let fifo = directory.path().join("fifo");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let socket_path = directory.path().join("socket");
    let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let (mut host, agent) = connect();
    host.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    for (path, expected) in [
        (fifo.as_path(), "FILE_SPECIAL_TYPE"),
        (socket_path.as_path(), "FILE_SPECIAL_TYPE"),
        (directory.path(), "FILE_IS_DIRECTORY"),
    ] {
        v2_send(
            &mut host,
            FileRequest::Read {
                path: byte_path(path),
                offset: 0,
                length: None,
            },
        );
        assert!(
            matches!(receive(&mut host), AgentResponse::Error { code: Some(code), .. } if code == expected)
        );
    }
    drop(host);
    agent.join().unwrap();
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
    let copied = directory.path().join("copied");
    v2_data(
        &mut host,
        FileRequest::Copy {
            path: byte_path(&target),
            destination: byte_path(&copied),
            recursive: true,
            overwrite: Overwrite::Reject,
        },
    );
    assert_eq!(
        std::fs::read_link(copied.join("link")).unwrap(),
        std::path::Path::new("data")
    );
    assert_eq!(
        std::fs::metadata(copied.join("data")).unwrap().ino(),
        std::fs::metadata(copied.join("hard")).unwrap().ino()
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
