//! Byte paths and staged transfers for the execution-scoped System Agent.

mod tree;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use smolvm_protocol::system_files_v2::{
    BytePath, BytesReceipt, Entry, Overwrite, Request, MAX_ARCHIVE_ENTRIES, MAX_BYTES, MAX_PAGE,
};
use smolvm_protocol::AgentResponse;

use super::{
    prepare_permissions, process, send_response, slot, with_keepalive, ConnectionPermit, ReadWrite,
    WireStream, CHUNK_SIZE,
};

const PATH_MAX: usize = 4096;
const LIST_SCAN_MAX: usize = 262_144;
const SYNC_PROBE: Duration = Duration::from_millis(500);
type Result<T> = std::result::Result<T, Fault>;

#[derive(Debug)]
struct Fault(&'static str, String);

impl Fault {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self(code, message.into())
    }

    fn response(self) -> AgentResponse {
        AgentResponse::error(self.1, self.0)
    }
}

impl From<io::Error> for Fault {
    fn from(err: io::Error) -> Self {
        let code = match err.raw_os_error() {
            Some(libc::ENOENT) => "NOT_FOUND",
            Some(libc::ENOTDIR) => "FILE_NOT_DIRECTORY",
            Some(libc::EISDIR) => "FILE_IS_DIRECTORY",
            Some(libc::EACCES | libc::EPERM) => "FILE_PERMISSION_DENIED",
            Some(libc::EEXIST | libc::ENOTEMPTY) => "FILE_EXISTS",
            Some(libc::EXDEV) => "FILE_CROSS_DEVICE",
            Some(libc::EBUSY) => "FILE_MOUNTPOINT",
            Some(libc::ELOOP) => "FILE_SYMLINK",
            Some(libc::EFBIG) => "FILE_TOO_LARGE",
            Some(libc::ENOSPC | libc::EDQUOT) => "FILE_NO_SPACE",
            Some(libc::EROFS) => "FILE_READ_ONLY",
            _ if err.kind() == io::ErrorKind::InvalidInput => "INVALID_REQUEST",
            _ => "FILE_IO_FAILED",
        };
        Self::new(code, err.to_string())
    }
}

pub(crate) struct Upload {
    destination: PathBuf,
    stage: tree::Stage,
    file: File,
    expected_size: u64,
    expected_hash: String,
    hash: Sha256,
    bytes: u64,
    overwrite: Overwrite,
    archive: bool,
    _slot: ConnectionPermit,
}

pub(crate) fn handle(
    stream: &mut WireStream<impl ReadWrite>,
    request: Request,
    upload: &mut Option<Upload>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let client = stream.as_raw_fd();
    let response = match request {
        Request::Capabilities => {
            let home = guest_home();
            reply(serde_json::json!({
                "home": home.to_string_lossy(), "home_bytes": bytes(&home),
                "max_upload_bytes": MAX_BYTES, "max_download_bytes": MAX_BYTES,
                "max_archive_entries": MAX_ARCHIVE_ENTRIES,
            }))
        }
        Request::List { path, limit, after } => {
            let _permit = match slot() {
                Ok(permit) => permit,
                Err(error) => return send_response(stream, &error),
            };
            list(&path, limit, after.as_ref()).unwrap_or_else(Fault::response)
        }
        Request::Stat { path, follow } => stat(&path, follow).unwrap_or_else(Fault::response),
        Request::Realpath { path } => realpath(&path).unwrap_or_else(Fault::response),
        Request::Read {
            path,
            offset,
            length,
        } => {
            let _permit = match slot() {
                Ok(permit) => permit,
                Err(error) => return send_response(stream, &error),
            };
            return download(stream, &path, offset, length);
        }
        Request::Archive { path } => {
            let _permit = match slot() {
                Ok(permit) => permit,
                Err(error) => return send_response(stream, &error),
            };
            let result = (|| {
                let path = path_from_bytes(&path, false)?;
                let mut wire = Download::new(stream);
                tree::export(path, &mut wire, client)?;
                wire.finish()
            })();
            result.unwrap_or_else(Fault::response)
        }
        Request::WriteBegin {
            path,
            size,
            sha256,
            overwrite,
            follow,
            archive,
        } => match begin(&path, size, sha256, overwrite, follow, archive) {
            Ok(staged) => {
                *upload = Some(staged);
                reply(())
            }
            Err(error) => error.response(),
        },
        Request::WriteChunk { data } => match upload.take() {
            Some(mut staged) => match staged.append(&data) {
                Ok(()) => {
                    *upload = Some(staged);
                    reply(())
                }
                Err(error) => error.response(),
            },
            None => invalid("no v2 write is staged on this connection").response(),
        },
        Request::WriteCommit => match upload.take() {
            Some(staged) => with_keepalive(stream, SYNC_PROBE, move || {
                staged.commit(client).unwrap_or_else(Fault::response)
            }),
            None => invalid("no v2 write is staged on this connection").response(),
        },
        operation => {
            let _permit = match slot() {
                Ok(permit) => permit,
                Err(error) => return send_response(stream, &error),
            };
            with_keepalive(stream, SYNC_PROBE, move || {
                tree::mutate(operation, client).unwrap_or_else(Fault::response)
            })
        }
    };
    send_response(stream, &response)
}

fn guest_home() -> PathBuf {
    let mut passwd = Vec::new();
    if File::open("/etc/passwd")
        .and_then(|file| file.take(1 << 20).read_to_end(&mut passwd))
        .is_ok()
    {
        for line in passwd.split(|byte| *byte == b'\n') {
            let fields: Vec<_> = line.splitn(7, |byte| *byte == b':').collect();
            if let [_, _, b"0", _, _, home, _] = fields.as_slice() {
                if let Ok(home) = path_from_bytes(&BytePath(home.to_vec()), true) {
                    return home.to_path_buf();
                }
            }
        }
    }
    PathBuf::from("/root")
}

fn invalid(message: impl Into<String>) -> Fault {
    Fault::new("INVALID_REQUEST", message)
}

fn limit(message: impl Into<String>) -> Fault {
    Fault::new("RESOURCE_LIMIT", message)
}

fn reply(data: impl Serialize) -> AgentResponse {
    AgentResponse::ok_with_data(serde_json::json!(data))
}

fn path_from_bytes(path: &BytePath, root: bool) -> Result<&Path> {
    let raw = &path.0;
    if raw != b"/" || !root {
        if raw.len() > PATH_MAX
            || raw.contains(&0)
            || !raw
                .strip_prefix(b"/")
                .is_some_and(|rest| rest.split(|b| *b == b'/').all(name_valid))
        {
            return Err(invalid("a clean absolute byte path is required"));
        }
    }
    Ok(Path::new(OsStr::from_bytes(raw)))
}

fn name_valid(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&0)
}

fn bytes(path: &Path) -> BytePath {
    BytePath(path.as_os_str().as_bytes().to_vec())
}

fn file_type(metadata: &Metadata) -> &'static str {
    let kind = metadata.file_type();
    if kind.is_file() {
        "file"
    } else if kind.is_dir() {
        "directory"
    } else if kind.is_symlink() {
        "symlink"
    } else if kind.is_fifo() {
        "fifo"
    } else if kind.is_socket() {
        "socket"
    } else if kind.is_char_device() {
        "character_device"
    } else if kind.is_block_device() {
        "block_device"
    } else {
        "other"
    }
}

fn wrong_type(metadata: &Metadata) -> Fault {
    if metadata.is_dir() {
        Fault::new("FILE_IS_DIRECTORY", "a regular file is required")
    } else {
        Fault::new(
            "FILE_SPECIAL_TYPE",
            format!("unsupported file type: {}", file_type(metadata)),
        )
    }
}

fn entry(path: &Path, metadata: &Metadata) -> Entry {
    Entry {
        name: path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned(),
        path: path.to_string_lossy().into_owned(),
        path_bytes: bytes(path),
        kind: file_type(metadata),
        size: metadata.size(),
        mode: metadata.mode() & 0o7777,
        modified_unix: metadata.mtime(),
    }
}

fn stat(path: &BytePath, follow: bool) -> Result<AgentResponse> {
    let path = path_from_bytes(path, true)?;
    let metadata = if follow {
        path.metadata()?
    } else {
        path.symlink_metadata()?
    };
    Ok(reply(entry(path, &metadata)))
}

fn realpath(path: &BytePath) -> Result<AgentResponse> {
    let path = path_from_bytes(path, true)?.canonicalize()?;
    Ok(reply(
        serde_json::json!({ "path": path.to_string_lossy(), "path_bytes": bytes(&path) }),
    ))
}

fn list(path: &BytePath, page: u16, after: Option<&BytePath>) -> Result<AgentResponse> {
    let path = path_from_bytes(path, true)?;
    let page = usize::from(page);
    if !(1..=usize::from(MAX_PAGE)).contains(&page) {
        return Err(invalid("list limit must be 1 through 200"));
    }
    let after = after
        .map(|cursor| {
            let cursor = path_from_bytes(cursor, false)?;
            if cursor.parent() != Some(path) {
                return Err(invalid("cursor is outside the selected directory"));
            }
            Ok(cursor.file_name().expect("non-root path").as_bytes())
        })
        .transpose()?;
    let dir = tree::open_path(path, true)?;
    if !dir.metadata()?.is_dir() {
        return Err(Fault::new("FILE_NOT_DIRECTORY", "a directory is required"));
    }
    let mut next = BTreeMap::new();
    for (index, item) in fs::read_dir(tree::fd_path(&dir))?.enumerate() {
        if index == LIST_SCAN_MAX {
            return Err(limit("directory exceeds the 262144-entry scan limit"));
        }
        let name = item?.file_name();
        if matches!(after, Some(after) if name.as_bytes() <= after) {
            continue;
        }
        next.insert(name, ());
        if next.len() > page + 1 {
            next.pop_last();
        }
    }
    let more = next.len() > page;
    if more {
        next.pop_last();
    }
    let mut items = Vec::with_capacity(next.len());
    for (name, ()) in next {
        let metadata = match tree::fd_path(&dir).join(&name).symlink_metadata() {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        let child = path.join(name);
        if child.as_os_str().len() > PATH_MAX {
            return Err(limit("listed path exceeds the 4096-byte protocol limit"));
        }
        items.push(entry(&child, &metadata));
    }
    // Advance past the last name even when it disappeared during this page.
    let next_cursor = more
        .then(|| {
            let last = items.last().map(|item| item.path_bytes.clone());
            last.ok_or_else(|| Fault::new("FILE_CHANGED", "directory changed during listing"))
        })
        .transpose()?;
    Ok(reply(
        serde_json::json!({ "items": items, "next_cursor": next_cursor }),
    ))
}

fn download(
    stream: &mut WireStream<impl ReadWrite>,
    path: &BytePath,
    offset: u64,
    length: Option<u64>,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let outcome = (|| {
        let pinned = tree::open_path(path_from_bytes(path, true)?, true)?;
        let metadata = pinned.metadata()?;
        if !metadata.is_file() {
            return Err(wrong_type(&metadata));
        }
        let size = metadata.size();
        if offset > size {
            return Err(Fault::new(
                "FILE_RANGE_INVALID",
                "read offset exceeds file size",
            ));
        }
        let size = length.unwrap_or(size - offset).min(size - offset);
        if size > MAX_BYTES {
            return Err(Fault::new(
                "FILE_TOO_LARGE",
                "read exceeds the 4 GiB transfer limit",
            ));
        }
        let mut file = File::open(tree::fd_path(&pinned))?;
        file.seek(SeekFrom::Start(offset))?;
        let mut writer = Download::new(stream);
        if io::copy(&mut file.take(size), &mut writer)? != size {
            return Err(Fault::new("FILE_CHANGED", "file shrank during read"));
        }
        writer.finish()
    })();
    send_response(stream, &outcome.unwrap_or_else(Fault::response))
}

// Buffer only a single chunk and hash exactly the bytes delivered to the wire.
struct Download<'stream, 'wire, S> {
    stream: &'stream mut WireStream<'wire, S>,
    buffer: Vec<u8>,
    hash: Sha256,
    bytes: u64,
}

impl<'stream, 'wire, S: ReadWrite> Download<'stream, 'wire, S> {
    fn new(stream: &'stream mut WireStream<'wire, S>) -> Self {
        Self {
            stream,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            hash: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(mut self) -> Result<AgentResponse> {
        self.flush()?;
        Ok(reply(BytesReceipt {
            bytes: self.bytes,
            sha256: format!("{:x}", self.hash.finalize()),
        }))
    }
}

impl<S: ReadWrite> Write for Download<'_, '_, S> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() as u64 > MAX_BYTES - self.bytes {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        let count = (CHUNK_SIZE - self.buffer.len()).min(data.len());
        self.buffer.extend_from_slice(&data[..count]);
        self.hash.update(&data[..count]);
        self.bytes += count as u64;
        if self.buffer.len() == CHUNK_SIZE {
            self.flush()?;
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let data = std::mem::replace(&mut self.buffer, Vec::with_capacity(CHUNK_SIZE));
        send_response(self.stream, &AgentResponse::DataChunk { data, done: false })
            .map_err(|err| io::Error::other(err.to_string()))
    }
}

fn begin(
    path: &BytePath,
    size: u64,
    hash: String,
    overwrite: Overwrite,
    follow: bool,
    archive: bool,
) -> Result<Upload> {
    if size > MAX_BYTES {
        return Err(Fault::new(
            "FILE_TOO_LARGE",
            "write exceeds the 4 GiB transfer limit",
        ));
    }
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
    {
        return Err(invalid("a lowercase SHA-256 digest is required"));
    }
    if archive && follow {
        return Err(invalid(
            "archive upload does not follow destination symlinks",
        ));
    }
    let target = path_from_bytes(path, archive)?;
    let destination = match tree::metadata(target)? {
        Some(info) if info.is_symlink() && follow => target.canonicalize()?,
        Some(info) if info.is_symlink() => {
            return Err(Fault::new("FILE_SYMLINK", "destination is a symlink"));
        }
        _ => target.to_path_buf(),
    };
    if archive {
        if !destination.metadata()?.is_dir() {
            return Err(Fault::new(
                "FILE_NOT_DIRECTORY",
                "archive parent must be a directory",
            ));
        }
    } else {
        file_destination(&destination, overwrite)?;
    }
    let _slot = slot().map_err(|_| limit("too many active System file requests"))?;
    let stage = tree::stage_in(if archive {
        &destination
    } else {
        tree::parent(&destination)?
    })?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(stage.path().join("data"))?;
    Ok(Upload {
        file,
        stage,
        destination,
        expected_size: size,
        expected_hash: hash,
        hash: Sha256::new(),
        bytes: 0,
        overwrite,
        archive,
        _slot,
    })
}

fn file_destination(path: &Path, overwrite: Overwrite) -> Result<()> {
    if let Some(info) = tree::metadata(path)? {
        if overwrite == Overwrite::Reject {
            return Err(Fault::new("FILE_EXISTS", "destination already exists"));
        }
        if info.is_symlink() {
            return Err(Fault::new("FILE_SYMLINK", "destination became a symlink"));
        }
        if !info.is_file() {
            return Err(wrong_type(&info));
        }
        if info.nlink() > 1 {
            return Err(Fault::new(
                "FILE_HARDLINK",
                "atomically replacing this file would separate its hard links",
            ));
        }
        tree::check_mountpoint(path)?;
    }
    Ok(())
}

impl Upload {
    fn append(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty()
            || data.len() > CHUNK_SIZE
            || data.len() as u64 > self.expected_size - self.bytes
        {
            return Err(invalid("write chunk exceeds its declared bounds"));
        }
        self.file.write_all(data)?;
        self.hash.update(data);
        self.bytes += data.len() as u64;
        Ok(())
    }

    fn commit(mut self, client: RawFd) -> Result<AgentResponse> {
        if self.bytes != self.expected_size
            || format!("{:x}", self.hash.finalize()) != self.expected_hash
        {
            return Err(Fault::new(
                "FILE_DIGEST_MISMATCH",
                "staged content did not match its intended size or SHA-256",
            ));
        }
        let path = if self.archive {
            self.file.rewind()?;
            let unpacked = self.stage.path().join("tree");
            fs::create_dir(&unpacked)?;
            let root = tree::extract(self.file, &unpacked, client)?;
            let destination = self
                .destination
                .join(root.file_name().expect("archive root name"));
            tree::publish(&root, &destination, self.overwrite, client)?;
            destination
        } else {
            file_destination(&self.destination, self.overwrite)?;
            prepare_permissions(&self.file, &self.destination).map_err(
                |response| match response {
                    AgentResponse::Error { message, .. } => Fault::new("FILE_IO_FAILED", message),
                    _ => unreachable!("permission checks return an Agent error"),
                },
            )?;
            let staged = self.stage.path().join("data");
            tree::publish(&staged, &self.destination, self.overwrite, client)?;
            self.destination
        };
        Ok(reply(serde_json::json!({
            "bytes": self.bytes, "sha256": self.expected_hash,
            "path": path.to_string_lossy(), "path_bytes": bytes(&path),
        })))
    }
}

fn check_connected(client: RawFd) -> Result<()> {
    if process::is_peer_closed(client) {
        return Err(Fault::new(
            "FILE_CANCELLED",
            "file client disconnected before commit",
        ));
    }
    Ok(())
}
