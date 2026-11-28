use super::{host, topology, unavailable, Disk, Input, Operation, MAX_TRANSFER, STANDARD};
use crate::ipc::{Fault, Result};
use base64::Engine;
use imago::{file::File as ImageFile, qcow2::Qcow2, raw::Raw, DynStorage, FormatAccess};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::{CString, OsStr, OsString},
    fs::{self, File, Metadata},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{FileExt, FileTypeExt, MetadataExt},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};

struct Namespace {
    work: tempfile::TempDir,
    disks: BTreeMap<usize, Disk>,
    mounted: BTreeMap<usize, PathBuf>,
    mounts: BTreeMap<Vec<u8>, Mount>,
}
struct Mount {
    detail: topology::Mount,
    slot: Option<usize>,
    reason: Option<&'static str>,
}

fn filesystem_reason(mount: &topology::Mount) -> &'static str {
    match mount.filesystem.as_str() {
        "tmpfs" | "ramfs" => "memory_only",
        "proc" | "sysfs" | "devpts" | "devtmpfs" | "cgroup" | "cgroup2" => "kernel_filesystem",
        "nfs" | "nfs4" | "cifs" | "smb3" | "9p" | "virtiofs" => "external_filesystem",
        _ => "unsupported_filesystem_or_device",
    }
}
fn as_path(path: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(path))
}
fn wire_path(path: &[u8]) -> (String, String) {
    (
        String::from_utf8_lossy(path).into_owned(),
        STANDARD.encode(path),
    )
}
fn append(base: &[u8], name: &[u8]) -> Vec<u8> {
    if base == b"/" {
        [base, name].concat()
    } else {
        [base, b"/", name].concat()
    }
}
fn parent(path: &[u8]) -> &[u8] {
    path.iter()
        .rposition(|&byte| byte == b'/')
        .filter(|&i| i > 0)
        .map_or(b"/", |i| &path[..i])
}
fn not_found() -> Fault {
    Fault::new("E_NOT_FOUND", "path does not exist in this saved view")
}
fn path_error(error: io::Error) -> Fault {
    match error.kind() {
        io::ErrorKind::NotFound => not_found(),
        io::ErrorKind::NotADirectory => {
            Fault::new("E_FILE_TYPE", "saved path parent must be a directory")
        }
        _ => host(error),
    }
}

impl Namespace {
    fn new(mounts: Vec<topology::Mount>, disks: BTreeMap<usize, Disk>) -> Result<Self> {
        let root = mounts
            .iter()
            .rev()
            .find(|mount| mount.target == b"/")
            .ok_or_else(|| unavailable("captured root mount is missing"))?;
        let root_major = root.device.0;
        let mounts = mounts
            .into_iter()
            .map(|detail| {
                let slot = topology::disk_slot(root_major, &detail)
                    .filter(|slot| disks.contains_key(slot));
                let reason = slot.is_none().then(|| filesystem_reason(&detail));
                (
                    detail.target.clone(),
                    Mount {
                        slot,
                        detail,
                        reason,
                    },
                )
            })
            .collect();
        Ok(Self {
            work: tempfile::Builder::new()
                .prefix("smolvm-saved-files-")
                .tempdir()
                .map_err(host)?,
            mounts,
            disks,
            mounted: BTreeMap::new(),
        })
    }

    fn scope(&self) -> (Vec<String>, Vec<Value>) {
        let mut scope = Vec::new();
        let mut result = Vec::new();
        for (target, mount) in &self.mounts {
            let (path, path_bytes) = wire_path(target);
            let mut entry =
                json!({"path":path,"path_bytes":path_bytes,"filesystem":mount.detail.filesystem});
            if let Some(slot) = mount.slot {
                let disk = &self.disks[&slot];
                entry["volume_id"] = json!(disk.volume);
                entry["generation_id"] = json!(disk.generation);
                scope.push(path);
            }
            if let Some(reason) = mount.reason {
                entry["reason"] = json!(reason);
            }
            result.push(entry);
        }
        (scope, result)
    }

    fn owner(&self, path: &[u8]) -> Vec<u8> {
        let mut at = path;
        loop {
            if self.mounts.contains_key(at) {
                return at.to_vec();
            }
            at = parent(at);
        }
    }

    fn physical(&mut self, path: &[u8], owner: &[u8]) -> Result<PathBuf> {
        let mount = &self.mounts[owner];
        let slot = mount.slot.ok_or_else(|| {
            unavailable(format!(
                "{} is unavailable offline ({})",
                String::from_utf8_lossy(owner),
                mount.reason.unwrap_or("unsupported_filesystem_or_device")
            ))
        })?;
        if !self.mounted.contains_key(&slot) {
            let location = self.work.path().join(format!("mounted-{slot}"));
            let image = self.work.path().join(format!("image-{slot}"));
            let disk = &self.disks[&slot];
            mount_disk(disk, &image, &location)?;
            self.mounted.insert(slot, location);
        }
        let mut disk_path = self.mounted[&slot].clone();
        // Mountinfo stores the root within a filesystem for bind mounts.
        // A guest-reported root may never resolve through a host symlink.
        for part in as_path(&mount.detail.root[1..]).components() {
            disk_path.push(part);
            if fs::symlink_metadata(&disk_path)
                .map_err(path_error)?
                .is_symlink()
            {
                return Err(unavailable("saved mount root is a symlink"));
            }
        }
        let remain = path.strip_prefix(owner).unwrap();
        if !remain.is_empty() {
            disk_path.push(as_path(remain.strip_prefix(b"/").unwrap_or(remain)));
        }
        Ok(disk_path)
    }

    fn resolve(&mut self, path: &[u8], follow: bool) -> Result<(Vec<u8>, PathBuf, Metadata)> {
        let mut todo: VecDeque<Vec<u8>> = path[1..]
            .split(|&b| b == b'/')
            .map(<[u8]>::to_vec)
            .collect();
        let mut current = b"/".to_vec();
        let mut links = 0;
        while let Some(component) = todo.pop_front() {
            match component.as_slice() {
                b"" | b"." => continue,
                b".." => {
                    current = parent(&current).to_vec();
                    continue;
                }
                _ => (),
            }
            let next = append(&current, &component);
            if next.len() > 4096 {
                return Err(Fault::invalid("resolved saved path is too long"));
            }
            let owner = self.owner(&next);
            // A captured persistent mount can sit below a RAM-only or external
            // filesystem. Its mount target was proven by the saved topology
            // even though the offline reader cannot walk that parent.
            if self.mounts[&owner].slot.is_none() {
                let remaining = todo
                    .iter()
                    .fold(next.clone(), |path, part| append(&path, part));
                let mounted = self.owner(&remaining);
                if topology::valid_path(&remaining)
                    && mounted != owner
                    && self.mounts[&mounted].slot.is_some()
                {
                    current = next;
                    continue;
                }
            }
            let location = self.physical(&next, &owner)?;
            let stat = fs::symlink_metadata(&location).map_err(path_error)?;
            if stat.is_symlink() && (follow || !todo.is_empty()) {
                links += 1;
                if links > 40 {
                    return Err(Fault::invalid("too many saved file symlinks"));
                }
                let target = fs::read_link(location)
                    .map_err(path_error)?
                    .into_os_string()
                    .into_vec();
                if target.starts_with(b"/") {
                    current = b"/".to_vec();
                }
                for part in target.split(|&b| b == b'/').rev() {
                    todo.push_front(part.to_vec());
                }
            } else {
                if !todo.is_empty() && !stat.is_dir() {
                    return Err(Fault::new(
                        "E_FILE_TYPE",
                        "saved path parent must be a directory",
                    ));
                }
                current = next;
            }
        }
        let location = self.physical(&current, &self.owner(&current))?;
        let stat = fs::symlink_metadata(&location).map_err(path_error)?;
        Ok((current, location, stat))
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        for mount in self.mounted.values() {
            if let Ok(path) = CString::new(mount.as_os_str().as_bytes()) {
                unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
            }
        }
    }
}

fn namespace() -> Result<()> {
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0
        || unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } != 0
    {
        return Err(unavailable(format!(
            "private mount namespace: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn command(program: &str, args: &[&OsStr]) -> io::Result<Output> {
    Command::new("/usr/bin/timeout")
        .arg("45")
        .arg(program)
        .args(args)
        .env_clear()
        .output()
}
fn mount_disk(disk: &Disk, image: &Path, target: &Path) -> Result<()> {
    let output = File::options()
        .write(true)
        .create_new(true)
        .open(image)
        .map_err(host)?;
    flatten(disk, &output)?;
    drop(output);
    let replay = command(
        "/usr/sbin/e2fsck",
        &[
            OsStr::new("-p"),
            OsStr::new("-E"),
            OsStr::new("journal_only"),
            image.as_os_str(),
        ],
    )
    .map_err(host)?;
    if !matches!(replay.status.code(), Some(0 | 1)) {
        return Err(unavailable(
            "captured ext4 journal could not be replayed in its temporary disk",
        ));
    }
    fs::create_dir(target).map_err(host)?;
    let result = command(
        "/usr/sbin/losetup",
        &[
            OsStr::new("--find"),
            OsStr::new("--show"),
            OsStr::new("--read-only"),
            image.as_os_str(),
        ],
    )
    .map_err(host)?;
    let name = result.stdout.strip_suffix(b"\n").unwrap_or(&result.stdout);
    if !result.status.success()
        || !name
            .strip_prefix(b"/dev/loop")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit))
    {
        return Err(unavailable(
            "a read-only loop device could not be allocated",
        ));
    }
    let device = OsStr::from_bytes(name);
    let mounted = command(
        "/usr/bin/mount",
        &[
            OsStr::new("-n"),
            OsStr::new("-t"),
            OsStr::new("ext4"),
            OsStr::new("-o"),
            OsStr::new("ro,noload,nosuid,nodev,noexec"),
            device,
            target.as_os_str(),
        ],
    );
    let detached = command("/usr/sbin/losetup", &[OsStr::new("--detach"), device]);
    if !matches!(mounted, Ok(ref result) if result.status.success()) {
        return Err(unavailable(
            "captured ext4 filesystem could not be mounted read-only",
        ));
    }
    if !matches!(detached, Ok(ref result) if result.status.success()) {
        let target =
            CString::new(target.as_os_str().as_bytes()).map_err(|error| unavailable(error))?;
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
        return Err(unavailable(
            "saved reader could not mark the temporary loop for cleanup",
        ));
    }
    Ok(())
}

fn flatten(disk: &Disk, output: &File) -> Result<()> {
    if let [(layer, data)] = &disk.layers[..] {
        if layer.format == "raw"
            && data.metadata().map_err(host)?.len() == disk.capacity
            && unsafe {
                libc::ioctl(
                    output.as_raw_fd(),
                    0x4004_9409 as libc::c_ulong,
                    data.as_raw_fd(),
                )
            } == 0
        {
            return Ok(());
        }
    }
    type Storage = Box<dyn DynStorage>;
    let mut prior: Option<(&str, &str, Arc<FormatAccess<Storage>>)> = None;
    for (layer, file) in disk.layers.iter().rev() {
        let storage: Storage =
            Box::new(ImageFile::try_from(file.try_clone().map_err(host)?).map_err(host)?);
        let format = layer.format.as_str();
        let read = match format {
            "raw" if prior.is_none() => {
                FormatAccess::new(Raw::open_image_sync(storage, false).map_err(host)?)
            }
            "qcow2" => {
                let mut image = Qcow2::open_image_sync(storage, false).map_err(host)?;
                let (id, format, backing) = prior
                    .take()
                    .ok_or_else(|| unavailable("captured qcow2 layer has no backing"))?;
                if image.requires_external_data_file()
                    || image.implicit_external_data_file().is_some()
                    || image.implicit_backing_file().map(String::as_str) != Some(id)
                    || image.implicit_backing_format().map(String::as_str) != Some(format)
                {
                    return Err(unavailable(
                        "captured qcow2 layer has an unverified backing",
                    ));
                }
                image.set_backing(Some(backing));
                FormatAccess::new(image)
            }
            _ => return Err(unavailable("captured disk format is unsupported")),
        };
        prior = Some((&layer.spec.resource_id, format, Arc::new(read)));
    }
    let (_, _, read) = prior.ok_or_else(|| unavailable("captured disk has no immutable layers"))?;
    if read.size() != disk.capacity {
        return Err(unavailable(
            "captured disk capacity differs from its backing",
        ));
    }
    output.set_len(disk.capacity).map_err(host)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(host)?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut offset = 0;
    while offset < disk.capacity {
        let size = (disk.capacity - offset).min(buffer.len() as u64) as usize;
        let bytes = &mut buffer[..size];
        runtime
            .block_on(read.read(&mut *bytes, offset))
            .map_err(host)?;
        if bytes.iter().any(|&byte| byte != 0) {
            output.write_all_at(bytes, offset).map_err(host)?;
        }
        offset += size as u64;
    }
    Ok(())
}

fn entry(path: &[u8], name: &[u8], stat: &Metadata) -> Value {
    let (path, path_bytes) = wire_path(path);
    let kind = stat.file_type();
    let kind = if kind.is_file() {
        "file"
    } else if kind.is_dir() {
        "directory"
    } else if kind.is_symlink() {
        "symlink"
    } else if kind.is_socket() {
        "socket"
    } else if kind.is_fifo() {
        "fifo"
    } else if kind.is_char_device() {
        "character_device"
    } else if kind.is_block_device() {
        "block_device"
    } else {
        "other"
    };
    json!({"path":path,"path_bytes":path_bytes,"type":kind,"name":String::from_utf8_lossy(name),
        "size":stat.len(),"mode":stat.mode() & 0o7777,"modified_unix":stat.mtime()})
}

fn names(directory: &Path) -> Result<Vec<OsString>> {
    let mut names = fs::read_dir(directory)
        .map_err(path_error)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()
        .map_err(path_error)?;
    names.sort_unstable();
    Ok(names)
}

fn list(
    namespace: &Namespace,
    requested: &[u8],
    resolved: &[u8],
    directory: &Path,
    cursor: &[u8],
    limit: usize,
    result: &mut Value,
) -> Result<()> {
    if !cursor.is_empty() && (cursor == requested || parent(cursor) != requested) {
        return Err(Fault::invalid(
            "saved file cursor belongs to another directory",
        ));
    }
    let mut next = std::collections::BTreeSet::new();
    for (index, item) in fs::read_dir(directory).map_err(path_error)?.enumerate() {
        if index == 262_144 {
            return Err(Fault::new(
                "E_FILE_TOO_LARGE",
                "saved directory exceeds its entry scan limit",
            ));
        }
        let name = item.map_err(path_error)?.file_name();
        if append(requested, name.as_bytes()).as_slice() > cursor {
            next.insert(name);
            if next.len() > limit + 1 {
                next.pop_last();
            }
        }
    }
    let more = next.len() > limit;
    if more {
        next.pop_last();
    }
    let mut items = Vec::with_capacity(next.len());
    let mut last = Vec::new();
    for name in next {
        let child = append(requested, name.as_bytes());
        if !topology::valid_path(&child) {
            return Err(Fault::new(
                "E_FILE_TOO_LARGE",
                "saved directory path exceeds its byte limit",
            ));
        }
        let logical = append(resolved, name.as_bytes());
        let stat = fs::symlink_metadata(directory.join(&name)).map_err(path_error)?;
        let mut item = entry(&child, name.as_bytes(), &stat);
        if namespace
            .mounts
            .get(&logical)
            .is_some_and(|mount| mount.reason.is_some())
        {
            item["type"] = json!("other");
            item["size"] = json!(0);
        }
        items.push(item);
        last = child;
    }
    if more {
        result["next_cursor"] = json!(STANDARD.encode(last));
    }
    result["items"] = json!(items);
    Ok(())
}

struct Limited<W> {
    output: W,
    remaining: u64,
}
impl<W: Write> Write for Limited<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "saved archive exceeds its byte limit",
            ));
        }
        let wrote = self.output.write(buf)?;
        self.remaining -= wrote as u64;
        Ok(wrote)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

fn archive_file(
    namespace: &Namespace,
    owner: &[u8],
    logical: &[u8],
    source: &Path,
    relative: &Path,
    tar: &mut tar::Builder<Limited<&mut File>>,
    count: &mut usize,
) -> Result<()> {
    *count += 1;
    if *count > 100_000 || relative.components().count() > 256 {
        return Err(Fault::new(
            "E_FILE_TOO_LARGE",
            "saved archive exceeds its member limits",
        ));
    }
    let stat = fs::symlink_metadata(source).map_err(path_error)?;
    if !(stat.is_file() || stat.is_dir() || stat.is_symlink()) {
        return Err(Fault::new(
            "E_FILE_TYPE",
            "saved archive contains a special file",
        ));
    }
    tar.append_path_with_name(source, relative)
        .map_err(archive_error)?;
    if stat.is_dir() {
        for name in names(source)? {
            let child = append(logical, name.as_bytes());
            if namespace.owner(&child) == owner {
                archive_file(
                    namespace,
                    owner,
                    &child,
                    &source.join(&name),
                    &relative.join(&name),
                    tar,
                    count,
                )?;
            }
        }
    }
    Ok(())
}
fn archive_error(error: io::Error) -> Fault {
    if error.kind() == io::ErrorKind::FileTooLarge {
        Fault::new("E_FILE_TOO_LARGE", error.to_string())
    } else {
        host(error)
    }
}

pub(super) fn serve(
    input: Input,
    path: Vec<u8>,
    cursor: Vec<u8>,
    mounts: Vec<topology::Mount>,
    disks: BTreeMap<usize, Disk>,
) -> Result<File> {
    let mut ns = Namespace::new(mounts, disks)?;
    let (scope, mounts) = ns.scope();
    let mut result = json!({"scope":scope,"mounts":mounts,"capture_id":input.capture_id,"bytes":0});
    let mut body = tempfile::tempfile().map_err(host)?;
    if input.operation != Operation::Scope {
        namespace()?;
        let follow = input.follow
            || matches!(
                input.operation,
                Operation::List | Operation::Realpath | Operation::Read
            );
        let (logical, location, stat) = ns.resolve(&path, follow)?;
        let name = as_path(&path)
            .file_name()
            .map(OsStr::as_bytes)
            .unwrap_or(b"/");
        let display_path = if input.operation == Operation::Realpath {
            &logical
        } else {
            &path
        };
        let (display, bytes) = wire_path(display_path);
        result["path"] = json!(display);
        result["path_bytes"] = json!(bytes);
        match input.operation {
            Operation::Scope | Operation::Realpath => (),
            Operation::Stat | Operation::Exists => result["entry"] = entry(&path, name, &stat),
            Operation::List => {
                if !stat.is_dir() {
                    return Err(Fault::new(
                        "E_FILE_TYPE",
                        "saved listing requires a directory",
                    ));
                }
                list(
                    &ns,
                    &path,
                    &logical,
                    &location,
                    &cursor,
                    input.limit,
                    &mut result,
                )?;
            }
            Operation::Read => {
                if !stat.is_file() {
                    return Err(Fault::new(
                        "E_FILE_TYPE",
                        "saved read requires a regular file",
                    ));
                }
                let count = stat
                    .len()
                    .checked_sub(input.offset)
                    .and_then(|rest| {
                        input
                            .length
                            .filter(|&len| len <= rest)
                            .or_else(|| input.length.is_none().then_some(rest))
                    })
                    .ok_or_else(|| {
                        Fault::new("E_FILE_RANGE", "saved range lies outside the file")
                    })?;
                if count > MAX_TRANSFER {
                    return Err(Fault::new(
                        "E_FILE_TOO_LARGE",
                        "saved read exceeds its byte limit",
                    ));
                }
                let mut file = File::open(location).map_err(path_error)?;
                file.seek(SeekFrom::Start(input.offset)).map_err(host)?;
                if io::copy(&mut file.take(count), &mut body).map_err(host)? != count {
                    return Err(unavailable("saved data ended before its range"));
                }
            }
            Operation::Archive => {
                if !stat.is_dir() || name == b"/" {
                    return Err(Fault::new(
                        "E_FILE_TYPE",
                        "saved archive requires a named directory",
                    ));
                }
                let mut builder = tar::Builder::new(Limited {
                    output: &mut body,
                    remaining: MAX_TRANSFER,
                });
                builder.follow_symlinks(false);
                archive_file(
                    &ns,
                    &ns.owner(&logical),
                    &logical,
                    &location,
                    as_path(name),
                    &mut builder,
                    &mut 0,
                )?;
                builder.finish().map_err(archive_error)?;
            }
        }
    }

    if matches!(input.operation, Operation::Read | Operation::Archive) {
        body.rewind().map_err(host)?;
        let mut hash = Sha256::new();
        let bytes = io::copy(&mut body, &mut hash).map_err(host)?;
        result["bytes"] = json!(bytes);
        result["sha256"] = json!(format!("{:x}", hash.finalize()));
    }
    let data = serde_json::to_vec(&result).map_err(unavailable)?;
    if data.len() > 4 << 20 {
        return Err(Fault::new(
            "E_FILE_TOO_LARGE",
            "saved file metadata exceeds its limit",
        ));
    }
    let mut frame = tempfile::tempfile().map_err(host)?;
    frame
        .write_all(&(data.len() as u32).to_be_bytes())
        .map_err(host)?;
    frame.write_all(&data).map_err(host)?;
    body.rewind().map_err(host)?;
    io::copy(&mut body, &mut frame).map_err(host)?;
    File::open(format!("/proc/self/fd/{}", frame.as_raw_fd())).map_err(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocks::{BlockObject, BlockSpec};

    #[test]
    #[ignore = "requires root, mount namespace support, free loop devices and e2fsprogs"]
    fn saved_ext4_mounts_read_original_root_and_attached_data() {
        let fixture = tempfile::tempdir().unwrap();
        let mut inputs = Vec::new();
        let capacity = 16 << 20;
        for (tag, filename, contents) in [
            ("root", "root.txt", "root payload"),
            ("data", "extra.txt", "attached payload"),
        ] {
            let source = fixture.path().join(format!("{tag}-tree"));
            let image = fixture.path().join(format!("{tag}.raw"));
            fs::create_dir(&source).unwrap();
            fs::create_dir(source.join("mnt")).unwrap();
            fs::write(source.join(filename), contents).unwrap();
            File::create(&image).unwrap().set_len(capacity).unwrap();
            assert!(command(
                "/usr/sbin/mkfs.ext4",
                &[
                    OsStr::new("-q"),
                    OsStr::new("-F"),
                    OsStr::new("-d"),
                    source.as_os_str(),
                    image.as_os_str()
                ],
            )
            .unwrap()
            .status
            .success());
            let digest = Sha256::digest(fs::read(&image).unwrap());
            inputs.push((tag, image, digest));
        }
        let topology = b"1 0 252:0 / / rw - ext4 /dev/vda rw\n2 1 252:16 / /mnt rw - ext4 /dev/vdb rw\n3 1 0:4 / /proc rw - proc proc rw\n";
        for (path, expected) in [
            (b"/root.txt".as_slice(), b"root payload".as_slice()),
            (b"/mnt/extra.txt".as_slice(), b"attached payload".as_slice()),
        ] {
            let disks = inputs
                .iter()
                .enumerate()
                .map(|(slot, (id, path, _))| {
                    let object = BlockObject {
                        spec: BlockSpec {
                            resource_id: id.to_string(),
                            capacity_bytes: capacity,
                            volume_id: None,
                            backing_id: None,
                            content_sha256: None,
                            sealed: true,
                        },
                        format: "raw".into(),
                        backing_identity: String::new(),
                        verified_identity: None,
                    };
                    (
                        slot,
                        Disk {
                            layers: vec![(object, File::open(path).unwrap())],
                            volume: id.to_string(),
                            generation: id.to_string(),
                            capacity,
                        },
                    )
                })
                .collect();
            let input = Input {
                job_id: "job".into(),
                capture_id: "fixed".into(),
                manifest_digest: "digest".into(),
                source_operation_id: "operation".into(),
                instance_id: "instance".into(),
                operation: Operation::Read,
                path: String::new(),
                cursor: String::new(),
                limit: 0,
                offset: 0,
                length: None,
                follow: false,
            };
            let path = path.to_vec();
            let mut frame = std::thread::spawn(move || {
                serve(
                    input,
                    path,
                    Vec::new(),
                    topology::parse(topology).unwrap(),
                    disks,
                )
            })
            .join()
            .unwrap()
            .unwrap();
            let mut header = [0; 4];
            frame.read_exact(&mut header).unwrap();
            let mut raw = vec![0; u32::from_be_bytes(header) as usize];
            frame.read_exact(&mut raw).unwrap();
            let metadata: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(metadata["scope"], json!(["/", "/mnt"]));
            assert_eq!(metadata["capture_id"], "fixed");
            assert_eq!(metadata["bytes"], expected.len());
            let mut body = Vec::new();
            frame.read_to_end(&mut body).unwrap();
            assert_eq!(body, expected);
        }
        for (_, image, expected) in inputs {
            assert_eq!(Sha256::digest(fs::read(image).unwrap()), expected);
        }
    }
}
