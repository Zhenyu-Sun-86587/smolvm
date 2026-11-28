use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self as sys, AtFlags, RenameFlags, StatxFlags};
use smolvm_protocol::system_files_v2::{Overwrite, Request, MAX_ARCHIVE_ENTRIES, MAX_BYTES};
use smolvm_protocol::AgentResponse;

use super::{
    bytes, check_connected, invalid, limit, name_valid, path_from_bytes, reply, wrong_type, Fault,
    Result, PATH_MAX,
};

const MAX_DEPTH: usize = 64;
const MAX_EXTENDED_HEADER: u64 = 16 << 10;

pub(super) struct Stage {
    parent: File,
    root: File,
    name: PathBuf,
}

impl Stage {
    pub(super) fn path(&self) -> PathBuf {
        fd_path(&self.root)
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let path = fd_path(&self.parent).join(&self.name);
        if let Ok(root_mount) = mount(&self.root) {
            // A private staging tree may contain a displaced original. Never
            // follow a link or cross into another mount during cleanup.
            let _ = clear_tree(&self.root, root_mount, 0);
            let _ = fs::remove_dir(path);
        }
    }
}

pub(super) fn stage_in(parent: &Path) -> Result<Stage> {
    let parent = open_path(parent, true)?;
    let path = tempfile::Builder::new()
        .prefix(".smolvm-files-v2.")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(fd_path(&parent))?;
    let root = open_path(path.path(), false)?;
    let name = PathBuf::from(path.path().file_name().expect("stage has a basename"));
    let _ = path.keep();
    Ok(Stage { parent, root, name })
}

pub(super) fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .ok_or_else(|| invalid("path requires a parent"))
}

pub(super) fn metadata(path: &Path) -> Result<Option<Metadata>> {
    match path.symlink_metadata() {
        Ok(metadata) => Ok(Some(metadata)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn open_path(path: &Path, follow: bool) -> Result<File> {
    let flags = libc::O_PATH | if follow { 0 } else { libc::O_NOFOLLOW };
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)?)
}

pub(super) fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn mount(file: &File) -> Result<(u64, u64)> {
    let id = sys::statx(file, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
        .ok()
        .filter(|info| StatxFlags::from_bits_retain(info.stx_mask).contains(StatxFlags::MNT_ID))
        .map_or(0, |info| info.stx_mnt_id);
    Ok((file.metadata()?.dev(), id))
}

pub(super) fn check_mountpoint(path: &Path) -> Result<()> {
    let object = open_path(path, false)?;
    let parent = open_path(parent(path)?, true)?;
    if mount(&object)? != mount(&parent)? {
        return Err(Fault::new(
            "FILE_MOUNTPOINT",
            "operation targets a mountpoint",
        ));
    }
    Ok(())
}

fn child_mount(child: &File, expected: (u64, u64)) -> Result<()> {
    if mount(child)? != expected {
        return Err(Fault::new(
            "FILE_CROSS_DEVICE",
            "directory entry crosses a mount boundary",
        ));
    }
    Ok(())
}

fn clear_tree(root: &File, root_mount: (u64, u64), depth: usize) -> Result<()> {
    if depth > MAX_DEPTH + 2 {
        return Err(limit("staged cleanup exceeds the depth limit"));
    }
    for item in fs::read_dir(fd_path(root))? {
        let path = item?.path();
        let child = open_path(&path, false)?;
        child_mount(&child, root_mount)?;
        if child.metadata()?.is_dir() {
            clear_tree(&child, root_mount, depth + 1)?;
            fs::remove_dir(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct Walk {
    count: usize,
    bytes: u64,
    seen: HashMap<(u64, u64), PathBuf>,
}

impl Walk {
    fn member(&mut self, name: &Path, depth: usize) -> Result<()> {
        self.count += 1;
        if self.count > MAX_ARCHIVE_ENTRIES
            || depth > MAX_DEPTH
            || name.as_os_str().len() > PATH_MAX
        {
            return Err(limit("directory exceeds the entry, path, or depth limit"));
        }
        Ok(())
    }

    fn data(&mut self, size: u64) -> Result<()> {
        if size > MAX_BYTES - self.bytes {
            return Err(Fault::new(
                "FILE_TOO_LARGE",
                "directory data exceeds the 4 GiB transfer limit",
            ));
        }
        self.bytes += size;
        Ok(())
    }

    fn inode(&mut self, meta: &Metadata, path: &Path) -> Option<PathBuf> {
        if meta.nlink() > 1 {
            match self.seen.entry((meta.dev(), meta.ino())) {
                std::collections::hash_map::Entry::Occupied(first) => Some(first.get().clone()),
                std::collections::hash_map::Entry::Vacant(first) => {
                    first.insert(path.to_path_buf());
                    None
                }
            }
        } else {
            None
        }
    }
}

fn verify_tree(
    root: &File,
    root_mount: (u64, u64),
    depth: usize,
    walk: &mut Walk,
    client: RawFd,
) -> Result<()> {
    check_connected(client)?;
    walk.member(Path::new(""), depth)?;
    child_mount(root, root_mount)?;
    if root.metadata()?.is_dir() {
        for item in fs::read_dir(fd_path(root))? {
            verify_tree(
                &open_path(&item?.path(), false)?,
                root_mount,
                depth + 1,
                walk,
                client,
            )?;
        }
    }
    Ok(())
}

fn rename(source: &Path, destination: &Path, flags: RenameFlags) -> Result<()> {
    sys::renameat_with(sys::CWD, source, sys::CWD, destination, flags).map_err(io::Error::from)?;
    Ok(())
}

pub(super) fn publish(
    source: &Path,
    destination: &Path,
    overwrite: Overwrite,
    client: RawFd,
) -> Result<()> {
    let dst_parent = open_path(parent(destination)?, true)?;
    let destination = fd_path(&dst_parent).join(
        destination
            .file_name()
            .ok_or_else(|| invalid("cannot replace root"))?,
    );
    let source_metadata = source.symlink_metadata()?;
    if let Some(existing) = metadata(&destination)? {
        if overwrite == Overwrite::Reject {
            return Err(Fault::new("FILE_EXISTS", "destination already exists"));
        }
        check_mountpoint(&destination)?;
        if existing.is_dir() != source_metadata.is_dir() {
            return Err(Fault::new(
                "FILE_TYPE_CONFLICT",
                "source and destination directory types differ",
            ));
        }
        if existing.is_dir() {
            let old = open_path(&destination, false)?;
            verify_tree(&old, mount(&dst_parent)?, 0, &mut Walk::default(), client)?;
            check_connected(client)?;
            return rename(source, &destination, RenameFlags::EXCHANGE);
        }
        check_connected(client)?;
        return Ok(fs::rename(source, destination)?);
    }
    check_connected(client)?;
    rename(source, &destination, RenameFlags::NOREPLACE)
}

fn mkdir_recursive(path: &Path, client: RawFd) -> Result<()> {
    let mut first = path;
    let anchor = loop {
        let parent = parent(first)?;
        match open_path(parent, true) {
            Ok(dir) => break dir,
            Err(err) if err.0 == "NOT_FOUND" => first = parent,
            Err(err) => return Err(err),
        }
    };
    let first_name = first.file_name().expect("mkdir path with parent");
    let destination = fd_path(&anchor).join(first_name);
    if first == path {
        check_connected(client)?;
        if let Err(err) = fs::create_dir(&destination) {
            if err.kind() != io::ErrorKind::AlreadyExists
                || !destination.symlink_metadata()?.is_dir()
            {
                return Err(err.into());
            }
        }
        return Ok(());
    }
    let stage = stage_in(&fd_path(&anchor))?;
    let staged = stage.path().join(first_name);
    let remaining = path
        .strip_prefix(first)
        .expect("first missing path is an ancestor");
    fs::create_dir_all(staged.join(remaining))?;
    check_connected(client)?;
    rename(&staged, &destination, RenameFlags::NOREPLACE)
}

pub(super) fn mutate(operation: Request, client: RawFd) -> Result<AgentResponse> {
    let mut copied_bytes = None;
    let target = match &operation {
        Request::Mkdir { path, recursive } => {
            let path = path_from_bytes(path, false)?;
            if *recursive {
                mkdir_recursive(path, client)?;
            } else {
                check_connected(client)?;
                fs::create_dir(path)?;
            }
            path
        }
        Request::Remove { path, recursive } => {
            let path = path_from_bytes(path, false)?;
            let object = open_path(path, false)?;
            check_mountpoint(path)?;
            if object.metadata()?.is_dir() {
                if *recursive {
                    let stage = stage_in(parent(path)?)?;
                    verify_tree(&object, mount(&object)?, 0, &mut Walk::default(), client)?;
                    check_connected(client)?;
                    rename(path, &stage.path().join("removed"), RenameFlags::NOREPLACE)?;
                } else {
                    check_connected(client)?;
                    fs::remove_dir(path)?;
                }
            } else {
                check_connected(client)?;
                fs::remove_file(path)?;
            }
            path
        }
        Request::Rename {
            path,
            destination,
            overwrite,
        } => {
            let path = path_from_bytes(path, false)?;
            let destination = path_from_bytes(destination, false)?;
            check_mountpoint(path)?;
            if let Some(existing) = metadata(destination)? {
                let source = path.symlink_metadata()?;
                if *overwrite == Overwrite::Reject {
                    return Err(Fault::new("FILE_EXISTS", "destination already exists"));
                }
                check_mountpoint(destination)?;
                if existing.is_dir() != source.is_dir() {
                    return Err(Fault::new(
                        "FILE_TYPE_CONFLICT",
                        "source and destination directory types differ",
                    ));
                }
                if existing.dev() == source.dev() && existing.ino() == source.ino() {
                    return Err(Fault::new(
                        "FILE_EXISTS",
                        "source and destination refer to the same inode",
                    ));
                }
                if existing.is_dir() {
                    let stage = stage_in(parent(destination)?)?;
                    let old = open_path(destination, false)?;
                    verify_tree(&old, mount(&old)?, 0, &mut Walk::default(), client)?;
                    check_connected(client)?;
                    rename(path, destination, RenameFlags::EXCHANGE)?;
                    // Source now holds the overwritten tree. A failure to
                    // detach it is a partial effect, explicitly reconciled.
                    if rename(
                        path,
                        &stage.path().join("displaced"),
                        RenameFlags::NOREPLACE,
                    )
                    .is_err()
                    {
                        return Err(Fault::new("FILE_OUTCOME_UNKNOWN", "directory moved but the overwritten destination may remain at the source"));
                    }
                } else {
                    check_connected(client)?;
                    fs::rename(path, destination)?;
                }
            } else {
                check_connected(client)?;
                rename(path, destination, RenameFlags::NOREPLACE)?;
            }
            destination
        }
        Request::Copy {
            path,
            destination,
            recursive,
            overwrite,
        } => {
            let path = path_from_bytes(path, false)?;
            let destination = path_from_bytes(destination, false)?;
            let source = open_path(path, false)?;
            let source_meta = source.metadata()?;
            let target_parent = parent(destination)?.canonicalize()?;
            if source_meta.is_dir() {
                if !recursive {
                    return Err(Fault::new(
                        "FILE_IS_DIRECTORY",
                        "directory copy requires recursive=true",
                    ));
                }
                if target_parent.starts_with(fd_path(&source).canonicalize()?) {
                    return Err(invalid("cannot copy a directory into itself"));
                }
            }
            if let Some(existing) = metadata(destination)? {
                if *overwrite == Overwrite::Reject
                    || (existing.ino() == source_meta.ino() && existing.dev() == source_meta.dev())
                {
                    return Err(Fault::new("FILE_EXISTS", "destination already exists"));
                }
            }
            let stage = stage_in(&target_parent)?;
            let target = stage.path().join("copied");
            let options = CopyOptions {
                scope: mount(&source)?,
                client,
            };
            let mut walk = Walk::default();
            copy_member(&source, path, &target, 0, &mut walk, &options)?;
            copied_bytes = Some(walk.bytes);
            publish(&target, destination, *overwrite, client)?;
            destination
        }
        _ => return Err(invalid("unknown filesystem mutation")),
    };
    Ok(reply(serde_json::json!({
        "path": target.to_string_lossy(),
        "path_bytes": bytes(target),
        "bytes": copied_bytes.unwrap_or(0),
    })))
}

struct CopyOptions {
    scope: (u64, u64),
    client: RawFd,
}

fn copy_member(
    source: &File,
    source_path: &Path,
    target: &Path,
    depth: usize,
    walk: &mut Walk,
    options: &CopyOptions,
) -> Result<()> {
    check_connected(options.client)?;
    walk.member(source_path, depth)?;
    child_mount(source, options.scope)?;
    let metadata = source.metadata()?;
    if metadata.is_symlink() {
        symlink(read_link(source)?, target)?;
    } else if metadata.is_dir() {
        fs::create_dir(target)?;
        for item in fs::read_dir(fd_path(source))? {
            let item = item?;
            let child = open_path(&item.path(), false)?;
            copy_member(
                &child,
                &source_path.join(item.file_name()),
                &target.join(item.file_name()),
                depth + 1,
                walk,
                options,
            )?;
        }
        fs::set_permissions(target, fs::Permissions::from_mode(metadata.mode() & 0o777))?;
    } else if metadata.is_file() {
        if let Some(first) = walk.inode(&metadata, target) {
            fs::hard_link(first, target)?;
        } else {
            walk.data(metadata.size())?;
            let source = File::open(fd_path(source))?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(target)?;
            copy_bytes(
                source.take(metadata.size()),
                &mut file,
                metadata.size(),
                options.client,
            )?;
            file.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o777))?;
            file.sync_all()?;
        }
    } else {
        return Err(wrong_type(&metadata));
    }
    Ok(())
}

fn read_link(file: &File) -> Result<PathBuf> {
    let mut data = [0; PATH_MAX + 1];
    // SAFETY: Linux permits an empty pathname when the fd refers to a link.
    // The buffer has the size passed to readlinkat.
    let size = unsafe {
        libc::readlinkat(
            file.as_raw_fd(),
            c"".as_ptr(),
            data.as_mut_ptr().cast(),
            data.len(),
        )
    };
    if size < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if size as usize > PATH_MAX {
        return Err(limit("symlink target exceeds the path limit"));
    }
    Ok(PathBuf::from(OsStr::from_bytes(&data[..size as usize])))
}

fn copy_bytes(
    mut input: impl Read,
    output: &mut impl Write,
    size: u64,
    client: RawFd,
) -> Result<()> {
    let mut bytes = 0;
    let mut chunk = [0; 64 << 10];
    loop {
        check_connected(client)?;
        let count = input.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        output.write_all(&chunk[..count])?;
        bytes += count as u64;
    }
    if bytes != size {
        return Err(Fault::new(
            "FILE_CHANGED",
            "member size changed during the transfer",
        ));
    }
    Ok(())
}

pub(super) fn export(path: &Path, output: &mut impl Write, client: RawFd) -> Result<()> {
    let root = open_path(path, false)?;
    if !root.metadata()?.is_dir() {
        return Err(Fault::new(
            "FILE_NOT_DIRECTORY",
            "archive root must be a directory",
        ));
    }
    let mut builder = tar::Builder::new(output);
    let name = Path::new(
        path.file_name()
            .ok_or_else(|| invalid("cannot archive the filesystem root"))?,
    );
    let options = CopyOptions {
        scope: mount(&root)?,
        client,
    };
    pack_member(&root, name, 0, &mut Walk::default(), &options, &mut builder)?;
    builder.finish()?;
    Ok(())
}

fn pack_member(
    source: &File,
    name: &Path,
    depth: usize,
    walk: &mut Walk,
    options: &CopyOptions,
    output: &mut tar::Builder<impl Write>,
) -> Result<()> {
    check_connected(options.client)?;
    walk.member(name, depth)?;
    child_mount(source, options.scope)?;
    let metadata = source.metadata()?;
    let mut header = tar::Header::new_gnu();
    header.set_mode(metadata.mode() & 0o777);
    header.set_mtime(metadata.mtime().max(0) as u64);
    header.set_size(0);
    if metadata.is_dir() {
        header.set_entry_type(tar::EntryType::Directory);
        output.append_data(&mut header, name, io::empty())?;
        for item in fs::read_dir(fd_path(source))? {
            let item = item?;
            pack_member(
                &open_path(&item.path(), false)?,
                &name.join(item.file_name()),
                depth + 1,
                walk,
                options,
                output,
            )?;
        }
    } else if metadata.is_symlink() {
        let target = read_link(source)?;
        check_link_target(&target)?;
        header.set_entry_type(tar::EntryType::Symlink);
        output.append_link(&mut header, name, target)?;
    } else if metadata.is_file() {
        if let Some(first) = walk.inode(&metadata, name) {
            header.set_entry_type(tar::EntryType::Link);
            output.append_link(&mut header, name, first)?;
        } else {
            walk.data(metadata.size())?;
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(metadata.size());
            let input = File::open(fd_path(source))?.take(metadata.size());
            let mut counted = input;
            output.append_data(&mut header, name, &mut counted)?;
            if counted.limit() != 0 {
                return Err(Fault::new(
                    "FILE_CHANGED",
                    "archive member shrank during transfer",
                ));
            }
        }
    } else {
        return Err(wrong_type(&metadata));
    }
    Ok(())
}

fn invalid_archive(message: impl Into<String>) -> Fault {
    Fault::new("FILE_ARCHIVE_INVALID", message)
}

fn archive_path(raw: &[u8], directory: bool) -> Result<&Path> {
    let raw = if directory {
        raw.strip_suffix(b"/").unwrap_or(raw)
    } else {
        raw
    };
    if raw.len() > PATH_MAX || !raw.split(|b| *b == b'/').all(name_valid) {
        return Err(invalid_archive("archive contains an unsafe member path"));
    }
    let path = Path::new(OsStr::from_bytes(raw));
    if path.components().count() > MAX_DEPTH {
        return Err(limit("archive member exceeds the depth limit"));
    }
    Ok(path)
}

fn check_link_target(target: &Path) -> Result<()> {
    let length = target.as_os_str().len();
    if length == 0 || length > PATH_MAX || target.as_os_str().as_bytes().contains(&0) {
        return Err(invalid_archive("archive has an invalid symlink target"));
    }
    // An earlier symlink can change the effective depth of "..". Limit
    // archive links to child-relative targets so chains remain under the root.
    if target
        .components()
        .any(|part| !matches!(part, Component::CurDir | Component::Normal(_)))
    {
        return Err(invalid_archive(
            "archive symlink must have a child-relative target",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct Extended {
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
}

impl Extended {
    fn set(to: &mut Option<Vec<u8>>, raw: Vec<u8>) -> Result<()> {
        if to.is_some() {
            return Err(invalid_archive("duplicate archive path extension"));
        }
        if raw.len() > PATH_MAX {
            return Err(limit("archive extension exceeds the path limit"));
        }
        *to = Some(raw);
        Ok(())
    }

    fn read(&mut self, member: &mut tar::Entry<impl Read>) -> Result<bool> {
        let kind = member.header().entry_type();
        if kind.is_gnu_sparse() || kind.is_pax_global_extensions() {
            return Err(invalid_archive(
                "sparse and global archive headers are unsupported",
            ));
        }
        if !kind.is_gnu_longname() && !kind.is_gnu_longlink() && !kind.is_pax_local_extensions() {
            return Ok(false);
        }
        if member.size() > MAX_EXTENDED_HEADER {
            return Err(limit("archive extension exceeds 16 KiB"));
        }
        if kind.is_pax_local_extensions() {
            for field in member.pax_extensions()?.into_iter().flatten() {
                let field = field?;
                match field.key_bytes() {
                    b"path" => Self::set(&mut self.path, field.value_bytes().to_vec())?,
                    b"linkpath" => Self::set(&mut self.link, field.value_bytes().to_vec())?,
                    b"size" => {
                        return Err(invalid_archive("archive size overrides are unsupported"))
                    }
                    key if key.starts_with(b"GNU.sparse.") => {
                        return Err(invalid_archive("sparse archive headers are unsupported"))
                    }
                    _ => {}
                }
            }
        } else {
            let mut raw = Vec::new();
            member.read_to_end(&mut raw)?;
            if raw.last() == Some(&0) {
                raw.pop();
            }
            let field = if kind.is_gnu_longname() {
                &mut self.path
            } else {
                &mut self.link
            };
            Self::set(field, raw)?;
        }
        Ok(true)
    }
}

pub(super) fn extract(input: File, selected: &Path, client: RawFd) -> Result<PathBuf> {
    let mut archive = tar::Archive::new(input);
    let mut walk = Walk::default();
    let mut appended = HashSet::new();
    let mut directories = Vec::new();
    let mut directory_names = HashSet::new();
    let mut regular = HashSet::new();
    let mut root = None::<PathBuf>;
    let mut extended = Extended::default();
    let mut raw_count = 0;
    for member in archive.entries()?.raw(true) {
        check_connected(client)?;
        raw_count += 1;
        if raw_count > MAX_ARCHIVE_ENTRIES * 3 {
            return Err(limit("archive exceeds the header count limit"));
        }
        let mut member = member.map_err(|err| invalid_archive(err.to_string()))?;
        if extended.read(&mut member)? {
            continue;
        }
        let kind = member.header().entry_type();
        let raw_path = extended
            .path
            .take()
            .map_or_else(|| member.path_bytes().into_owned(), |path| path);
        let name = archive_path(&raw_path, kind.is_dir())?;
        let first = Path::new(
            name.components()
                .next()
                .expect("validated path")
                .as_os_str(),
        );
        let root_name = root.get_or_insert_with(|| first.to_path_buf());
        if root_name != first || (name == first && !kind.is_dir()) {
            return Err(invalid_archive(
                "archive requires exactly one directory root",
            ));
        }
        walk.member(name, name.components().count())?;
        if !appended.insert(name.to_path_buf()) {
            return Err(invalid_archive("archive has duplicate members"));
        }
        // Every parent must have appeared explicitly as a directory. No
        // extraction path can traverse a symlink or auto-create an ancestor.
        let target = selected.join(name);
        if name != first && !directory_names.contains(parent(name)?) {
            return Err(invalid_archive(
                "archive member requires a preceding directory parent",
            ));
        }
        let link = extended
            .link
            .take()
            .or_else(|| member.link_name_bytes().map(|raw| raw.into_owned()));
        let size = member.size();
        if !kind.is_file() && size != 0 {
            return Err(invalid_archive("non-regular archive member has data"));
        }
        let mode = member.header().mode()? & 0o777;
        if kind.is_dir() {
            fs::create_dir(&target)?;
            directory_names.insert(name.to_path_buf());
            directories.push((target, mode));
        } else if kind.is_file() {
            walk.data(size)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(target)?;
            copy_bytes(&mut member, &mut file, size, client)?;
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            file.sync_all()?;
            regular.insert(name.to_path_buf());
        } else if kind.is_symlink() {
            let link = link.ok_or_else(|| invalid_archive("symlink has no target"))?;
            let link = Path::new(OsStr::from_bytes(&link));
            check_link_target(link)?;
            symlink(link, target)?;
        } else if kind.is_hard_link() {
            let link = link.ok_or_else(|| invalid_archive("hard link has no target"))?;
            let link = archive_path(&link, false)?;
            if !regular.contains(link) {
                return Err(invalid_archive(
                    "hard link must refer to a preceding regular file in the same root",
                ));
            }
            fs::hard_link(selected.join(link), target)?;
        } else {
            return Err(invalid_archive(
                "archive member is a socket, FIFO, device, or unsupported type",
            ));
        }
    }
    let mut trailing = archive.into_inner();
    let mut padding = [0; 8192];
    let mut padding_size = 0;
    loop {
        check_connected(client)?;
        let count = trailing.read(&mut padding)?;
        if count == 0 {
            break;
        }
        if padding[..count].iter().any(|byte| *byte != 0) {
            return Err(invalid_archive(
                "archive contains data after its end marker",
            ));
        }
        padding_size += count as u64;
    }
    if padding_size < 512 || padding_size % 512 != 0 {
        return Err(invalid_archive("archive is missing a complete end marker"));
    }
    if extended.path.is_some() || extended.link.is_some() {
        return Err(invalid_archive("archive ends before its extended member"));
    }
    for (path, mode) in directories.into_iter().rev() {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(selected.join(root.ok_or_else(|| invalid_archive("archive is empty"))?))
}
