//! Private, explicitly provisioned state for a deep Serve installation.

use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};
use std::path::{Component, Path, PathBuf};

const STATE_MARKER: &str = ".smolvm-deep-state-v1";
const SOCKET_MARKER: &str = ".smolvm-deep-socket-v1";
const STATE_MAGIC: &str = "smolvm-deep-state/1\n";
pub(crate) const UID_REGISTRY: &str = "/var/lib/smolvm-custom/worker/uid-claims";

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn validate_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.parent().is_none()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid(
            "deep runtime paths must be absolute and must not contain ..",
        ));
    }
    for legacy in [
        "/var/lib/smolvm",
        "/var/lib/smolvm-platform-runtime",
        "/run/smolvm-platform",
    ] {
        if path.starts_with(legacy) || Path::new(legacy).starts_with(path) {
            return Err(invalid(
                "deep runtime path overlaps an official runtime path",
            ));
        }
    }
    if path
        .ancestors()
        .find(|entry| entry.exists())
        .is_some_and(|ancestor| {
            !ancestor
                .canonicalize()
                .is_ok_and(|resolved| resolved == ancestor)
        })
    {
        return Err(invalid("deep runtime paths cannot traverse symlinks"));
    }
    Ok(())
}

fn private_dir(path: &Path) -> io::Result<File> {
    validate_path(path)?;
    if fs::symlink_metadata(path).is_err_and(|err| err.kind() == io::ErrorKind::NotFound) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(path)?;
    }
    if path.canonicalize()? != path {
        return Err(invalid("deep runtime directory cannot traverse symlinks"));
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    let meta = dir.metadata()?;
    if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return Err(invalid("deep runtime directory must be owned by the serving uid and cannot be writable by other users"));
    }
    Ok(dir)
}

fn lock(file: &File, blocking: bool) -> io::Result<()> {
    let flags = libc::LOCK_EX | if blocking { 0 } else { libc::LOCK_NB };
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), flags) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn read_marker(dir: &Path, marker: &str) -> io::Result<String> {
    use std::io::Read;
    let marker = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(marker))?;
    let meta = marker.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
        || meta.len() > 128
    {
        return Err(invalid("invalid deep runtime directory ownership marker"));
    }
    let mut contents = String::new();
    marker.take(129).read_to_string(&mut contents)?;
    Ok(contents)
}

fn claim_dir(dir: &Path, marker: &str, expected: &str) -> io::Result<()> {
    let directory = private_dir(dir)?;
    lock(&directory, true)?;
    match read_marker(dir, marker) {
        Ok(contents) if contents == expected => Ok(()),
        Ok(_) => Err(invalid(
            "deep runtime directory belongs to another installation",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if fs::read_dir(dir)?.next().is_some() {
                return Err(invalid(
                    "unmarked deep runtime directory must be empty on first use",
                ));
            }
            use std::io::Write;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(marker))?;
            file.write_all(expected.as_bytes())?;
            file.sync_all()?;
            directory.sync_all()
        }
        Err(error) => Err(error),
    }
}

/// Establish the selected private state before resolving any writable paths.
pub fn initialize(state: Option<&Path>) -> crate::Result<()> {
    let environment = std::env::var_os("SMOLVM_DATA_DIR").map(PathBuf::from);
    let root = state.or(environment.as_deref()).ok_or_else(|| {
        crate::Error::config(
            "deep runtime",
            "an explicit --state-dir or SMOLVM_DATA_DIR is required",
        )
    })?;
    claim_dir(root, STATE_MARKER, STATE_MAGIC)?;
    for subdir in [
        ".cache",
        ".cache/smolvm",
        ".local",
        ".local/share",
        ".local/share/smolvm",
        ".config",
        ".config/smolvm",
        ".smolvm",
    ] {
        let candidate = root.join(subdir);
        if fs::symlink_metadata(&candidate).is_ok_and(|meta| !meta.is_dir()) {
            return Err(invalid(
                "deep runtime writable paths must remain inside its state directory",
            )
            .into());
        }
    }
    for key in ["SMOLVM_CONFIG", "SMOLVM_PACK_STAGING", "SMOLVM_USAGE_DIR"] {
        if let Some(path) = std::env::var_os(key).map(PathBuf::from) {
            if path == root || !path.starts_with(root) {
                return Err(crate::Error::config(
                    "deep runtime",
                    format!("{key} must be inside the selected state directory"),
                ));
            }
            validate_path(&path)?;
        }
    }
    std::env::set_var("SMOLVM_DATA_DIR", root.canonicalize()?);
    std::env::remove_var("SMOLVM_CGROUP_ROOT");
    std::env::remove_var("XDG_RUNTIME_DIR");
    Ok(())
}

fn scope_id(root: &Path) -> String {
    hex::encode(&Sha256::digest(root.as_os_str().as_bytes())[..16])
}

/// Verify the bound state directory and get its stable systemd and tmpfs identity.
pub(crate) fn instance_id() -> Option<String> {
    let configured = std::env::var_os("SMOLVM_DATA_DIR").map(PathBuf::from)?;
    let root = configured.canonicalize().ok()?;
    if configured != root {
        return None;
    }
    (read_marker(&root, STATE_MARKER).ok()?.as_str() == STATE_MAGIC).then(|| scope_id(&root))
}

pub(crate) fn require_instance() -> crate::Result<String> {
    instance_id().ok_or_else(|| {
        crate::Error::config(
            "deep runtime",
            "a private runtime state directory is required",
        )
    })
}

pub(crate) fn require_private_path(path: &Path) -> crate::Result<()> {
    let root = std::env::var_os("SMOLVM_DATA_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| invalid("deep runtime needs a bound state directory"))?;
    if path == root || !path.starts_with(&root) {
        return Err(
            invalid("deep runtime writable path must be inside its state directory").into(),
        );
    }
    validate_path(path)?;
    Ok(())
}

pub(crate) fn private_tmpfs(kind: &str) -> Option<PathBuf> {
    let shared = Path::new("/dev/shm");
    let path = shared.join(format!("smolvmdeep-{kind}-{}", instance_id()?));
    let metadata = fs::symlink_metadata(&path).ok()?;
    // A directory or bind mount on the shared tmpfs does not reserve space.
    let expected_mode = if kind == "capture" { 0o711 } else { 0o700 };
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    let mount = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    (metadata.is_dir()
        && metadata.dev() != fs::metadata(shared).ok()?.dev()
        && metadata.uid() == 0
        && metadata.mode() & 0o777 == expected_mode
        && unsafe { libc::statfs(mount.as_ptr(), &mut stat) } == 0
        && stat.f_type == libc::TMPFS_MAGIC)
        .then_some(path)
}

pub(crate) fn prepare_uid_registry() -> io::Result<()> {
    let path = Path::new(UID_REGISTRY);
    validate_path(path)?;
    if !path.exists() {
        let parent = path.parent().expect("UID registry parent");
        private_dir(parent)?;
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let dir = private_dir(path)?;
    if dir.metadata()?.mode() & 0o777 != 0o700 {
        return Err(invalid("deep Worker UID registry must use mode 0700"));
    }
    Ok(())
}

/// Claim this Serve's socket directory and retain the exclusive state lease.
pub(crate) fn claim_serve(socket: &Path) -> crate::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    validate_path(socket)?;
    if socket.as_os_str().as_bytes().len() >= 108 || socket.file_name().is_none() {
        return Err(invalid("invalid deep Unix socket path").into());
    }
    let root = std::env::var_os("SMOLVM_DATA_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| invalid("deep Serve needs a bound state directory"))?;
    let identity =
        instance_id().ok_or_else(|| invalid("deep Serve needs a bound state directory"))?;
    let socket_dir = socket
        .parent()
        .ok_or_else(|| invalid("deep Serve needs a socket directory"))?;
    if socket_dir != root {
        claim_dir(socket_dir, SOCKET_MARKER, &identity)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(".smolvm-deep-serve.lock"))?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.nlink() != 1
        || meta.mode() & 0o022 != 0
    {
        return Err(invalid("invalid deep Serve state lock").into());
    }
    lock(&file, false)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_and_socket_ownership_are_explicit_and_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("official");
        fs::create_dir(&old).unwrap();
        fs::write(old.join("machines.db"), "official contents").unwrap();
        assert!(claim_dir(&old, STATE_MARKER, STATE_MAGIC).is_err());
        assert_eq!(
            fs::read_to_string(old.join("machines.db")).unwrap(),
            "official contents"
        );
        assert!(!old.join(STATE_MARKER).exists());

        let first = temp.path().join("first");
        let second = temp.path().join("second");
        claim_dir(&first, STATE_MARKER, STATE_MAGIC).unwrap();
        claim_dir(&second, STATE_MARKER, STATE_MAGIC).unwrap();
        assert_ne!(scope_id(&first), scope_id(&second));

        let socket = temp.path().join("socket");
        claim_dir(&socket, SOCKET_MARKER, &scope_id(&first)).unwrap();
        assert!(claim_dir(&socket, SOCKET_MARKER, &scope_id(&second)).is_err());
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&old, &alias).unwrap();
        assert!(claim_dir(&alias, STATE_MARKER, STATE_MAGIC).is_err());
    }
}
