//! Sync the captured ext4 superblocks and return the current mount namespace.

use smolvm_protocol::{error_codes, saved_files, AgentResponse};
use std::{
    collections::BTreeSet, ffi::OsStr, fs::File, io, os::fd::AsRawFd, os::unix::ffi::OsStrExt,
};

pub(crate) fn capture() -> AgentResponse {
    match topology() {
        Ok(mountinfo) => AgentResponse::Ok {
            data: Some(serde_json::json!({ "mountinfo": mountinfo })),
        },
        Err(error) => AgentResponse::error(error.to_string(), error_codes::INVALID_REQUEST),
    }
}

fn topology() -> io::Result<Vec<u8>> {
    let before = std::fs::read("/proc/self/mountinfo")?;
    let mounts = saved_files::parse(&before)?;
    let root = mounts
        .iter()
        .rev()
        .find(|mount| mount.target == b"/")
        .unwrap();
    let mut synced = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for mount in mounts.iter().rev() {
        if !seen.insert(&mount.target)
            || saved_files::disk_slot(root.device.0, mount).is_none()
            || !synced.insert(mount.device)
        {
            continue;
        }
        let file = File::open(OsStr::from_bytes(&mount.target))?;
        let metadata = file.metadata()?;
        use std::os::unix::fs::MetadataExt;
        let device = metadata.dev();
        if (libc::major(device), libc::minor(device)) != mount.device {
            return Err(io::Error::other("Guest mount changed during file sync"));
        }
        if unsafe { libc::syncfs(file.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let after = std::fs::read("/proc/self/mountinfo")?;
    if before != after {
        return Err(io::Error::other(
            "Guest mount topology changed during file sync",
        ));
    }
    Ok(after)
}
