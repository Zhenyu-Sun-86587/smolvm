//! Persistent identities for opened managed backing files.

use std::fs::{File, Metadata};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

pub(crate) fn live(file: &File) -> io::Result<(u64, u64)> {
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "block storage is not a regular file",
        ));
    }
    Ok((meta.dev(), meta.ino()))
}

pub(crate) fn legacy(value: &str) -> Option<(u64, u64)> {
    let (dev, ino) = value.strip_prefix("inode:")?.split_once(':')?;
    Some((dev.parse().ok()?, ino.parse().ok()?))
}

pub(crate) fn recorded(file: &File) -> io::Result<String> {
    let (dev, ino) = live(file)?;
    Ok(durable(file)?.unwrap_or_else(|| format!("inode:{dev}:{ino}")))
}

pub(crate) fn same_mount(root: &File, file: &File, meta: &Metadata) -> io::Result<bool> {
    if meta.dev() != root.metadata()?.dev() {
        return Ok(false);
    }
    let root = mount_id(root)?;
    let file = mount_id(file)?;
    Ok(root == file)
}

fn mount_id(file: &File) -> io::Result<Option<u64>> {
    let mut stat = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let status = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            libc::STATX_MNT_ID,
            stat.as_mut_ptr(),
        )
    };
    if status < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOSYS) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let stat = unsafe { stat.assume_init() };
    Ok((stat.stx_mask & libc::STATX_MNT_ID != 0).then_some(stat.stx_mnt_id))
}

#[repr(C)]
struct FileHandle {
    bytes: libc::c_uint,
    kind: libc::c_int,
    data: [u8; 128],
}

pub(crate) fn durable(file: &File) -> io::Result<Option<String>> {
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let fs = unsafe { fs.assume_init() };
    // Both filesystems derive f_fsid from their on-disk UUID and encode inode
    // generation in their export handles. Other filesystems may use a kernel
    // device number for f_fsid or supply handles that only live until unmount.
    if !matches!(fs.f_type, libc::EXT4_SUPER_MAGIC | libc::BTRFS_SUPER_MAGIC) {
        return Ok(None);
    }
    // Linux defines fsid_t as two int32 words, with private field names in libc.
    let fsid: [i32; 2] = unsafe { std::mem::transmute(fs.f_fsid) };
    if fsid == [0, 0] {
        return Ok(None);
    }
    let mut handle = FileHandle {
        bytes: 128,
        kind: 0,
        data: [0; 128],
    };
    let mut mount_id = 0;
    let status = unsafe {
        libc::name_to_handle_at(
            file.as_raw_fd(),
            c"".as_ptr(),
            (&mut handle as *mut FileHandle).cast(),
            &mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    if status < 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENOSYS)) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let bytes = handle.data.get(..handle.bytes as usize).filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid kernel file handle"))?;
    Ok(Some(format!(
        "handle-v1:{:x}:{:08x}{:08x}:{}:{}",
        fs.f_type,
        fsid[0],
        fsid[1],
        handle.kind,
        hex::encode(bytes),
    )))
}
