// SPDX-License-Identifier: Apache-2.0
//! The coordinator supplies one fixed-length identity request to its own helper.
//! The helper never accepts an identity, pathname or executable from argv or env.
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use zeroize::{Zeroize, Zeroizing};

const NAME: &CStr = c"machine-id";
const FRAME: usize = 192;
const ACK: usize = 80;
const HOSTNAME: u32 = 1;
const MACHINE_ID: u32 = 2;
const ENTROPY: u32 = 4;
const READY: u8 = 1;
const COMPLETE: u8 = 2;
const FAILED: u8 = 3;

fn errno(result: i32) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn invalid() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

struct Identity<'a> {
    hostname: &'a [u8],
    machine_id: [u8; 33],
    entropy: &'a [u8],
}

impl<'a> Identity<'a> {
    fn decode(frame: &'a [u8; FRAME]) -> io::Result<Self> {
        // Bytes 8..64 bind this operation to the host's nonce, epoch and digest
        // of the complete execution/attachment context. The kernel checks the
        // acknowledgement against its own active context.
        let epoch = u64::from_le_bytes(frame[24..32].try_into().unwrap());
        let name_len = frame[112] as usize;
        if &frame[..4] != b"SGI1"
            || frame[4..8] != [1, 0, 0, 0]
            || epoch == 0
            || frame[8..24].iter().all(|&v| v == 0)
            || frame[32..64].iter().all(|&v| v == 0)
            || frame[64..96].iter().all(|&v| v == 0)
            || frame[96..112].iter().all(|&v| v == 0)
            || !(1..=63).contains(&name_len)
            || frame[113 + name_len..].iter().any(|&v| v != 0)
        {
            return Err(invalid());
        }
        let hostname = &frame[113..113 + name_len];
        if !hostname.split(|&c| c == b'.').all(|label| {
            !label.is_empty()
                && label[0].is_ascii_alphanumeric()
                && label[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .iter()
                    .all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        }) {
            return Err(invalid());
        }
        let mut machine_id = [b'\n'; 33];
        let hex = b"0123456789abcdef";
        for (i, b) in frame[96..112].iter().enumerate() {
            machine_id[2 * i] = hex[(b >> 4) as usize];
            machine_id[2 * i + 1] = hex[(b & 15) as usize];
        }
        Ok(Self {
            hostname,
            machine_id,
            entropy: &frame[64..96],
        })
    }
}

// Use an unnamed file and a challenge-derived temporary link within the pinned
// Guest directory. A partial write cannot truncate the installed machine ID.
fn install_machine_id(dir: &File, desired: &[u8; 33], nonce: &[u8]) -> io::Result<()> {
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            NAME.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if raw >= 0 {
        let mut old = unsafe { File::from_raw_fd(raw) };
        if !old.metadata()?.is_file() {
            return Err(invalid());
        }
        let mut bytes = [0u8; 34];
        let mut count = 0;
        while count < bytes.len() {
            match old.read(&mut bytes[count..])? {
                0 => break,
                n => count += n,
            }
        }
        if count == desired.len() && bytes[..count] == desired[..] {
            return Ok(());
        }
    } else if io::Error::last_os_error().kind() != io::ErrorKind::NotFound {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_CLOEXEC | libc::O_RDWR,
            0o444 as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut temp = unsafe { File::from_raw_fd(fd) };
    temp.write_all(desired)?;
    temp.sync_all()?;
    let mut label = *b".smolvm-identity-00000000000000000000000000000000\0";
    let digits = b"0123456789abcdef";
    for (i, b) in nonce.iter().enumerate() {
        label[17 + i * 2] = digits[(b >> 4) as usize];
        label[18 + i * 2] = digits[(b & 15) as usize];
    }
    let name = CStr::from_bytes_with_nul(&label).map_err(|_| invalid())?;
    errno(unsafe {
        libc::linkat(
            temp.as_raw_fd(),
            c"".as_ptr(),
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    })?;
    if let Err(error) = errno(unsafe {
        libc::renameat(
            dir.as_raw_fd(),
            name.as_ptr(),
            dir.as_raw_fd(),
            NAME.as_ptr(),
        )
    }) {
        unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
        return Err(error);
    }
    dir.sync_all()
}

fn apply(frame: &[u8; FRAME], dir: &File, rng: &mut File, completed: &mut u32) -> io::Result<()> {
    let identity = Identity::decode(frame)?;
    install_machine_id(dir, &identity.machine_id, &frame[8..24])?;
    *completed |= MACHINE_ID;
    errno(unsafe {
        libc::sethostname(identity.hostname.as_ptr().cast(), identity.hostname.len())
    })?;
    *completed |= HOSTNAME;
    rng.write_all(identity.entropy)?;
    // RNDRESEEDCRNG mixes the fresh host material before userspace is released.
    errno(unsafe { libc::ioctl(rng.as_raw_fd(), 0x5207) })?;
    *completed |= ENTROPY;
    Ok(())
}

fn response(phase: u8, frame: &[u8; FRAME], completed: u32, error: i32) -> [u8; ACK] {
    let mut ack = [0; ACK];
    ack[..4].copy_from_slice(b"SGA1");
    ack[4] = phase;
    ack[8..64].copy_from_slice(&frame[8..64]);
    ack[64..68].copy_from_slice(&completed.to_le_bytes());
    ack[68..72].copy_from_slice(&error.to_le_bytes());
    ack
}

pub fn run() -> io::Result<()> {
    let mut control = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/smolvm-identity")?;
    if !control.metadata()?.file_type().is_char_device() {
        return Err(invalid());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/etc")?;
    // A frozen userspace filesystem daemon cannot service a target identity
    // write. Only profiles using this locally served mount may register.
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    errno(unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) })?;
    let fs = unsafe { stat.assume_init() }.f_type as u64;
    if fs != libc::EXT4_SUPER_MAGIC as u64 && fs != libc::TMPFS_MAGIC as u64 {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let mut rng = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/urandom")?;
    let meta = rng.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if !meta.file_type().is_char_device()
        || libc::major(meta.rdev()) != 1
        || libc::minor(meta.rdev()) != 9
    {
        return Err(invalid());
    }
    let mut frame = Zeroizing::new([0; FRAME]);
    errno(unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) })?;
    let mut stack = [0u8; 32 * 1024];
    for at in (0..size_of::<[u8; 32 * 1024]>()).step_by(4096) {
        unsafe {
            std::ptr::write_volatile(stack.as_mut_ptr().add(at), 1);
        }
    }
    control.write_all(&response(READY, &frame, 0, 0))?;
    control.read_exact(&mut *frame)?;
    let mut completed = 0;
    let result = apply(&frame, &directory, &mut rng, &mut completed);
    let ack = match &result {
        Ok(()) => response(COMPLETE, &frame, completed, 0),
        Err(error) => response(
            FAILED,
            &frame,
            completed,
            -error.raw_os_error().unwrap_or(libc::EIO),
        ),
    };
    frame.zeroize();
    control.write_all(&ack)?;
    result
}
