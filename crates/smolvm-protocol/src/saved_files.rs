//! Mount topology shared by the System Guest and the offline StatePoint reader.

use std::io;

/// Maximum size of one captured mountinfo record.
pub const MAX_MOUNTINFO: usize = 24 << 10;
const MAX_MOUNTS: usize = 256;

#[derive(Clone, Debug)]
/// One mount read from the Guest namespace.
pub struct Mount {
    /// Absolute byte path in the Guest namespace.
    pub target: Vec<u8>,
    /// Absolute byte path relative to the mounted filesystem.
    pub root: Vec<u8>,
    /// Linux device major and minor.
    pub device: (u32, u32),
    /// Linux filesystem type.
    pub filesystem: String,
}

fn invalid() -> io::Error {
    io::Error::other("invalid Guest mount topology")
}

fn unescape(word: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut index = 0;
    while index < word.len() {
        let byte = word[index];
        if byte == b'\\' {
            let escaped = word.get(index + 1..index + 4).ok_or_else(invalid)?;
            let byte = match escaped {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid()),
            };
            output.push(byte);
            index += 4;
        } else {
            output.push(byte);
            index += 1;
        }
    }
    if !valid_path(&output) {
        return Err(invalid());
    }
    Ok(output)
}

/// Accept an absolute byte path with normalized components.
pub fn valid_path(path: &[u8]) -> bool {
    path == b"/"
        || path.strip_prefix(b"/").is_some_and(|suffix| {
            path.len() <= 4096
                && !path.contains(&0)
                && suffix
                    .split(|&byte| byte == b'/')
                    .all(|part| !part.is_empty() && part != b"." && part != b"..")
        })
}

/// Decode a bounded mountinfo record with a whole-device ext4 root.
pub fn parse(raw: &[u8]) -> io::Result<Vec<Mount>> {
    if raw.len() > MAX_MOUNTINFO || !raw.ends_with(b"\n") {
        return Err(invalid());
    }
    let mut mounts = Vec::new();
    for line in raw[..raw.len() - 1].split(|&byte| byte == b'\n') {
        let fields: Vec<_> = line.split(|&byte| byte == b' ').collect();
        let split = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(invalid)?;
        if split < 6 || fields.len() != split + 4 || mounts.len() == MAX_MOUNTS {
            return Err(invalid());
        }
        let device = std::str::from_utf8(fields[2]).map_err(io::Error::other)?;
        let (major, minor) = device.split_once(':').ok_or_else(invalid)?;
        let filesystem = std::str::from_utf8(fields[split + 1]).map_err(io::Error::other)?;
        if filesystem.is_empty()
            || filesystem.len() > 64
            || !filesystem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        {
            return Err(invalid());
        }
        mounts.push(Mount {
            target: unescape(fields[4])?,
            root: unescape(fields[3])?,
            device: (
                major.parse().map_err(io::Error::other)?,
                minor.parse().map_err(io::Error::other)?,
            ),
            filesystem: filesystem.into(),
        });
    }
    if mounts
        .iter()
        .rev()
        .find(|mount| mount.target == b"/")
        .is_none_or(|mount| {
            mount.root != b"/"
                || mount.filesystem != "ext4"
                || mount.device.0 == 0
                || mount.device.1 != 0
        })
    {
        return Err(invalid());
    }
    Ok(mounts)
}

/// Resolve whole virtio disk slots relative to the managed ext4 root. Other
/// devices (including partitions and device mapper) have no saved mapping.
pub fn disk_slot(root_major: u32, mount: &Mount) -> Option<usize> {
    (mount.filesystem == "ext4" && mount.device.0 == root_major && mount.device.1 % 16 == 0)
        .then_some(mount.device.1 as usize / 16)
}
