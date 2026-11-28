//! Byte-safe filesystem operations on the Worker-attested System Agent stream.

use serde::{Deserialize, Serialize};

use crate::base64_bytes;

/// Advertised independently of the base Agent protocol version.
pub const CAPABILITY: &str = "system-file-transfer-v2";
/// Supported on a System image provisioned with the desktop account.
pub const DESKTOP_DROP_CAPABILITY: &str = "system-file-desktop-drop-v1";
/// Byte limit for one streamed upload or download.
pub const MAX_BYTES: u64 = 4 << 30;
/// Maximum number of entries in a recursive operation.
pub const MAX_ARCHIVE_ENTRIES: usize = 16_384;
/// Maximum number of entries per directory page.
pub const MAX_PAGE: u16 = 200;

/// One request on the execution-scoped System Agent connection. Only write
/// chunks and commit are accepted after a write has been staged.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Request {
    /// Report home and transfer bounds.
    Capabilities,
    /// Read a page in bytewise basename order.
    List {
        /// Absolute filesystem path.
        path: BytePath,
        /// Maximum number of entries to return.
        limit: u16,
        /// Absolute path of the last entry received.
        after: Option<BytePath>,
    },
    /// Inspect metadata for a selected path.
    Stat {
        /// Absolute filesystem path.
        path: BytePath,
        /// Whether to follow a final symlink.
        follow: bool,
    },
    /// Resolve the absolute path, including symlinks.
    Realpath {
        /// Absolute filesystem path.
        path: BytePath,
    },
    /// Stream a bounded range of a regular file.
    Read {
        /// Absolute filesystem path.
        path: BytePath,
        /// Starting byte offset.
        offset: u64,
        /// Maximum number of bytes to read, or to EOF when absent.
        length: Option<u64>,
    },
    /// Stream a raw tar containing the selected directory.
    Archive {
        /// Absolute filesystem path.
        path: BytePath,
    },
    /// Stage an upload without changing the destination.
    WriteBegin {
        /// Absolute filesystem path.
        path: BytePath,
        /// Size in bytes.
        size: u64,
        /// Lowercase hexadecimal SHA-256 digest.
        sha256: String,
        /// Policy for an occupied destination.
        overwrite: Overwrite,
        /// Whether to follow a final symlink.
        follow: bool,
        /// Whether to publish a tar archive under the selected parent.
        archive: bool,
    },
    /// Stage a desktop upload into a directory belonging to the desktop account.
    DesktopWriteBegin {
        /// Absolute filesystem path.
        path: BytePath,
        /// Size in bytes.
        size: u64,
        /// Lowercase hexadecimal SHA-256 digest.
        sha256: String,
        /// Policy for an occupied destination.
        overwrite: Overwrite,
        /// Whether to publish a tar archive under the selected parent.
        archive: bool,
    },
    /// Append the next nonempty, bounded piece to a staged upload.
    WriteChunk {
        #[serde(with = "base64_bytes")]
        /// Bytes encoded as base64.
        data: Vec<u8>,
    },
    /// Verify and publish the staged upload.
    WriteCommit,
    /// Create a directory.
    Mkdir {
        /// Absolute filesystem path.
        path: BytePath,
        /// Whether the operation may include nested entries.
        recursive: bool,
    },
    /// Unlink a filesystem entry.
    Remove {
        /// Absolute filesystem path.
        path: BytePath,
        /// Whether the operation may include nested entries.
        recursive: bool,
    },
    /// Copy an entry to the exact destination path.
    Copy {
        /// Absolute filesystem path.
        path: BytePath,
        /// Absolute destination path.
        destination: BytePath,
        /// Whether the operation may include nested entries.
        recursive: bool,
        /// Policy for an occupied destination.
        overwrite: Overwrite,
    },
    /// Move an entry within its filesystem.
    Rename {
        /// Absolute filesystem path.
        path: BytePath,
        /// Absolute destination path.
        destination: BytePath,
        /// Policy for an occupied destination.
        overwrite: Overwrite,
    },
}

/// Standard padded base64 on the wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BytePath(#[serde(with = "base64_bytes")] pub Vec<u8>);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Destination conflict behavior.
pub enum Overwrite {
    /// Refuse an occupied destination.
    Reject,
    /// Permit replacement of a compatible destination.
    Replace,
}

#[derive(Debug, Serialize)]
/// Byte-preserving filesystem metadata.
pub struct Entry {
    /// Display name with replacement for non-UTF-8 data.
    pub name: String,
    /// Absolute filesystem path.
    pub path: String,
    /// Original byte path for future operations.
    pub path_bytes: BytePath,
    #[serde(rename = "type")]
    /// Stable filesystem entry type.
    pub kind: &'static str,
    /// Size in bytes.
    pub size: u64,
    /// POSIX permission and special bits.
    pub mode: u32,
    /// Last modification time as Unix seconds.
    pub modified_unix: i64,
}

#[derive(Debug, Serialize)]
/// Integrity receipt for a completed transfer.
pub struct BytesReceipt {
    /// Number of bytes in the verified stream.
    pub bytes: u64,
    /// Lowercase hexadecimal SHA-256 digest.
    pub sha256: String,
}
