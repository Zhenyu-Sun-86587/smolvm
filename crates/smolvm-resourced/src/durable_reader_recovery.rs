//! Recover the original RAM reader of a committed durable restore.

use super::{Identity, Worker};
use crate::catalog::Execution;
use crate::escrow_catalog::LeaseRecord;
use crate::grants::fence_unproven;
use crate::ipc::{Fault, Result};
use crate::native_control::Endpoint;
use crate::statepoint_capture::host_io;
use crate::statepoint_store;
use rusqlite::params;
use std::collections::HashSet;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

fn materialized_ram_link(link: &Path, store: &Path) -> bool {
    let Ok(relative) = link.strip_prefix(store) else {
        return false;
    };
    let mut elements = relative.iter();
    elements
        .next()
        .and_then(|entry| entry.to_str())
        .is_some_and(|entry| entry.starts_with(".restore-"))
        && elements.next().is_some_and(|entry| entry == "materialized")
        && elements
            .next()
            .is_some_and(|entry| entry == "memory.bin (deleted)")
        && elements.next().is_none()
}

fn immutable_ram_identity(meta: &Metadata, size: u64) -> Option<Identity> {
    (meta.is_file() && meta.nlink() == 0 && meta.mode() & 0o222 == 0 && meta.len() == size)
        .then(|| (meta.dev(), meta.ino(), meta.len()))
}

fn retained_identity(pid: i32, directory: &Path, size: u64) -> Result<Identity> {
    let directory = fs::canonicalize(directory).map_err(host_io)?;
    let mut identities = HashSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd")).map_err(host_io)? {
        let path = entry.map_err(host_io)?.path();
        let link = match fs::read_link(&path) {
            Ok(link) => link,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(host_io(error)),
        };
        if !materialized_ram_link(&link, &directory) {
            continue;
        }
        let meta = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(host_io(error)),
        };
        if let Some(identity) = immutable_ram_identity(&meta, size) {
            identities.insert(identity);
        }
    }
    if identities.len() != 1 {
        return Err(fence_unproven(
            "the original StatePoint RAM reader is absent or ambiguous",
        ));
    }
    Ok(identities.into_iter().next().expect("one RAM reader"))
}

fn corrupt(error: io::Error) -> Fault {
    Fault::new("E_STATEPOINT_CORRUPT", error.to_string())
}

impl Worker {
    pub(super) fn recover_statepoint_reader(
        &mut self,
        execution: &Execution,
        lease: &LeaseRecord,
        capture: &str,
    ) -> Result<()> {
        let fail =
            || fence_unproven("durable reader does not belong to a committed StatePoint restore");
        if lease.incarnation_id != execution.incarnation_id
            || lease.operation_id != execution.last_operation_id
            || lease.delivered != 2
            || lease.state != "unknown"
        {
            return Err(fail());
        }
        self.verify_live_execution(execution)?;
        let operation = self.catalog.operation(&lease.operation_id)?;
        let activation = self.catalog.activation(&lease.operation_id)?;
        let (point, source) = crate::managed_state_restore::source(
            &self.catalog,
            &execution.route_id,
            &execution.bundle_digest,
            capture,
        )?;
        if operation.kind != "restore_target"
            || operation.phase != "COMPLETED"
            || !activation.matches(execution)
            || activation.phase != "released"
            || activation.decision != "commit"
            || activation.binding.input.capture_resource_id != lease.resource_id
            || activation.binding.input.capture_anchor != point.point.capture_anchor
            || point.point.representation_id != lease.resource_id
        {
            return Err(fail());
        }
        let directory = self.statepoints.directory();
        let manifest = statepoint_store::read(
            directory,
            &point.point,
            &source.bundle_digest,
            &source.operation_id,
        )
        .map_err(corrupt)?;
        if point.manifest_digest.as_deref() != Some(manifest.digest().map_err(corrupt)?.as_str()) {
            return Err(Fault::new(
                "E_STATEPOINT_CORRUPT",
                "durable StatePoint restore manifest changed",
            ));
        }

        // Older readers retain the immutable anonymous materialization without
        // recording its inode in the catalog. Discover it in this exact peer,
        // then obtain the actual open description and verify the packed bytes.
        // The checkpoint descriptor has already been consumed by the loader.
        let size = point.point.memory_bytes().map_err(corrupt)?;
        let identity = retained_identity(execution.pid, directory, size)?;
        let endpoint = Endpoint::load(&self.catalog.db, &execution.incarnation_id, &self.boot)?;
        let files = endpoint
            .recover_descriptors("reader", &[identity])?
            .ok_or_else(|| {
                fence_unproven("the original VMM did not return its StatePoint RAM reader")
            })?;
        let [file] = <[_; 1]>::try_from(files).map_err(|_| fail())?;
        let file = File::from(file);
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        let before = file.metadata().map_err(host_io)?;
        if flags < 0
            || flags & libc::O_PATH != 0
            || flags & libc::O_ACCMODE != libc::O_RDONLY
            || immutable_ram_identity(&before, size) != Some(identity)
        {
            return Err(fail());
        }
        statepoint_store::verify_retained_ram(directory, &manifest, &file).map_err(corrupt)?;
        let after = file.metadata().map_err(host_io)?;
        if immutable_ram_identity(&after, size) != Some(identity)
            || (before.ctime(), before.ctime_nsec()) != (after.ctime(), after.ctime_nsec())
        {
            return Err(fail());
        }
        self.verify_live_execution(execution)?;

        if self.catalog.db.execute(
            "UPDATE fd_leases SET state='attached', revision=revision+1
             WHERE lease_id=? AND operation_id=? AND incarnation_id=? AND resource_id=?
             AND state='unknown' AND delivered=2 AND revision=?",
            params![
                lease.lease_id,
                lease.operation_id,
                execution.incarnation_id,
                lease.resource_id,
                lease.revision
            ],
        )? != 1
        {
            return Err(Fault::new(
                "E_STALE_REVISION",
                "StatePoint lease changed during recovery",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_only_deleted_ram_in_the_exact_worker_store() {
        let base = Path::new("/state/a/statepoints");
        assert!(materialized_ram_link(
            &base.join(".restore-test/materialized/memory.bin (deleted)"),
            base,
        ));
        for other in [
            ".restore-test/materialized/checkpoint.bin (deleted)",
            ".restore-test/materialized/memory.bin",
            "restore-test/materialized/memory.bin (deleted)",
            ".restore-test/extra/materialized/memory.bin (deleted)",
            "../b/statepoints/.restore-test/materialized/memory.bin (deleted)",
        ] {
            assert!(!materialized_ram_link(&base.join(other), base));
        }
    }
}
