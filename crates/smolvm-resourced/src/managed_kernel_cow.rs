//! Discover the installed Worker ABI before admitting an anonymous RAM launch.
use crate::ipc::{Fault, Result};
use smolvm_runtime_protocol::kernel_cow::PROFILE;

pub(crate) struct Import {
    pub capture_id: String,
    pub proof_digest: String,
}

pub(crate) const UNAVAILABLE: &str = "worker_kernel_cow_unavailable";
// libkrun's QUERY succeeds only after discovering this UAPI layout.
pub(crate) const ABI_DIGEST: &str =
    "sha256:03e38c51fd9ac381993e22a9e9116060a0d867f39da57de3b717a2c6fa3a37a2";

pub(crate) fn require_worker(bundle: &str) -> Result<()> {
    if worker_available(bundle) {
        Ok(())
    } else {
        Err(Fault::new(
            "E_CAPABILITY_UNSUPPORTED",
            "installed Worker bundle and kernel do not support this Kernel CoW RAM profile",
        ))
    }
}

pub(crate) fn capability(bundle: &str) -> serde_json::Value {
    let available = worker_available(bundle);
    serde_json::json!({
        "supported":available,
        "status":if available { "supported" } else { "unavailable" },
        "reason_code":if available { "" } else { "WORKER_KERNEL_COW_UNAVAILABLE" },
        "contract_version":available.then_some(1),
        "verified_profile":available.then_some(PROFILE),
    })
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn worker_available(_: &str) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn worker_available(bundle: &str) -> bool {
    use std::{fs, io::Read, os::unix::fs::MetadataExt, path::Path};

    if !Path::new("/sys/kernel/smolvm_cow/abi").exists() {
        return false;
    }

    fn trusted(path: &Path) -> Option<()> {
        path.canonicalize().ok()?.ancestors().all(|entry| {
            fs::symlink_metadata(entry)
                .is_ok_and(|meta| meta.uid() == 0 && meta.mode() & 0o022 == 0)
        }).then_some(())
    }

    fn installed_probe(bundle: &str) -> Option<i32> {
        let executable = std::env::current_exe().ok()?;
        let root = executable.parent()?;
        trusted(root)?;
        let manifest = root.join("runtime-bundle.json");
        trusted(&manifest)?;
        const LIMIT: u64 = 16 << 20;
        let mut bytes = Vec::new();
        fs::File::open(manifest).ok()?.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
        if bytes.len() as u64 > LIMIT {
            return None;
        }
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        if manifest["bundle_digest"] != bundle || manifest["schema"] != "RuntimeBundle/1" {
            return None;
        }
        let lib = root.join("lib/libkrun.so");
        let firmware = root.join("lib/libkrunfw.so");
        trusted(&lib)?;
        trusted(&firmware)?;
        // SAFETY: The installed runtime libraries are on a trusted, protected
        // path. The ABI is private to these paired Worker and runtime builds.
        unsafe {
            use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_LAZY};
            let _firmware = Library::open(Some(firmware), RTLD_GLOBAL | RTLD_LAZY).ok()?;
            let krun = Library::open(Some(lib), RTLD_LAZY).ok()?;
            for required in [
                b"krun_enable_worker_kernel_cow_v1\0".as_slice(),
                b"krun_import_worker_kernel_cow_v1\0".as_slice(),
            ] {
                krun.get::<*const libc::c_void>(required).ok()?;
            }
            let probe = krun.get::<unsafe extern "C" fn() -> i32>(
                b"krun_probe_worker_kernel_cow_v1\0",
            ).ok()?;
            Some(probe())
        }
    }

    installed_probe(bundle) == Some(0)
}
