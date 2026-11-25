//! The verified systemd ancestor shared by the Worker and all of its VMMs.
use std::{io, path::PathBuf, sync::OnceLock};

/// The top-level slice used by existing deep Worker deployments.
pub const DEFAULT_SLICE: &str = "smolvmdeep.slice";
const SLICE_ENV: &str = "SMOLVM_WORKER_SLICE_NAME";

fn valid_slice(name: &str) -> bool {
    name.strip_suffix(".slice").is_some_and(|stem| {
        !stem.is_empty()
            && stem.len() <= 63
            && !matches!(stem, "system" | "user" | "machine" | "smolvm")
            && stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

/// Resolve one dedicated top-level slice for the process lifetime.
pub fn configured_slice() -> io::Result<&'static str> {
    static SLICE: OnceLock<Result<String, &'static str>> = OnceLock::new();
    SLICE
        .get_or_init(|| match std::env::var(SLICE_ENV) {
            Ok(name) if valid_slice(&name) => Ok(name),
            Err(std::env::VarError::NotPresent) => Ok(DEFAULT_SLICE.into()),
            _ => Err("SMOLVM_WORKER_SLICE_NAME must name a dedicated top-level systemd slice"),
        })
        .as_ref()
        .map(String::as_str)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, *error))
}

pub(crate) fn cgroup() -> io::Result<PathBuf> {
    Ok(PathBuf::from("/sys/fs/cgroup").join(configured_slice()?))
}

pub(crate) fn contains_process(pid: i32) -> io::Result<bool> {
    let prefix = format!("0::/{}/", configured_slice()?);
    let groups = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    Ok(groups.lines().any(|line| {
        line.strip_prefix(&prefix)
            .is_some_and(|child| child.ends_with(".scope") && !child.contains('/'))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_dedicated_top_level_slice_is_required() {
        assert!(valid_slice(DEFAULT_SLICE));
        assert!(valid_slice("smolvmproof42.slice"));
        for invalid in [
            "-.slice",
            "smolvm.slice",
            "system.slice",
            "smolvm-deep.slice",
            "a/escape.slice",
            "proof.scope",
        ] {
            assert!(!valid_slice(invalid), "{invalid}");
        }
    }
}
