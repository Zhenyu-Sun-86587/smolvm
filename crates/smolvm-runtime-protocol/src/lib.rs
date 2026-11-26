//! Wire types for the downstream Linux Serve extension.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub mod cpu_quota;

/// Systemd scope shared by the Serve that launches a managed VMM and the
/// Worker that verifies its process and accounts for its resources.
pub fn managed_scope_name(serve: &str, machine: &str) -> String {
    let machine_hash = format!("{:x}", Sha256::digest(machine.as_bytes()));
    format!("smolvmdeep-vm-{serve}-{}.scope", &machine_hash[..32])
}

mod measured_release;
pub use measured_release::{MANAGED_ACCEPTANCE_PATH, MeasuredRelease, measured_release};

const CONTRACT_PROTOCOLS: [(&str, &str); 6] = [
    ("worker_resource", "WorkerResource"),
    ("capture_control", "CaptureControl"),
    ("statepoint", "StatePoint"),
    ("guest_identity", "GuestIdentity"),
    ("block_attachment", "BlockAttachment"),
    ("network_attachment", "NetworkAttachment"),
];

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRef {
    pub instance_id: String,
    pub incarnation_id: String,
    pub execution_epoch: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub status: String,
    pub supported: bool,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Handshake {
    pub schema: String,
    pub route_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_instance_id: Option<String>,
    pub bundle_digest: String,
    pub state_reader_id: String,
    pub protocols: BTreeMap<String, u32>,
    pub required_features: Vec<String>,
    pub capabilities: BTreeMap<String, Capability>,
}

/// The installer verifies the full bundle. Serve also verifies that its own
/// executable and the reader it advertises belong to that manifest.
pub fn handshake(mut manifest: Value, binary_hash: &str) -> Result<Handshake, &'static str> {
    let obj = manifest.as_object_mut().ok_or("invalid bundle manifest")?;
    let digest = obj.remove("bundle_digest").ok_or("missing bundle digest")?;
    obj.remove("signature");
    manifest.sort_all_objects();
    let payload = serde_json::to_vec(&manifest).map_err(|_| "invalid bundle payload")?;
    let actual = format!("sha256:{:x}", Sha256::digest(payload));
    if digest != actual
        || manifest["schema"] != "RuntimeBundle/1"
        || manifest["platform"] != "linux-x86_64"
    {
        return Err("incompatible bundle manifest");
    }
    let artifacts = manifest["artifacts"]
        .as_array()
        .ok_or("missing artifacts")?;
    let mut binaries = artifacts.iter().filter(|a| a["path"] == "smolvm-bin");
    if binaries.next().is_none_or(|a| a["sha256"] != binary_hash) || binaries.next().is_some() {
        return Err("Serve binary does not match bundle");
    }
    let contracts = &manifest["contracts"];
    let reader = contracts["state_reader_id"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or("missing reader ID")?;
    let mut protocols = BTreeMap::new();
    for (field, name) in CONTRACT_PROTOCOLS {
        if contracts[field].as_u64() != Some(1) {
            return Err("incompatible bundle protocol");
        }
        protocols.insert(name.to_owned(), 1);
    }
    protocols.insert("RuntimeBundle".to_owned(), 1);
    let mut capabilities: BTreeMap<String, Capability> = [
        "lifecycle.standby",
        "lifecycle.standby_wake",
        "state.live_fork",
        "state.independent_fork",
        "state.fork_batch",
        "state.checkpoint",
        "state.hibernate",
        "state.restore",
        "state.rollback",
        "state.clone_ready",
        "storage.block_attach",
        "storage.multidisk_capture",
        "network.tap",
        "network.tap_restore",
        "network.native",
        "network.fixed_internal",
        "network.native_reidentity",
        "boot.system",
        "boot.system_state_restore",
    ]
    .into_iter()
    .map(|name| {
        (
            name.to_owned(),
            Capability {
                status: "unknown".into(),
                supported: false,
                reason_code: "CAPABILITY_NOT_VERIFIED".into(),
                contract_version: None,
                verified_profile: None,
            },
        )
    })
    .collect();
    if contracts["managed_block_launch"].as_u64() == Some(1)
        && manifest["guest"]["boot_profiles"]
            .as_array()
            .is_some_and(|p| p.iter().any(|v| v == "system-debian-v1"))
        && artifacts
            .iter()
            .any(|a| a["path"] == "guest/identity-helper")
    {
        capabilities.insert(
            "boot.system".into(),
            Capability {
                status: "supported".into(),
                supported: true,
                reason_code: String::new(),
                contract_version: Some(1),
                verified_profile: Some("system-debian-v1".into()),
            },
        );
    }
    if contracts["managed_parked_fork"].as_u64() == Some(1)
        && contracts["managed_block_launch"].as_u64() == Some(1)
        && manifest["guest"]["boot_profiles"].as_array().is_some_and(|profiles| profiles.iter().any(|p|p=="oci-v1"))
        && artifacts.iter().any(|a|a["path"]=="guest/identity-helper") {
        for name in ["state.independent_fork","state.fork_batch"] {
            capabilities.insert(name.into(),Capability {
                supported:true, status:"supported".into(), reason_code:String::new(),
                contract_version:Some(1), verified_profile:Some("managed-parked-v1".into()),
            });
        }
    }
    if contracts["managed_statepoint"].as_u64() == Some(1)
        && contracts["managed_block_launch"].as_u64() == Some(1)
        && artifacts.iter().any(|a| a["path"] == "guest/identity-helper")
    {
        for name in ["state.checkpoint", "state.hibernate", "state.restore", "state.rollback"] {
            capabilities.insert(name.into(), Capability {
                status: "supported".into(), supported: true, reason_code: String::new(),
                contract_version: Some(1), verified_profile: Some("managed-block-v1".into()),
            });
        }
    }
    Ok(Handshake {
        schema: "runtime-ext/v1".into(),
        route_id: "deep".into(),
        runtime_instance_id: None,
        bundle_digest: actual,
        state_reader_id: reader.to_owned(),
        protocols,
        required_features: vec![],
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn negotiation_binds_reader_and_serve_to_one_manifest() {
        let binary_hash = format!("{:x}", Sha256::digest(b"smolvm fixture"));
        let mut manifest = json!({
            "schema": "RuntimeBundle/1", "platform": "linux-x86_64",
            "artifacts":[{"path":"smolvm-bin","sha256":binary_hash}],
            "contracts":{"state_reader_id":"reader-1","worker_resource":1,"statepoint":1,
                "block_attachment":1,"guest_identity":1,"network_attachment":1,"capture_control":1}
        });
        manifest.sort_all_objects();
        manifest["bundle_digest"] = json!(format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&manifest).unwrap())
        ));
        let response = handshake(manifest.clone(), &binary_hash).unwrap();
        assert_eq!(response.state_reader_id, "reader-1");
        assert!(!response.capabilities["state.hibernate"].supported);
        assert!(handshake(manifest.clone(), "other binary").is_err());
        manifest["contracts"]["state_reader_id"] = json!("reader-2");
        assert!(handshake(manifest, &binary_hash).is_err());
    }
}
