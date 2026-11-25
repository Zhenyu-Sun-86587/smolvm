//! Wire types for the downstream Linux Serve extension.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRef {
    pub instance_id: String,
    pub incarnation_id: String,
    pub execution_epoch: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Capability {
    pub status: String,
    pub supported: bool,
    pub reason_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Handshake {
    pub schema: String,
    pub route_id: String,
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
    for (field, name) in [
        ("worker_resource", "WorkerResource"),
        ("capture_control", "CaptureControl"),
        ("statepoint", "StatePoint"),
        ("guest_identity", "GuestIdentity"),
        ("block_attachment", "BlockAttachment"),
        ("network_attachment", "NetworkAttachment"),
    ] {
        if contracts[field].as_u64() != Some(1) {
            return Err("incompatible bundle protocol");
        }
        protocols.insert(name.to_owned(), 1);
    }
    protocols.insert("RuntimeBundle".to_owned(), 1);
    let capabilities = [
        "lifecycle.standby",
        "state.live_fork",
        "state.independent_fork",
        "state.fork_batch",
        "state.checkpoint",
        "state.hibernate",
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
            },
        )
    })
    .collect();
    Ok(Handshake {
        schema: "runtime-ext/v1".into(),
        route_id: "deep".into(),
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
