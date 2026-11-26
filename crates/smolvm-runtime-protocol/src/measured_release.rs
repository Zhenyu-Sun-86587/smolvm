use super::{CONTRACT_PROTOCOLS, Capability, Handshake};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MANAGED_ACCEPTANCE_PATH: &str = "metadata/managed-acceptance.json";
const WORKER: &str = "smolvm-resourced";
const SYSTEM_TEMPLATE: &str = "guest/system-debian.tar.gz";
const NETWORK_CONTRACT: &str = "managed_private_network";
const BASE_CASES: [&str; 5] = [
    "oci-capture",
    "lifecycle",
    "system-fork",
    "system-captures",
    "system-relay",
];
const PACKET_CASES: [(&str, &str, &str); 2] = [
    ("packet-native", "fixed_internal", "native"),
    ("packet-fixed", "native", "fixed_internal"),
];
const MANAGED: [&str; 4] = [
    "managed_block_launch",
    "managed_parked_fork",
    "managed_statepoint",
    "lifecycle_policy",
];
// Keep this projection in the same order as the release measurement tool.
const MEASURED_ARTIFACTS: [(&str, &str); 7] = [
    ("smolvm-bin", "smolvm-bin"),
    (WORKER, WORKER),
    ("lib/libkrun.so.2", "lib/libkrun.so"),
    ("lib/libkrunfw.so.5", "lib/libkrunfw.so"),
    ("guest/oci-rootfs.tar.gz", "guest/oci-rootfs.tar.gz"),
    ("guest/identity-helper", "guest/identity-helper"),
    ("guest/agent", "guest/agent"),
];

pub struct MeasuredRelease {
    worker_sha256: String,
    private_network: bool,
}

impl MeasuredRelease {
    pub fn worker_sha256(&self) -> &str {
        &self.worker_sha256
    }

    pub fn advertise(&self, handshake: &mut Handshake, unavailable: Option<&str>) {
        let mut publish = |name: &str, profile: &str| {
            let capability = if let Some(reason) = unavailable {
                Capability {
                    status: "unknown".into(),
                    supported: false,
                    reason_code: reason.into(),
                    contract_version: None,
                    verified_profile: None,
                }
            } else {
                Capability {
                    status: "supported".into(),
                    supported: true,
                    reason_code: String::new(),
                    contract_version: Some(1),
                    verified_profile: Some(profile.into()),
                }
            };
            handshake.capabilities.insert(name.into(), capability);
        };
        publish("lifecycle.standby", "managed-parked-v1");
        publish("boot.system_state_restore", "system-debian-v1");
        if self.private_network {
            for name in [
                "network.native",
                "network.fixed_internal",
                "network.tap",
                "network.tap_restore",
            ] {
                publish(name, "managed-private-system-v1");
            }
            publish("lifecycle.standby_wake", "managed-parked-v1");
        }
    }
}

fn artifact<'a>(manifest: &'a Value, path: &str) -> Option<&'a Value> {
    let mut entries = manifest["artifacts"]
        .as_array()?
        .iter()
        .filter(|a| a["path"] == path);
    let first = entries.next()?;
    entries.next().is_none().then_some(first)
}

fn artifact_digest(manifest: &Value, path: &str) -> Option<String> {
    let sha256 = artifact(manifest, path)?["sha256"].as_str()?;
    valid_hash(sha256).then(|| format!("sha256:{sha256}"))
}

fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}

fn matches_artifact(manifest: &Value, path: &str, field: &Value) -> bool {
    artifact_digest(manifest, path).is_some_and(|digest| *field == digest)
}

fn log_matches(manifest: &Value, case: &str, run: &Value) -> bool {
    run["harness_sha256"]
        .as_str()
        .and_then(|sha| sha.strip_prefix("sha256:"))
        .is_some_and(valid_hash)
        && matches_artifact(
            manifest,
            &format!("metadata/managed/{case}.log"),
            &run["log_sha256"],
        )
}

fn measurement_digest(manifest: &Value, record: &str) -> Option<String> {
    let artifacts: Vec<Value> = MEASURED_ARTIFACTS
        .iter()
        .map(|(measured, installed)| {
            let index = artifact(manifest, installed)?;
            let sha = index["sha256"].as_str().filter(|sha| valid_hash(sha))?;
            let bytes = index["size"].as_u64().filter(|size| *size > 0)?;
            Some(json!({"path":measured,"sha256":sha,"size":bytes}))
        })
        .collect::<Option<_>>()?;
    let mut contracts: BTreeMap<&str, Value> = CONTRACT_PROTOCOLS
        .iter()
        .map(|(key, _)| (*key, json!(1)))
        .chain(MANAGED.map(|key| (key, json!(1))))
        .collect();
    contracts.insert(
        "state_reader_id",
        json!(format!("managed-acceptance:{record}")),
    );
    let mut stage = json!({"schema":"RuntimeBundle/1","platform":"linux-x86_64",
        "guest":{"boot_profiles":["oci-v1","system-debian-v1"]},"artifacts":artifacts,"contracts":contracts});
    stage.sort_all_objects();
    Some(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&stage).ok()?)
    ))
}

/// Derive capabilities from installed evidence indexed by the verified manifest.
/// The installer checks the complete files, actual System archive and logs. Serve
/// checks the evidence binding again before asking the current Worker for its digest.
pub fn measured_release(manifest: &Value, evidence_bytes: &[u8]) -> Option<MeasuredRelease> {
    let contracts = &manifest["contracts"];
    let guest = &manifest["guest"];
    let boot = guest["boot_profiles"].as_array()?;
    if !MANAGED.iter().all(|key| contracts[key].as_u64() == Some(1))
        || !boot.iter().any(|name| name == "system-debian-v1")
        || !boot.iter().any(|name| name == "oci-v1")
        || !matches_artifact(
            manifest,
            "guest/identity-helper",
            &guest["identity_helper_digest"],
        )
        || !matches_artifact(manifest, "guest/agent", &guest["agent_digest"])
        || !matches_artifact(
            manifest,
            "profiles/verification.json",
            &manifest["verification_profile_digest"],
        )
        || artifact(manifest, MANAGED_ACCEPTANCE_PATH)?["size"].as_u64()?
            != evidence_bytes.len() as u64
        || artifact_digest(manifest, MANAGED_ACCEPTANCE_PATH)?
            != format!("sha256:{:x}", Sha256::digest(evidence_bytes))
    {
        return None;
    }
    let worker_sha256 = artifact_digest(manifest, WORKER)?;
    let system_template = artifact_digest(manifest, SYSTEM_TEMPLATE)?;
    let evidence: Value = serde_json::from_slice(evidence_bytes).ok()?;
    if !matches_artifact(
        manifest,
        "metadata/build-lock.json",
        &evidence["build_lock_sha256"],
    ) || !matches_artifact(
        manifest,
        "metadata/build-record.json",
        &evidence["build_record_sha256"],
    ) || !BASE_CASES
        .iter()
        .all(|case| log_matches(manifest, case, &evidence["runs"][case]))
    {
        return None;
    }
    let private_network = match evidence["schema"].as_str()? {
        "RuntimeManagedAcceptance/1" if contracts.get(NETWORK_CONTRACT).is_none() => false,
        "RuntimeManagedAcceptance/2" if contracts[NETWORK_CONTRACT].as_u64() == Some(1) => {
            let packet = &evidence["private_network"];
            let measured = measurement_digest(manifest, evidence["build_record_sha256"].as_str()?)?;
            if packet["measurement_bundle_digest"] != measured
                || packet["system_template_sha256"] != system_template
                || !PACKET_CASES.iter().all(|(case, source, target)| {
                    let run = &packet["runs"][case];
                    run["source_mode"] == *source
                        && run["target_mode"] == *target
                        && run["harness_sha256"]
                            == evidence["runs"]["system-fork"]["harness_sha256"]
                        && log_matches(manifest, case, run)
                })
                || packet["runs"]["packet-native"]["log_sha256"]
                    == packet["runs"]["packet-fixed"]["log_sha256"]
            {
                return None;
            }
            true
        }
        _ => return None,
    };
    Some(MeasuredRelease {
        worker_sha256,
        private_network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(private_network: bool) -> (Value, Vec<u8>) {
        fn entry(path: &str, data: &[u8]) -> Value {
            json!({"path":path,"size":data.len(),"sha256":format!("{:x}",Sha256::digest(data))})
        }

        let names = MEASURED_ARTIFACTS.map(|(_, installed)| installed);
        let files = [
            "metadata/build-lock.json",
            "metadata/build-record.json",
            "profiles/verification.json",
            SYSTEM_TEMPLATE,
        ];
        let paths = names.into_iter().chain(files).map(str::to_owned).chain(
            BASE_CASES
                .into_iter()
                .chain(PACKET_CASES.map(|(case, _, _)| case))
                .map(|case| format!("metadata/managed/{case}.log")),
        );
        let artifacts: Vec<_> = paths.map(|path| entry(&path, path.as_bytes())).collect();
        let contracts: BTreeMap<_, _> = MANAGED
            .into_iter()
            .map(|key| (key, json!(1)))
            .chain(CONTRACT_PROTOCOLS.map(|(key, _)| (key, json!(1))))
            .chain(std::iter::once((
                "state_reader_id",
                json!("fixture-reader"),
            )))
            .collect();
        let mut manifest = json!({"schema":"RuntimeBundle/1","platform":"linux-x86_64",
            "contracts":contracts,"artifacts":artifacts,"guest":{"boot_profiles":["oci-v1","system-debian-v1"]}});
        manifest["guest"]["identity_helper_digest"] =
            json!(artifact_digest(&manifest, "guest/identity-helper"));
        manifest["guest"]["agent_digest"] = json!(artifact_digest(&manifest, "guest/agent"));
        manifest["verification_profile_digest"] =
            json!(artifact_digest(&manifest, "profiles/verification.json"));
        let run = |case| {
            json!({"harness_sha256":format!("sha256:{}","a".repeat(64)),
            "log_sha256":artifact_digest(&manifest,&format!("metadata/managed/{case}.log"))})
        };
        let runs: BTreeMap<_, _> = BASE_CASES
            .map(|case| (case, run(case)))
            .into_iter()
            .collect();
        let mut evidence = json!({"schema":"RuntimeManagedAcceptance/1","runs":runs,
            "build_lock_sha256":artifact_digest(&manifest,"metadata/build-lock.json"),
            "build_record_sha256":artifact_digest(&manifest,"metadata/build-record.json")});
        if private_network {
            let packet: BTreeMap<_, _> = PACKET_CASES
                .map(|(case, source, target)| {
                    let mut run = run(case);
                    run["source_mode"] = json!(source);
                    run["target_mode"] = json!(target);
                    (case, run)
                })
                .into_iter()
                .collect();
            evidence["schema"] = json!("RuntimeManagedAcceptance/2");
            evidence["private_network"] = json!({"runs":packet,
                "system_template_sha256":artifact_digest(&manifest,SYSTEM_TEMPLATE),
                "measurement_bundle_digest":measurement_digest(&manifest,evidence["build_record_sha256"].as_str().unwrap())});
            manifest["contracts"][NETWORK_CONTRACT] = json!(1);
        }
        let bytes = serde_json::to_vec(&evidence).unwrap();
        let index = manifest["artifacts"].as_array_mut().unwrap();
        index.push(entry(MANAGED_ACCEPTANCE_PATH, &bytes));
        (manifest, bytes)
    }

    #[test]
    fn measured_profiles_keep_legacy_and_unmeasured_names_scoped() {
        for private_network in [false, true] {
            let (mut manifest, evidence) = fixture(private_network);
            let release = measured_release(&manifest, &evidence).unwrap();
            let sha = artifact(&manifest, "smolvm-bin").unwrap()["sha256"]
                .as_str()
                .unwrap()
                .to_owned();
            manifest.sort_all_objects();
            manifest["bundle_digest"] = json!(format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&manifest).unwrap())
            ));
            let mut response = crate::handshake(manifest, &sha).unwrap();
            assert!(!response.capabilities["network.native"].supported);
            release.advertise(&mut response, None);
            assert!(response.capabilities["lifecycle.standby"].supported);
            assert!(response.capabilities["boot.system_state_restore"].supported);
            assert_eq!(
                response.capabilities["lifecycle.standby_wake"].supported,
                private_network
            );
            assert_eq!(
                response.capabilities["network.native"].supported,
                private_network
            );
            assert!(!response.capabilities["network.native_reidentity"].supported);
            release.advertise(&mut response, Some("WORKER_RELEASE_MISMATCH"));
            assert!(!response.capabilities["lifecycle.standby"].supported);
            assert_eq!(response.capabilities["lifecycle.standby"].status, "unknown");
            assert!(response.capabilities["boot.system"].supported);
        }
    }

    #[test]
    fn network_evidence_rejects_a_different_worker_and_changed_measurement() {
        let (mut manifest, mut evidence) = fixture(true);
        let original = measured_release(&manifest, &evidence).unwrap();
        assert_eq!(
            Some(original.worker_sha256.clone()),
            artifact_digest(&manifest, WORKER)
        );
        manifest["artifacts"][1]["sha256"] = json!("b".repeat(64));
        assert!(measured_release(&manifest, &evidence).is_none());
        let (manifest, _) = fixture(true);
        evidence.push(b' ');
        assert!(measured_release(&manifest, &evidence).is_none());
    }
}
