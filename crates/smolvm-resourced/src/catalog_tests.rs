use super::{Catalog, NewExecution};
use crate::ipc::{Expected, Request};
use serde_json::json;

#[test]
fn boot_change_marks_volatile_resources_lost_and_preserves_intents() {
    let work = tempfile::tempdir().unwrap();
    let path = work.path().join("catalog.sqlite");
    let bundle = format!("sha256:{}", "2".repeat(64));
    let digest = format!("sha256:{}", "4".repeat(64));
    let request: Request = serde_json::from_value(json!({
        "protocol":"WorkerResource/1","method":"BeginOperation","request_id":"catalog",
        "route_id":"deep","operation_id":"op","request_digest":digest,"bundle_digest":bundle,
        "expected":{"instance_id":"vm","incarnation_id":null,"execution_epoch":0},
    }))
    .unwrap();
    {
        let mut catalog = Catalog::open(&path, "boot-a", "session-a").unwrap();
        catalog.register_bundle(&bundle, &digest).unwrap();
        catalog.begin(&request, "catalog").unwrap();
        for (id, durability) in [("temporary", "volatile"), ("permanent", "durable")] {
            catalog
                .register_resource(&request, id, durability, json!({"id":id}))
                .unwrap();
        }
    }
    let mut catalog = Catalog::open(&path, "boot-b", "session-b").unwrap();
    assert_eq!(catalog.health().unwrap()["state"], "recovering");
    assert_eq!(catalog.resource("temporary").unwrap()["state"], "lost");
    assert_eq!(catalog.resource("permanent").unwrap()["state"], "available");
    assert_eq!(catalog.begin(&request, "catalog").unwrap().phase, "NEW");
    assert_eq!(
        catalog.complete_recovery("session-b").unwrap_err().code,
        "E_RECOVERING"
    );
    assert_eq!(
        catalog.gc("permanent", 1, false).unwrap_err().code,
        "E_RECOVERING"
    );
    catalog.finish(&request, true, 1).unwrap();
    assert_eq!(
        catalog.complete_recovery("session-a").unwrap_err().code,
        "E_STALE_SESSION"
    );
    assert_eq!(
        catalog.complete_recovery("session-b").unwrap()["state"],
        "ready"
    );
}

#[test]
fn interrupted_cold_boot_can_abort_after_the_execution_is_fenced() {
    let work = tempfile::tempdir().unwrap();
    let bundle = format!("sha256:{}", "2".repeat(64));
    let digest = format!("sha256:{}", "4".repeat(64));
    let mut catalog = Catalog::open(&work.path().join("worker.db"), "boot", "session").unwrap();
    catalog.register_bundle(&bundle, &digest).unwrap();
    let mut launch: Request = serde_json::from_value(json!({
        "protocol":"WorkerResource/1","method":"BeginOperation","request_id":"launch",
        "route_id":"deep","operation_id":"op","request_digest":digest,"bundle_digest":bundle,
        "expected":{"instance_id":"vm","incarnation_id":null,"execution_epoch":0},
    })).unwrap();
    let operation = catalog.begin(&launch, "launch").unwrap();
    let expected = Expected { instance_id: "vm".to_owned(), incarnation_id: Some("exec".to_owned()), execution_epoch: 1 };
    let execution = catalog.register_execution(&operation, NewExecution {
        route: "deep", bundle: &bundle, expected: &expected, boot: "boot", pid: 101, start: 2,
        uid: 1000, permit_digest: &digest,
    }).unwrap();
    launch.expected = Some(expected);
    assert_eq!(catalog.finish(&launch, true, 1).unwrap_err().code, "E_OPERATION_HAS_EFFECTS");
    catalog.finalize_execution(&execution).unwrap();
    launch.expected.as_mut().unwrap().incarnation_id = None;
    assert_eq!(catalog.finish(&launch, false, 1).unwrap_err().code, "E_OPERATION_IN_PROGRESS");
    assert_eq!(catalog.finish(&launch, true, 1).unwrap().phase, "ABORTED");
    launch.operation_id = Some("new-launch".to_owned());
    assert_eq!(catalog.begin(&launch, "launch").unwrap().phase, "NEW");
}
