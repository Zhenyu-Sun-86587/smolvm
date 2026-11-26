use super::{Catalog, NewExecution};
use crate::ipc::{Expected, Fault, Request};
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
        catalog.mark_gc("permanent", 1).unwrap_err().code,
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
fn committed_restore_can_abort_after_exit_only_without_recorded_publication() {
    let work = tempfile::tempdir().unwrap();
    let mut catalog = Catalog::open(&work.path().join("catalog.sqlite"), "boot", "session").unwrap();
    let bundle = format!("sha256:{}", "2".repeat(64));
    let digest = format!("sha256:{}", "4".repeat(64));
    catalog.register_bundle(&bundle, &digest).unwrap();

    for phase in ["failed_held", "policy_armed", "released"] {
        let mut request: Request = serde_json::from_value(json!({
            "protocol":"WorkerResource/1","method":"BeginOperation","request_id":"catalog",
            "route_id":"deep","operation_id":phase,"request_digest":digest,"bundle_digest":bundle,
            "expected":{"instance_id":phase,"incarnation_id":null,"execution_epoch":0},
        }))
        .unwrap();
        let operation = catalog.begin(&request, "restore_target").unwrap();
        let target = Expected {
            instance_id: phase.into(),
            incarnation_id: Some(phase.into()),
            execution_epoch: 1,
        };
        let execution = catalog.register_execution(&operation, NewExecution {
            route: "deep", bundle: &bundle, expected: &target, boot: "boot",
            pid: 123, start: 456, uid: 1000, permit_digest: &digest,
        }).unwrap();
        catalog.db.execute(
            "INSERT INTO target_activations VALUES(?1,?2,?1,?1,1,'session','boot',?3,?4,
             '{}',NULL,2,4,?1,'commit',5,6)",
            rusqlite::params![phase, bundle, format!("{phase:0<64}"), "1".repeat(32)],
        ).unwrap();

        request.expected = Some(target);
        assert_eq!(catalog.finish(&request, true, 1).unwrap_err().code, "E_FENCE_UNPROVEN");
        catalog.finalize_execution(&execution).unwrap();
        request.expected.as_mut().unwrap().incarnation_id = None;
        if phase == "released" {
            assert_eq!(catalog.finish(&request, true, 1).unwrap_err().code, "E_FENCE_UNPROVEN");
        } else {
            assert_eq!(catalog.finish(&request, true, 1).unwrap().phase, "ABORTED");
            assert_eq!(catalog.finish(&request, true, 1).unwrap().phase, "ABORTED");
        }
        let history: (String, String) = catalog.db.query_row(
            "SELECT phase,decision FROM target_activations WHERE operation_id=?",
            [phase], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(history.0, if phase == "released" { "released" } else { "failed_held" });
        assert_eq!(history.1, "commit");
    }
}

#[test]
fn fork_receipt_reports_activation_for_current_attempt_only() {
    let work = tempfile::tempdir().unwrap();
    let mut catalog = Catalog::open(&work.path().join("catalog.sqlite"), "boot", "session").unwrap();
    let bundle = format!("sha256:{}", "2".repeat(64));
    let digest = format!("sha256:{}", "4".repeat(64));
    catalog.register_bundle(&bundle, &digest).unwrap();
    let request: Request = serde_json::from_value(json!({
        "protocol":"WorkerResource/1","method":"BeginOperation","request_id":"catalog",
        "route_id":"deep","operation_id":"child","request_digest":digest,"bundle_digest":bundle,
        "expected":{"instance_id":"child","incarnation_id":null,"execution_epoch":0},
    }))
    .unwrap();
    let operation = catalog.begin(&request, "restore_target").unwrap();
    catalog.register_execution(&operation, NewExecution {
        route: "deep", bundle: &bundle, boot: "boot", pid: 123, start: 456, uid: 1000,
        permit_digest: &digest,
        expected: &Expected {
            instance_id: "child".into(), incarnation_id: Some("target".into()), execution_epoch: 1,
        },
    }).unwrap();
    catalog.db.execute_batch(
        "INSERT INTO operations
             SELECT 'source','fork_batch',request_digest,route_id,'source',bundle_digest,1,NULL,'NEW','NONE',1
             FROM operations WHERE operation_id='child';
         INSERT INTO executions (incarnation_id,route_id,instance_id,execution_epoch,bundle_digest,host_boot_id,
                pid,pid_start_time,uid,phase,last_operation_id,launch_permit_digest)
             SELECT 'parent',route_id,'source',1,bundle_digest,host_boot_id,122,pid_start_time,uid,'registered',
                'source',launch_permit_digest FROM executions WHERE incarnation_id='target';
         INSERT INTO managed_fork_batches (operation_id,source_incarnation,serve_instance,capture_id,template,
                children,session,token,anchor,network_gate,original,stage,source_released)
             VALUES ('source','parent','serve','capture','{}','[]',1,'token','anchor',0,'RUNNING','children',1);
         INSERT INTO managed_fork_children(batch_id,ordinal,name,instance_id,operation_id,prior_epoch)
             VALUES ('source',0,'child','child','child',0);
         INSERT INTO managed_launches(operation_id,incarnation_id,serve_instance,machine_name,spec_json,
                devices_json,vcpus,memory_mib) VALUES ('child','target','serve','child','{}','[]',1,512);",
    ).unwrap();
    let receipt = || catalog.operation("source").unwrap().fork.unwrap()["children"][0].clone();
    assert!(receipt().get("activation_decision").is_none());

    catalog.db.execute(
        "INSERT INTO target_activations VALUES('child',?1,'child','target',1,'session','boot',?2,?3,
         '{}',NULL,2,NULL,'identity_ready','none',3,4)",
        rusqlite::params![bundle, "1".repeat(64), "2".repeat(32)],
    ).unwrap();
    assert_eq!(receipt()["activation_decision"], "none");
    catalog.db.execute(
        "UPDATE target_activations SET phase='policy_armed',decision='commit',prior_revision=5,revision=6,commit_revision=4",
        [],
    ).unwrap();
    assert_eq!(receipt()["activation_decision"], "commit");

    catalog.db.execute(
        "UPDATE managed_fork_children SET operation_id='child-retry',attempt=1,prior_epoch=1",
        [],
    ).unwrap();
    let retry = receipt();
    assert_eq!(retry["attempt"], 1);
    assert_eq!(retry["execution_epoch"], 2);
    assert!(retry.get("activation_decision").is_none());
}

#[test]
fn failed_collection_keeps_the_tombstone_and_its_backing_edge() {
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
        let mut catalog = Catalog::open(&path, "boot", "original").unwrap();
        catalog.register_bundle(&bundle, &digest).unwrap();
        catalog.begin(&request, "catalog").unwrap();
        for id in ["point", "disk"] {
            catalog.register_resource(&request, id, "durable", json!({"id":id})).unwrap();
        }
        catalog.add_edge(&request, "point", "disk", "backing").unwrap();
        catalog.finish(&request, false, 1).unwrap();
        catalog.mark_gc("point", 1).unwrap();
        assert_eq!(catalog.collect_gc("point", 2, |_| Err(Fault::new("E_HOST_IO", "injected unlink failure")))
            .unwrap_err().code, "E_HOST_IO");
        assert_eq!(catalog.resource("point").unwrap()["state"], "deleting");
        assert_eq!(catalog.mark_gc("disk", 1).unwrap_err().code, "E_RESOURCE_PINNED");
    }

    let mut catalog = Catalog::open(&path, "boot", "restarted").unwrap();
    assert_eq!(catalog.collect_gc("point", 2, |_| unreachable!()).unwrap_err().code, "E_RECOVERING");
    catalog.complete_recovery("restarted").unwrap();
    let pending = catalog.pending_gc(0).unwrap();
    let [(_, point, revision, false)] = pending.as_slice() else {
        panic!("expected the original tombstone");
    };
    assert_eq!((point.as_str(), *revision), ("point", 2));
    let deleted = catalog.collect_gc(point, *revision, |_| Ok(())).unwrap();
    assert_eq!(deleted["state"], "deleted");
    assert_eq!(catalog.collect_gc(point, *revision, |_| Ok(())).unwrap(), deleted);
    assert_eq!(catalog.mark_gc("disk", 1).unwrap()["state"], "deleting");
}
