use super::*;
use crate::statepoint_capture::{Export, Purpose};
use crate::statepoint_store::{self, Point, Region as SavedRegion};
use std::collections::BTreeMap;
use std::process::Child;

struct TestProcess(Child);

impl TestProcess {
    fn start() -> Self {
        Self(Command::new("/usr/bin/sleep").arg("60").spawn().unwrap())
    }

    fn pid(&self) -> i32 {
        self.0.id() as i32
    }

    fn exit(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

const REGIONS: [Region; 2] = [
    Region {
        guest_start: 0,
        size: 4096,
    },
    Region {
        guest_start: 8192,
        size: 4096,
    },
];

fn recorded(
    path: &Path,
    donor: &TestProcess,
    helper: &TestProcess,
    kind: &str,
    owner: &str,
) -> Catalog {
    let c = Catalog::open(path, "boot-a", "broker-a").unwrap();
    c.register_bundle(&digest(b"bundle"), &digest(b"executable"))
        .unwrap();
    c.db.execute(
        "INSERT INTO operations VALUES('op',?,'request','deep','machine',?,1,
        'source','NEW','NONE',1)",
        params![kind, digest(b"bundle")],
    )
    .unwrap();
    c.db.execute(
        "INSERT INTO executions(incarnation_id,route_id,instance_id,execution_epoch,bundle_digest,
         host_boot_id,pid,pid_start_time,uid,phase,last_operation_id)
         VALUES('source','deep','machine',1,?,'boot-a',?,?,20100,'registered','op')",
        params![
            digest(b"bundle"),
            donor.pid(),
            pid_start(donor.pid()).unwrap()
        ],
    )
    .unwrap();
    c.db.execute("INSERT INTO managed_fork_batches(operation_id,source_incarnation,serve_instance,
        capture_id,template,children,session,token,anchor,network_gate,original,stage,
        selected_memory_fork_backend)
        VALUES('op','source','serve','cut',?,'[]',1,'hold','gate',0,'RUNNING','exporting','kernel_cow')",
        [r#"{"memory_mib":64}"#]).unwrap();
    c.db.execute(
        "INSERT INTO resources VALUES('cut','descriptor','available','volatile',1,
        '{\"schema\":\"KernelMmAnchor/1\"}','digest','op',1)",
        [],
    )
    .unwrap();
    c.db.execute(
        "INSERT INTO root_refs VALUES(?,'op','cut','active',1,'op')",
        [owner],
    )
    .unwrap();
    let layout_digest =
        digest(&serde_json::to_vec(&json!({"profile":PROFILE,"regions":REGIONS})).unwrap());
    let exec = fs::metadata(format!("/proc/{}/exe", helper.pid())).unwrap();
    c.db.execute(
        "INSERT INTO kernel_mm_anchors VALUES('cut','op','source',1,1,'boot-a',
        ?,?,'0123456789abcdef0123456789abcdef',?,?,?,?,'cut',NULL)",
        params![
            serde_json::to_string(&REGIONS).unwrap(),
            layout_digest,
            helper.pid(),
            pid_start(helper.pid()).unwrap(),
            exec.dev() as i64,
            exec.ino() as i64
        ],
    )
    .unwrap();
    c
}

#[test]
fn recovery_replays_only_the_original_accounted_kernel_cut() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("catalog.sqlite");
    let source = TestProcess::start();
    let mut helper = TestProcess::start();
    let first = recorded(&path, &source, &helper, "fork_batch", "fork_capture");
    first.db.execute_batch(
        "INSERT INTO native_endpoints VALUES('source','/run/test-control',1,1);
         UPDATE managed_fork_batches SET stage='children',source_released=1,checkpoint=x'01';",
    ).unwrap();
    drop(first);

    let mut catalog = Catalog::open(&path, "boot-a", "second").unwrap();
    reconcile(&catalog).unwrap();
    // A known RAM resource cannot clear an unknown source execution.
    let blocked = |c: &mut Catalog| {
        assert_eq!(c.complete_recovery("second").unwrap_err().code, "E_RECOVERING");
    };
    blocked(&mut catalog);
    catalog.db.execute_batch(
        "UPDATE executions SET phase='registered' WHERE incarnation_id='source';
         UPDATE kernel_mm_anchors SET source_session=2;",
    ).unwrap();
    blocked(&mut catalog);
    catalog.db.execute_batch(
        "UPDATE kernel_mm_anchors SET source_session=1;
         UPDATE root_refs SET state='dropped';",
    ).unwrap();
    blocked(&mut catalog);
    catalog.db.execute_batch(
        "UPDATE root_refs SET state='active';
         UPDATE managed_fork_batches SET selected_memory_fork_backend='native';",
    ).unwrap();
    blocked(&mut catalog);
    catalog.db.execute("UPDATE managed_fork_batches SET selected_memory_fork_backend='kernel_cow'", []).unwrap();
    assert_eq!(catalog.complete_recovery("second").unwrap()["state"], "ready");

    // Once the journal proves the source was released, its exit cannot
    // strand a child of the same cut. A recorded loss remains a loss.
    catalog.db.execute_batch(
        "UPDATE worker_state SET recovering=1;
         UPDATE executions SET phase='exited';
         DELETE FROM native_endpoints;
         UPDATE managed_fork_batches SET source_released=0;",
    ).unwrap();
    blocked(&mut catalog);
    catalog.db.execute("UPDATE managed_fork_batches SET source_released=1", []).unwrap();
    assert_eq!(catalog.complete_recovery("second").unwrap()["state"], "ready");
    helper.exit();
    reconcile(&catalog).unwrap();
    catalog.db.execute("UPDATE worker_state SET recovering=1", []).unwrap();
    assert_eq!(catalog.complete_recovery("second").unwrap()["state"], "ready");
    assert_eq!(catalog.resource("cut").unwrap()["state"], "lost");
    assert!(pinned(&catalog, "op", "cut").is_err());
}

#[test]
fn restart_keeps_original_process_and_loss_never_rebinds_cut() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("catalog.sqlite");
    let source = TestProcess::start();
    let mut helper = TestProcess::start();
    let mut restored_child = TestProcess::start();
    assert_ne!(source.pid(), helper.pid());
    drop(recorded(
        &path,
        &source,
        &helper,
        "fork_batch",
        "fork_capture",
    ));
    let c = Catalog::open(&path, "boot-a", "broker-b").unwrap();
    reconcile(&c).unwrap();
    let recovered = pinned(&c, "op", "cut").ok().unwrap();
    let live = process(&recovered, "boot-a").unwrap().unwrap();
    assert!(!pid_exited(&live).unwrap());
    assert_eq!(recovered.pid, helper.pid());
    assert_eq!(recovered.receipt.regions, REGIONS);
    assert!(process(&recovered, "different-host-boot")
        .unwrap()
        .is_none());
    assert_eq!(c.resource("cut").unwrap()["kind"], "kernel_mm_anchor");
    assert_eq!(c.resource("cut").unwrap()["state"], "available");
    assert_eq!(
        pinned(&c, "other-op", "cut").err().unwrap().code,
        "E_NOT_FOUND"
    );

    helper.exit();
    reconcile(&c).unwrap();
    assert!(pid_exited(&live).unwrap());
    assert_eq!(c.resource("cut").unwrap()["state"], "lost");
    assert_eq!(
        c.closure("fork_capture", "op").unwrap()["resources"],
        json!([])
    );
    assert_eq!(acquire(&c, "op", "cut").unwrap_err().code, "E_CAPTURE_LOST");
    let source_row = c.execution("source").unwrap();
    let (_, donor) = observe_pid(source.pid()).unwrap();
    assert_eq!(
        register(&c, "op", "cut", &source_row, donor, &REGIONS)
            .unwrap_err()
            .code,
        "E_CAPTURE_LOST"
    );
    assert!(restored_child.0.try_wait().unwrap().is_none());
}

#[test]
fn last_capture_pin_fences_collection() {
    let tmp = tempfile::tempdir().unwrap();
    let source = TestProcess::start();
    let mut helper = TestProcess::start();
    let mut c = recorded(
        &tmp.path().join("catalog.sqlite"),
        &source,
        &helper,
        "fork_batch",
        "fork_capture",
    );
    c.db.execute(
        "INSERT INTO root_refs VALUES('operation','target','cut','active',1,'op')",
        [],
    )
    .unwrap();
    c.db.execute(
        "UPDATE root_refs SET state='dropped' WHERE owner_kind='fork_capture'",
        [],
    )
    .unwrap();
    reconcile(&c).unwrap();
    assert_eq!(c.resource("cut").unwrap()["state"], "available");
    assert_eq!(
        crate::admission::status(&c.db).unwrap()["allocated"]["memory_mib"],
        145
    );
    c.db.execute(
        "UPDATE root_refs SET state='dropped' WHERE owner_kind='operation'",
        [],
    )
    .unwrap();
    reconcile(&c).unwrap();
    assert_eq!(c.resource("cut").unwrap()["state"], "available");
    c.db.execute(
        "UPDATE operations SET phase='COMPLETED' WHERE operation_id='op'",
        [],
    )
    .unwrap();
    reconcile(&c).unwrap();
    assert_eq!(c.resource("cut").unwrap()["state"], "deleting");
    helper.exit();
    c.collect_gc("cut", 2, |catalog| collect(catalog, "cut"))
        .unwrap();
    assert_eq!(c.resource("cut").unwrap()["state"], "deleted");
    assert_eq!(
        crate::admission::status(&c.db).unwrap()["allocated"]["memory_mib"],
        0
    );
}

#[test]
fn durable_checkpoint_replays_original_ram_and_clears_volatile_export_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("catalog.sqlite");
    let source = TestProcess::start();
    let helper = TestProcess::start();
    let mut c = recorded(
        &path,
        &source,
        &helper,
        "vm_snapshot",
        "kernel_anchor_export",
    );
    let op = c.operation("op").unwrap();
    let checkpoint = b"captured CPU and device state";
    let export = Export {
        capture_id: "cut".into(),
        representation_id: "durable-cut".into(),
        purpose: Purpose::Checkpoint,
        session: 1,
        hold_token: "1".repeat(32),
    };
    let point = Point {
        schema: "StatePoint/1".into(),
        capture_id: "cut".into(),
        representation_id: "durable-cut".into(),
        incarnation_id: "source".into(),
        execution_epoch: 1,
        source_ram_digest: lookup(&c, "cut").unwrap().unwrap().receipt.layout_digest,
        checkpoint_digest: digest(checkpoint),
        checkpoint_bytes: checkpoint.len() as u64,
        capture_anchor: "1".repeat(32),
        helper_digest: digest(b"helper"),
        regions: REGIONS
            .into_iter()
            .map(|r| SavedRegion {
                gpa: r.guest_start,
                length: r.size,
            })
            .collect(),
        devices: Vec::new(),
        disk_generations: Vec::new(),
    };
    c.start_statepoint(&op, &export, &point, Some(checkpoint))
        .unwrap();
    drop(c);
    let mut c = Catalog::open(&path, "boot-a", "broker-restarted").unwrap();
    let replay_checkpoint = c.kernel_statepoint_checkpoint("cut").unwrap();
    let (rx, mut tx) = UnixStream::pair().unwrap();
    let input: Vec<u8> = (0..8192).map(|index| (index / 4096) as u8).collect();
    tx.write_all(&input).unwrap();
    tx.write_all(b"+").unwrap();
    drop(tx);
    let mut ram = RamReader {
        stream: rx,
        remaining: input.len() as u64,
    };
    let manifest = statepoint_store::write(
        tmp.path(),
        point,
        op.bundle_digest,
        op.operation_id,
        &replay_checkpoint,
        &mut ram,
        BTreeMap::new(),
    )
    .unwrap();
    let pending = c.require_statepoint("cut").unwrap();
    let saved = c
        .publish_statepoint(&pending, &manifest, &manifest.digest().unwrap())
        .unwrap();
    assert_eq!(saved.phase, "durable");
    assert!(c.kernel_statepoint_checkpoint("cut").is_err());
    assert_eq!(
        c.closure("kernel_anchor_export", "op").unwrap()["resources"],
        json!([])
    );
    let (mut cpu, mut memory) =
        statepoint_store::materialize(tmp.path(), &manifest, BTreeMap::new()).unwrap();
    let mut bytes = Vec::new();
    cpu.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, checkpoint);
    bytes.clear();
    memory.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, input);
}

#[test]
fn incomplete_anchor_stream_cannot_publish_last_chunk() {
    for body in [b"abc".as_slice(), b"abcd".as_slice(), b"abcd-".as_slice()] {
        let (rx, mut tx) = UnixStream::pair().unwrap();
        tx.write_all(body).unwrap();
        drop(tx);
        let mut ram = RamReader {
            stream: rx,
            remaining: 4,
        };
        assert!(ram.read_exact(&mut [0; 4]).is_err());
    }
}
