#!/usr/bin/env python3
"""Exercise Worker-owned native resize on real Linux KVM System executions."""

import argparse
import base64
from contextlib import ExitStack
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile

from test_deep_managed_launch import EXT, digest, http, installed_bundle, rpc, settled, until, verify
from test_deep_worker_pressure import MIB, create_slice, open_pidfd, properties, restart_worker


def expect_error(code, operation):
    try:
        operation()
    except RuntimeError as error:
        assert code in str(error), error
    else:
        raise AssertionError(f"expected {code}")


def exercise(endpoint, root, original, inventory, _started, legacy, group, pressure_driver=None):
    worker = root / "ipc/worker.sock"
    bundle = http(endpoint, EXT + "/capabilities")["bundle_digest"]

    def resources(ref):
        view = http(endpoint, f"{EXT}/instances/{ref['instance_id']}/resources", {"expected": ref})
        assert all(view[key] == ref[key] for key in ref), view
        return view

    def binding(name):
        view = http(endpoint, f"{EXT}/machines/{name}/binding")
        return {field: view[field] for field in ("instance_id", "incarnation_id", "execution_epoch")}

    def body(key, ref, kind, parameters):
        return dict(operation_id=key, request_digest=digest(key.encode()), expected=ref,
                    kind=kind, parameters=parameters)

    def operation(key, ref, kind, **parameters):
        return http(endpoint, EXT + "/operations", body(key, ref, kind, parameters))

    def resize(key, ref, **change):
        return operation(key, ref, "resize_resources", **change)

    def complete(key):
        value = settled(endpoint, key, 100)
        assert value["phase"] == "COMPLETED", value
        return value

    def execute(ref, *command):
        view = http(endpoint, f"{EXT}/instances/{ref['instance_id']}/guest/exec",
                    {"expected": ref, "request": {"command": command, "timeout_seconds": 12}})
        result = view["result"]
        assert result["exit_code"] == 0, result
        return base64.b64decode(result["stdout"])

    def ledger():
        return rpc(worker, "QueryWorkerBudget")["allocated"]

    def cpu_quota(ref):
        quota, period = (int(item) for item in resources(ref)["observed"]["scope_cpu_max"].split())
        return quota * 1000 // period

    def control(method, key, ref, payload):
        return rpc(worker, method, payload, route_id="deep",
                   bundle_digest=bundle, expected=ref, operation_id=key, request_digest=digest(key.encode()))

    def limit(key, ref, millicpus):
        return control("SetManagedCPULimit", key, ref, {"millicpus": millicpus})

    def online(ref):
        return execute(ref, "/bin/cat", "/sys/devices/system/cpu/online")

    def scope(pid):
        line = Path(f"/proc/{pid}/cgroup").read_text().strip()
        assert line.startswith("0::/smolvmresize"), line
        return Path("/sys/fs/cgroup") / line.removeprefix("0::/")

    def pressure_round(ref):
        control("ApplyLifecyclePolicy", "pressure-after-resize", ref, {
            "expected_applied_revision": 0, "new_revision": 1,
            "effective_policy": {"auto_standby": False, "auto_hibernate": True,
                                 "hibernate_after_seconds": 600, "min_running_after_wake_seconds": 0},
        })
        counts = {"host": {"inbound": 0, "outbound": 0},
                  "guest": {"inbound": 0, "outbound": 0, "exec": 0, "task": 0},
                  "platform": {"task": 0, "exec": 0, "stream": 0}}
        for collector, values in counts.items():
            control("ReportActivity", "hint-" + collector, ref, {
                "collector": collector, "session": "resize-pressure-test", "seq": 1,
                "valid_for_ms": 60000, "counts": values,
            })
        properties(group.name, str(int((group / "memory.current").read_text()) + 120 * MIB))

        def hint_result():
            view = control("GetLifecycleStatus", "hint-status", ref, {})
            hint = (view["pressure"] or {}).get("last_balloon")
            if hint and hint["outcome"] != "unknown":
                return view, hint

        view, hint = until(hint_result, 35)
        assert hint["decision_id"] == view["last_decision"]["operation_id"]
        assert hint["worker_memory_before_bytes"] > 0 and hint["worker_memory_after_bytes"] > 0
        assert hint["outcome"] in ("observed", "timed_out", "unavailable"), hint
        print(json.dumps({"automatic_balloon_before_hibernate": hint}), flush=True)
        properties(group.name, "infinity")
        return hint

    def unbind_balloon(ref):
        driver = "/sys/bus/virtio/drivers/virtio_balloon"
        device = execute(ref, "/bin/sh", "-ec",
                         f'set -- {driver}/virtio*; test -d "$1"; basename "$1"').decode().strip()
        assert device.startswith("virtio")
        execute(ref, "/bin/sh", "-ec", f'printf %s "$1" > {driver}/unbind', "unbind", device)
        return driver, device

    initial = resources(original)
    assert initial["profile"] == "parked-capture" and initial["capture_compatible"], initial
    assert initial["observed"]["cpus"] == {"created": 2, "capacity": 2}, initial
    assert initial["observed"]["online_cpu_ids"] == [0, 1], initial
    assert initial["capabilities"]["balloon"]["available_now"], initial
    budget = ledger()
    if pressure_driver:
        assert budget["memory_mib"] == 512
        if pressure_driver == "unbound":
            unbind_balloon(original)
        else:
            resize("confirm-balloon", original, change="balloon", target_mib=16)
            assert complete("confirm-balloon")["resize"]["observed"]["balloon"]["actual_mib"] == 16
            resize("return-balloon", original, change="balloon", target_mib=0)
            assert complete("return-balloon")["resize"]["observed"]["balloon"]["actual_mib"] == 0
        assert ledger() == budget
        hint = pressure_round(original)
        assert ledger()["memory_mib"] == budget["memory_mib"]
        if pressure_driver == "unbound":
            assert hint["outcome"] in ("timed_out", "unavailable") and not hint["guest_reported_bytes"], hint
        else:
            assert hint["outcome"] == "observed" and hint["guest_reported_bytes"] > 0, hint
        print(json.dumps({"balloon_driver": pressure_driver, "bundle": bundle, "guest_memory_budget": budget,
                          "worker_digest": rpc(worker, "Health")["executable_sha256"], "hint": hint}), flush=True)
        return
    expect_error("E_CAPABILITY_UNSUPPORTED", lambda: resize("fixed-cpu-refused", original, change="cpu_online", cpus=3))
    expect_error("E_CAPABILITY_UNSUPPORTED", lambda: resize("fixed-ram-refused", original, change="memory_grow", memory_mib=640))
    assert ledger() == budget
    if legacy:
        assert not initial["capabilities"]["cpu_offline"]["available_now"]
        expect_error("E_CAPABILITY_UNSUPPORTED", lambda: resize("legacy-agent-refused", original, change="cpu_offline", cpus=1))
        assert online(original) == b"0-1\n" and ledger() == budget
        print("The original System Agent booted with both actual CPUs online and refused the unadvertised offlining operation.", flush=True)
        return

    execute(original, "/bin/sh", "-ec", "dd if=/dev/zero of=/dev/shm/smolvm-test bs=1M count=144 status=none; rm /dev/shm/smolvm-test")
    accepted = resize("balloon-inflate", original, change="balloon", target_mib=32)
    assert accepted["phase"] == "NEW" and accepted["resize"]["stage"] == "queued", accepted
    balloon = complete("balloon-inflate")["resize"]
    assert balloon["observed"]["balloon"] == {"target_mib": 32, "actual_mib": 32}
    assert balloon["observed"]["scope_memory_before_bytes"] > balloon["observed"]["scope_memory_current_bytes"], balloon
    assert ledger() == budget
    print(json.dumps({"confirmed_balloon": balloon["observed"], "budget_retained": budget}), flush=True)
    resize("balloon-deflate", original, change="balloon", target_mib=0)
    assert complete("balloon-deflate")["resize"]["observed"]["balloon"]["actual_mib"] == 0

    driver, device = unbind_balloon(original)
    resize("balloon-unresponsive", original, change="balloon", target_mib=16)

    def awaiting_actual():
        value = http(endpoint, EXT + "/operations/balloon-unresponsive")
        reading = value["resize"]["observed"].get("balloon")
        if value["phase"] == "NEW" and reading == {"target_mib": 16, "actual_mib": 0}:
            return value

    until(awaiting_actual, 10)
    assert resources(original)["pending"]["operation_id"] == "balloon-unresponsive"
    try:
        operation("capture-during-balloon", original, "vm_snapshot", capture_id="no-capture-during-balloon")
    except RuntimeError as error:
        assert any(code in str(error) for code in ("E_OPERATION_IN_PROGRESS", "E_STATE_CONFLICT")), error
    else:
        raise AssertionError("capture obtained the resize's active binding lock")
    pid = inventory["execution"]["pid"]
    with ExitStack() as restart_stack, open_pidfd(pid) as descriptor:
        restart_worker(restart_stack, root, worker)
        failed = settled(endpoint, "balloon-unresponsive", 65)
        assert failed["phase"] == "ABORTED" and failed["resize"]["error_code"] == "E_BALLOON_UNRESPONSIVE", failed
        assert failed["resize"]["observed"]["balloon"] == {"target_mib": 0, "actual_mib": 0}, failed
        assert not select.select([descriptor], [], [], 0)[0]
        assert ledger() == budget and resources(original)["pending"] is None
        execute(original, "/bin/sh", "-ec", f"printf %s \"$1\" > {driver}/bind", "bind", device)
        print("A target-only balloon ACK stayed pending across real Worker restart, then restored its old target and failed explicitly. Capture waited on the same binding lock.", flush=True)

        quota = (scope(pid) / "cpu.max").read_text()
        resize("offline-one-cpu", original, change="cpu_offline", cpus=1)
        result = complete("offline-one-cpu")["resize"]
        assert result["observed"]["online_cpus"] == 1 and online(original) == b"0\n"
        assert (scope(pid) / "cpu.max").read_text() == quota and ledger() == budget
        assert resources(original)["observed"]["cpus"]["created"] == 2
        operation("capture-offline-cpu", original, "hibernate", capture_id="offline-cpu-point")
        expect_error("E_STATE_CONFLICT", lambda: resize("balloon-during-capture", original, change="balloon", target_mib=16))
        complete("capture-offline-cpu")
        operation("restore-offline-cpu", binding("test-managed"), "vm_restore",
                  name="test-managed", capture_id="offline-cpu-point", mode="exact")
        complete("restore-offline-cpu")
        restored = binding("test-managed")
        assert restored["execution_epoch"] == original["execution_epoch"] + 1
        assert online(restored) == b"0\n"
        assert execute(restored, "/bin/cat", "/sys/devices/system/cpu/present") == b"0-1\n"
        expect_error("E_STALE_EXECUTION", lambda: resources(original))
        resize("restore-online-two", restored, change="cpu_online", cpus=2)
        complete("restore-online-two")
        assert online(restored) == b"0-1\n" and ledger() == budget
        print("The Worker offlined one of two Linux CPUs, kept both created slots and the quota, captured and restored its online set, and onlined the retained slot on the new epoch.", flush=True)

        name = "test-compute-growth"
        disks = [
            dict(attachment_id=f"hot-{role}", device_id=role, role=role,
                 generation_id="base-ext4" if role == "root" else "empty-data", read_only=False)
            for role in ("root", "storage", "data")
        ]
        operation("launch-hot-compute", binding(name), "launch", name=name, boot_profile="system-debian-v1",
                  live_compute_growth=True, cpus=1, memory_mib=512, disks=disks, init="/sbin/init",
                  args=["--unit=multi-user.target", "--log-target=console"])
        complete("launch-hot-compute")
        ref = binding(name)
        shape = until(lambda: (view if (view := resources(ref))["capabilities"]["cpu_grow"]["available_now"]
                                and view["capabilities"]["memory_grow"]["available_now"] else None), 35)
        assert shape["profile"] == "live-compute" and not shape["capture_compatible"], shape
        assert shape["observed"]["cpus"] == {"created": 1, "capacity": 16}
        assert shape["observed"]["online_cpu_ids"] == [0]
        assert cpu_quota(ref) == 1000
        expect_error("E_CAPABILITY_UNSUPPORTED", lambda: operation("hot-capture-refused", ref, "vm_snapshot", capture_id="hot-no-state"))
        held = ledger()
        expect_error("E_RESOURCE_LIMIT", lambda: resize("hot-CPU-cap-refused", ref, change="cpu_online", cpus=5))
        expect_error("E_RESOURCE_LIMIT", lambda: resize("hot-RAM-cap-refused", ref, change="memory_grow", memory_mib=768))
        assert ledger() == held and resources(ref)["observed"]["ram"]["mapped"] == 0

        resized = resize("hot-create-two", ref, change="cpu_online", cpus=2)
        assert resized["resize"]["stage"] == "queued", resized
        assert ledger()["vcpus"] == held["vcpus"] + 1
        done = complete("hot-create-two")
        assert done["resize"]["observed"]["cpus"] == {"created": 2, "capacity": 16}
        assert cpu_quota(ref) == 2000
        assert online(ref) == b"0-1\n"
        assert resize("hot-create-two", ref, change="cpu_online", cpus=2) == done
        expect_error("E_IDEMPOTENCY_CONFLICT", lambda: resize("hot-create-two", ref, change="cpu_online", cpus=3))
        assert limit("cap-grown-vcpu", ref, 1500)["requested_millicpus"] == 1500
        resize("offline-with-explicit-cap", ref, change="cpu_offline", cpus=1)
        complete("offline-with-explicit-cap")
        assert cpu_quota(ref) == 1500 and ledger()["vcpus"] == held["vcpus"] + 1
        assert limit("reset-grown-vcpu-cap", ref, None)["requested_millicpus"] is None
        assert cpu_quota(ref) == 2000 and online(ref) == b"0\n"

        def memtotal():
            return int(execute(ref, "/bin/cat", "/proc/meminfo").splitlines()[0].split()[1])

        before = memtotal()
        resize("hot-add-RAM", ref, change="memory_grow", memory_mib=640)
        assert ledger()["memory_mib"] == held["memory_mib"] + 128
        done = complete("hot-add-RAM")
        recorded = done["resize"]["observed"]["ram"]
        after = memtotal()
        assert recorded["mapped"] == recorded["plugged"] == 128 << 20, recorded
        assert after - before >= 120 << 10, (before, after)
        assert binding(name) == ref and resize("hot-add-RAM", ref, change="memory_grow", memory_mib=640) == done
        print(json.dumps({"hot_compute": resources(ref)["observed"], "guest_memtotal_kib": [before, after],
                          "ledger": ledger(), "initial_cpu_operation": resized["phase"]}), flush=True)

        pressure_round(restored)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=lambda raw: Path(raw).resolve(), required=True)
    parser.add_argument("--system-image", type=lambda raw: Path(raw).resolve(), required=True)
    parser.add_argument("--guest", type=lambda raw: Path(raw).resolve(), help="optional prebuilt static fixture executable")
    parser.add_argument("--legacy-agent", action="store_true", help="verify a System image from before typed live resource methods")
    parser.add_argument("--pressure-balloon", choices=("bound", "unbound"),
                        help="measure pressure feedback and its actual effect on the configured memory budget")
    parser.add_argument("--work-dir", type=Path, default=Path("/var/tmp"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires Linux root, KVM and systemd")
    if os.environ.get("SMOLVM_RESIZE_TEST_NAMESPACE") != "1":
        os.execvp("unshare", ["unshare", "--mount", "--propagation", "private", "--net", "--",
                             "/usr/bin/env", "SMOLVM_RESIZE_TEST_NAMESPACE=1", sys.executable, __file__, *sys.argv[1:]])
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="smrz-") as directory, ExitStack() as stack:
        root = Path(directory)
        root.chmod(0o755)
        unit = f"smolvmresize{os.getpid()}_{os.urandom(4).hex()}.slice"
        group = create_slice(unit, stack)
        os.environ.update(SMOLVM_WORKER_SLICE_NAME=unit, SMOLVM_WORKER_VCPU_BUDGET="5")
        try:
            bundle = stack.enter_context(installed_bundle(args.bundle, root)) if args.pressure_balloon else args.bundle
            verify(bundle, root, args.guest, args.system_image, False, False, False, False,
                   stage_bundle=not args.pressure_balloon,
                   observer=lambda *result: exercise(*result, args.legacy_agent, group, args.pressure_balloon))
        except BaseException:
            for log in [root / "serve.log", root / "worker.log", *(root / "state/managed").glob("*.log")]:
                if log.exists():
                    print(log.name, log.read_text(errors="replace")[-4500:], file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
