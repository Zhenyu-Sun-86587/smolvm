#!/usr/bin/env python3
"""Exercise one Worker and two real Serve routes in an isolated systemd VM slice."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager, suppress
import grp
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

from test_deep_managed_launch import EXT, digest, http, installed_bundle, rpc, settled, until, verify
from test_deep_native_standby import worker_ready


MIB = 1 << 20


def create_slice(unit, stack):
    subprocess.run(["busctl", "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))",
                    unit, "fail", "2", "Description", "s", "SmolVM isolated acceptance slice",
                    "MemoryAccounting", "b", "true", "0"], check=True, stdout=subprocess.DEVNULL)
    stack.callback(subprocess.run, ["systemctl", "stop", unit], check=False)
    group = Path("/sys/fs/cgroup") / unit
    until(lambda: (group / "memory.current").exists(), 5)
    return group


def properties(unit, limit):
    subprocess.run(["systemctl", "set-property", "--runtime", unit, f"MemoryMax={limit}"], check=True)


def measured_variant(source, target):
    shutil.copytree(source, target, symlinks=True, copy_function=os.link)
    manifest = target / "runtime-bundle.json"
    raw = json.loads(manifest.read_text())
    raw.pop("bundle_digest")
    raw["contracts"]["state_reader_id"] += "-pressure-secondary"
    raw["bundle_digest"] = digest(json.dumps(raw, separators=(",", ":"), sort_keys=True).encode())
    manifest.unlink()
    manifest.write_text(json.dumps(raw))


def scope(endpoint, name):
    binding = http(endpoint, f"{EXT}/machines/{name}/binding")
    return {key: binding[key] for key in ("instance_id", "incarnation_id", "execution_epoch")}


def worker_command(bundle, root, worker):
    return [bundle / "smolvm-resourced", "serve", "--socket", worker, "--state-dir", root / "catalog",
            "--socket-gid", str(grp.getgrnam("kvm").gr_gid)]


def bundle_env(bundle, home):
    return {**os.environ, "HOME": str(home), "SMOLVM_LIB_DIR": str(bundle / "lib"),
            "LD_LIBRARY_PATH": str(bundle / "lib")}


def spawn(stack, command, env, log):
    output = stack.enter_context(log.open("ab"))
    process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=output)

    def stop():
        if process.poll() is None:
            process.kill()
        process.wait()

    stack.callback(stop)
    return process


def default_compatibility(current, historical, root):
    runtime = root / "compat-runtime"
    runtime.mkdir()
    Path("/run/smolvm-custom").mkdir(exist_ok=True)
    subprocess.run(["mount", "--bind", runtime, "/run/smolvm-custom"], check=True)
    try:
        for side, serve_bundle, worker_bundle in (("historical-serve", historical, current),
                                                   ("historical-worker", current, historical)):
            case = root / side
            (case / "ipc").mkdir(parents=True)
            (case / "home").mkdir()
            worker = case / "ipc/worker.sock"
            endpoint = case / "api/s.sock"
            with ExitStack() as stack:
                env = bundle_env(worker_bundle, case / "home")
                env.pop("SMOLVM_WORKER_SLICE_NAME", None)
                spawn(stack, worker_command(worker_bundle, case, worker), env, case / "worker.log")
                until(lambda: worker_ready(worker))
                health = rpc(worker, "Health")
                assert health.get("vm_slice") == ("smolvmdeep.slice" if side == "historical-serve" else None), health
                env = bundle_env(serve_bundle, case / "home")
                env.pop("SMOLVM_WORKER_SLICE_NAME", None)
                spawn(stack, [serve_bundle / "smolvm-bin", "--state-dir", case / "state", "serve", "start",
                              "--listen", f"unix://{endpoint}", "--worker-resource-socket", worker,
                              "--guest-rollout-port", "37228", "--shutdown-grace", "0"], env, case / "serve.log")
                until(lambda: http(endpoint, EXT + "/capabilities"))
                assert scope(endpoint, "default-slice-compatible")["execution_epoch"] == 0
    finally:
        subprocess.run(["umount", "/run/smolvm-custom"], check=True)
    print("A historical Serve reached the new default Worker, and the new Serve reached a historical Worker on the default slice.", flush=True)


def restart_worker(stack, root, worker):
    bundle = root / "bundle"
    old_session = rpc(worker, "Health")["broker_session_id"]
    pid = unix_peer(worker)
    with open_pidfd(pid) as pidfd:
        assert (Path(f"/proc/{pid}/exe")).samefile(bundle / "smolvm-resourced")
        assert os.fsencode(worker) in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        assert select.select([pidfd], [], [], 8)[0]
    spawn(stack, worker_command(bundle, root, worker), bundle_env(bundle, root / "home"), root / "worker.log")
    until(lambda: worker_ready(worker), 25)
    assert rpc(worker, "Health")["broker_session_id"] != old_session


def unix_peer(path, socktype=socket.SOCK_SEQPACKET):
    with socket.socket(socket.AF_UNIX, socktype) as peer:
        peer.connect(str(path))
        pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert uid == os.geteuid()
    return pid


def memfd_identities(pid):
    retained = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        with suppress(FileNotFoundError):
            if fd.readlink().as_posix().startswith("/memfd:"):
                metadata = fd.stat()
                retained.add((metadata.st_dev, metadata.st_ino))
    return retained


def guest_ticks(root, ref, state="state"):
    path = root / state / "managed" / (ref["incarnation_id"] + ".log")
    return [line.split() for line in path.read_text(errors="replace").splitlines()
            if line.startswith("PARKED_BLOCK_TICK ")]


def shmem_bytes(group):
    return int(dict(line.split() for line in (group / "memory.stat").read_text().splitlines())["shmem"])


def slice_bytes(group):
    return {"memory_current": int((group / "memory.current").read_text()), "shmem": shmem_bytes(group)}


@contextmanager
def open_pidfd(pid):
    fd = os.pidfd_open(pid)
    try:
        yield fd
    finally:
        os.close(fd)


def abandon_reply(worker, method, payload, **scope):
    request = dict(protocol="WorkerResource/1", method=method, request_id=method, payload=payload, **scope)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.connect(str(worker))
        peer.sendall(json.dumps(request).encode())


def artifact_digest(manifest, path):
    artifact = next(item for item in manifest["artifacts"] if item["path"] == path)
    return "sha256:" + artifact["sha256"].removeprefix("sha256:")


def serve_identity(endpoint, manifest):
    handshake = until(lambda: http(endpoint, EXT + "/capabilities"))
    assert handshake["bundle_digest"] == manifest["bundle_digest"], handshake
    assert handshake["state_reader_id"] == manifest["contracts"]["state_reader_id"], handshake
    pid = unix_peer(endpoint, socket.SOCK_STREAM)
    with Path(f"/proc/{pid}/exe").open("rb") as executable:
        measured = "sha256:" + hashlib.file_digest(executable, "sha256").hexdigest()
    assert measured == artifact_digest(manifest, "smolvm-bin")
    return {"serve_id": handshake["runtime_instance_id"], "bundle": handshake["bundle_digest"],
            "reader": handshake["state_reader_id"], "serve_sha256": measured}


def process_memory(pid):
    wanted = {"Rss", "Pss", "Private_Clean", "Private_Dirty", "Shared_Clean", "Shared_Dirty"}
    memory = {}
    for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
        name, _, value = line.partition(":")
        if name in wanted:
            count, unit = value.split()
            assert unit == "kB"
            memory[name] = int(count) * 1024
    assert memory.keys() == wanted and 0 < memory["Pss"] <= memory["Rss"], memory
    return memory


def pressure_proof(primary, root, first, inventory, _started, group, same_bundle, peer_bundle,
                   admission_worker_digest=None):
    worker = root / "ipc/worker.sock"
    unit = group.name
    manifest = json.loads((root / "bundle/runtime-bundle.json").read_text())
    primary_identity = serve_identity(primary, manifest)
    a = primary_identity["bundle"]
    if admission_worker_digest:
        secondary_bundle = peer_bundle
    elif peer_bundle:
        # The VMM runs as an unprivileged UID and must be able to traverse the Bundle path.
        secondary_bundle = root / "bundle-secondary"
        shutil.copytree(peer_bundle, secondary_bundle, symlinks=True)
    elif same_bundle:
        secondary_bundle = root / "bundle"
    else:
        secondary_bundle = root / "bundle-secondary"
        measured_variant(root / "bundle", secondary_bundle)
    secondary_manifest = json.loads((secondary_bundle / "runtime-bundle.json").read_text())
    b = secondary_manifest["bundle_digest"]
    assert (a == b) == same_bundle
    expected_worker = admission_worker_digest or artifact_digest(manifest, "smolvm-resourced")
    health = rpc(worker, "Health")
    assert health["vm_slice"] == unit
    if same_bundle or peer_bundle:
        assert health["executable_sha256"] == expected_worker
    tracked = tuple(
        key for key in ("memory.max", "memory.high", "cpu.max", "cpuset.cpus")
        if (group / key).exists()
    )
    original_limits = {key: (group / key).read_text() for key in tracked}
    secondary = root / "api-second/s.sock"
    base_command = [secondary_bundle / "smolvm-bin", "--state-dir", root / "state-second",
                    "serve", "start", "--listen", f"unix://{secondary}", "--worker-resource-socket", worker,
                    "--guest-rollout-port", "37228", "--shutdown-grace", "0"]
    env = bundle_env(secondary_bundle, root / "home")
    if not admission_worker_digest:
        mismatch = subprocess.run([root / "bundle/smolvm-bin", *base_command[1:]],
                                  env={**bundle_env(root / "bundle", root / "home"),
                                       "SMOLVM_WORKER_SLICE_NAME": "smolvmwrong.slice"},
                                  capture_output=True, timeout=30)
        assert mismatch.returncode != 0 and b"VM slice settings differ" in mismatch.stderr, mismatch.stderr

    with ExitStack() as stack:
        spawn(stack, base_command, env, root / "serve-second.log")
        secondary_identity = serve_identity(secondary, secondary_manifest)
        assert secondary_identity["bundle"] == b and primary_identity["serve_id"] != secondary_identity["serve_id"]
        if same_bundle:
            print(f"Both live Serve routes use verified Bundle {a}, Worker {expected_worker}.", flush=True)
        if peer_bundle:
            assert primary_identity["reader"] != secondary_identity["reader"]
            assert primary_identity["serve_sha256"] != secondary_identity["serve_sha256"]
            identities = ({"first_serve": primary_identity, "second_serve": secondary_identity} if admission_worker_digest
                          else {"current_serve": primary_identity, "historical_serve": secondary_identity})
            print(json.dumps({**identities, "worker_sha256": expected_worker, "slice": unit}), flush=True)
        assert {key: (group / key).read_text() for key in tracked} == original_limits
        assert all((group / path).exists() for path in ("memory.events", "memory.pressure", "io.pressure"))
        assert scope(secondary, "test-second")["execution_epoch"] == 0

        import_scope = dict(route_id="deep", bundle_digest=b, operation_id="second-import",
                            request_digest=digest(b"second-import"),
                            expected=dict(instance_id="second-import", incarnation_id=None, execution_epoch=0))
        scope_a = first
        rpc(worker, "BeginOperation", {"kind": "catalog"}, **import_scope)
        for name, path in (("second-root", root / "root.ext4"), ("second-data", root / "data.raw")):
            with path.open("rb") as data:
                sha = "sha256:" + hashlib.file_digest(data, "sha256").hexdigest()
                data.seek(0)
                rpc(worker, "ImportImmutableBlock", {"resource_id": name, "capacity_bytes": path.stat().st_size,
                    "content_sha256": sha}, fds=(data.fileno(),), fd_table=[dict(index=0, resource_id=name, role="block_import")],
                    **import_scope)
        rpc(worker, "FinishOperation", {"abort": False, "expected_revision": 1}, **import_scope)

        def launch(endpoint, name):
            disk_ids = ("base-ext4", "empty-data") if endpoint == primary else ("second-root", "second-data")
            disks = [dict(attachment_id=f"{name}-{role}", device_id=role, role=role,
                          generation_id=disk_ids[role != "root"], read_only=role == "root")
                     for role in ("root", "storage", "data")]
            parameters = dict(name=name, boot_profile="oci-v1", cpus=1, memory_mib=384, disks=disks, init="/counter", args=[])
            return submit(endpoint, "launch-" + name, scope(endpoint, name), "launch", parameters)

        def submit(endpoint, operation, ref, kind, parameters):
            return http(endpoint, EXT + "/operations", dict(operation_id=operation, request_digest=digest(operation.encode()),
                        expected=ref, kind=kind, parameters=parameters))

        def budget():
            return rpc(worker, "QueryWorkerBudget")

        current_before_second = int((group / "memory.current").read_text())
        assert launch(secondary, "test-second")["phase"] == "NEW"
        launched = settled(secondary, "launch-test-second")
        assert launched["phase"] == "COMPLETED", launched
        scope_b = scope(secondary, "test-second")
        second_inventory = http(secondary, f"{EXT}/instances/{scope_b['instance_id']}/inventory")
        pids = [record["execution"]["pid"] for record in (inventory, second_inventory)]
        for pid in pids:
            assert f"0::/{unit}/" in Path(f"/proc/{pid}/cgroup").read_text()
        if peer_bundle:
            print(json.dumps({"vm_scopes": {
                role: Path(f"/proc/{pid}/cgroup").read_text().strip()
                for role, pid in zip(("current", "historical"), pids, strict=True)}}), flush=True)
        current_with_both = int((group / "memory.current").read_text())
        assert current_with_both > current_before_second + 16 * MIB, (current_before_second, current_with_both)
        descriptors = [os.pidfd_open(pid) for pid in pids]
        for fd in descriptors:
            stack.callback(os.close, fd)
        assert budget()["allocated"]["vcpus"] == 3

        serial = 0

        def envelope(bundle, ref, key):
            return dict(expected=ref, route_id="deep", bundle_digest=bundle, operation_id=key,
                        request_digest=digest(key.encode()))

        def call(bundle, ref, method, payload, *, key=None):
            nonlocal serial
            serial += 1
            return rpc(worker, method, payload, **envelope(bundle, ref, key or f"pressure-{serial}"))

        def policy(bundle, ref, revision, priority, keep=False, grace=0, idle_after=600):
            return call(bundle, ref, "ApplyLifecyclePolicy", dict(expected_applied_revision=revision - 1,
                new_revision=revision, effective_policy=dict(auto_standby=idle_after >= 300,
                    auto_hibernate=True, hibernate_after_seconds=idle_after,
                    pressure_reclaim="idle_only", reclaim_priority=priority, keep_running=keep,
                    min_running_after_wake_seconds=grace)))

        def proof_session(ref):
            return "proof-" + ref["incarnation_id"]

        def facts(bundle, ref, busy=False):
            for collector, counts in [("guest", {"task": 0, "exec": 0, "inbound": 0, "outbound": int(busy)}), ("host", {"inbound": 0, "outbound": 0}),
                                      ("platform", {"task": 0, "exec": 0, "stream": 0})]:
                call(bundle, ref, "ReportActivity", dict(collector=collector, session=proof_session(ref),
                                                          seq=serial+1, valid_for_ms=15000, counts=counts))

        def status(bundle, ref):
            return call(bundle, ref, "GetLifecycleStatus", {})

        def wait_pressure(on):
            def state():
                value = status(a, scope_a)
                pressure = value["pressure"]
                return value if pressure is not None and pressure["admission_throttled"] == on else None
            return until(state, 20)

        def pressure_on():
            current = int((group / "memory.current").read_text())
            properties(unit, str(current + 140 * MIB))
            return wait_pressure(True)

        policy(a, scope_a, 1, 90, keep=True)
        policy(b, scope_b, 1, 0)
        facts(a, scope_a)
        facts(b, scope_b, busy=True)
        lease = call(b, scope_b, "AcquireRunningLease", dict(protection_id="protected-second", principal="pressure-test",
            semantics_version=2, ttl_seconds=120, token="pressure-test-lease-token-private"))
        original = budget()["allocated"]
        captures = {}
        for endpoint, ref, memory in ((primary, scope_a, 512), (secondary, scope_b, 384)):
            op = "storm-checkpoint-" + str(memory)
            capture = op + "-capture"
            assert submit(endpoint, op, ref, "vm_snapshot", {"capture_id": capture})["phase"] == "NEW"
            reserved = budget()["allocated"]
            assert reserved == {**original, "storage_bytes": original["storage_bytes"] + (memory + 68) * MIB}, reserved
            if endpoint == primary:
                try:
                    submit(secondary, "storm-checkpoint-384", scope_b, "vm_snapshot",
                           {"capture_id": "storm-checkpoint-384-capture"})
                except RuntimeError as error:
                    assert "E_RESOURCE_LIMIT" in str(error) and "unreserved" in str(error), error
                else:
                    raise AssertionError("overlapping exports admitted more than the global storage budget")
                assert budget()["allocated"] == reserved
            terminal = settled(endpoint, op)
            assert terminal["phase"] == "COMPLETED" and terminal["statepoint"]["phase"] == "durable", terminal
            captures[endpoint] = terminal["statepoint"]
            assert budget()["allocated"] == original
        aborted = submit(primary, "aborted-checkpoint", scope_a, "vm_snapshot", {"capture_id": "aborted-checkpoint-capture"})
        assert budget()["allocated"]["storage_bytes"] == original["storage_bytes"] + 580 * MIB
        http(primary, EXT + "/operations/aborted-checkpoint/cancel",
             dict(request_digest=digest(b"aborted-checkpoint"), expected=scope_a, expected_revision=aborted["revision"]))
        assert settled(primary, "aborted-checkpoint")["phase"] == "ABORTED"
        assert budget()["allocated"] == original
        print("NEW exports counted storage once across both Serve routes. A competing export was refused, and both commit and abort returned their reservation.", flush=True)

        if peer_bundle and not admission_worker_digest:
            for receiving, origin, role in ((primary, secondary, "current"), (secondary, primary, "historical")):
                point = captures[origin]
                target = scope(receiving, "wrong-reader")
                assert target["execution_epoch"] == 0 and target["incarnation_id"] is None
                try:
                    submit(receiving, f"wrong-reader-{role}", target, "vm_restore",
                           {"name": "wrong-reader", "capture_id": point["capture_id"], "mode": "clone_conflicts"})
                except RuntimeError as error:
                    assert "E_BUNDLE_UNAVAILABLE" in str(error) and "original StatePoint reader" in str(error), error
                else:
                    raise AssertionError("a StatePoint was read by the other installed Bundle")
                assert scope(receiving, "wrong-reader") == target
                assert budget()["allocated"] == original
                assert rpc(worker, "QueryResource", {"resource_id": point["representation_id"]})["state"] == "available"
                print(f"{role} Serve returned E_BUNDLE_UNAVAILABLE for {point['manifest_digest']}. "
                      "The retained root and stopped target were unchanged.", flush=True)

        facts(a, scope_a)
        facts(b, scope_b, busy=True)
        proof = pressure_on()
        sample = proof["pressure"]["sample"]
        assert sample["slice_name"] == unit and sample["slice_current"] and sample["slice_max"]
        assert sample["slice_memory_psi"] is not None and sample["slice_io_psi"] is not None
        assert sample["disk_available"] == budget()["capacity"]["storage_bytes"] - original["storage_bytes"]
        end = time.monotonic() + 8
        while time.monotonic() < end:
            facts(a, scope_a)
            facts(b, scope_b, busy=True)
            assert status(a, scope_a)["power"] == status(b, scope_b)["power"] == "RUNNING"
            time.sleep(0.5)
        assert not select.select(descriptors, [], [], 0)[0]
        assert status(a, scope_a)["last_decision"] is None and status(b, scope_b)["last_decision"] is None
        before = budget()["allocated"]

        def attempt(item):
            endpoint, ref, kind, index = item
            name = f"throttled-{kind}-{index}"
            try:
                if kind == "launch":
                    launch(endpoint, name)
                elif kind == "fork":
                    submit(endpoint, name, ref, "fork_batch", {"children": [name + "-a", name + "-b"]})
                else:
                    submit(endpoint, name, scope(endpoint, name), "vm_restore",
                           {"name": name, "capture_id": captures[endpoint]["capture_id"], "mode": "clone_conflicts"})
            except RuntimeError as error:
                assert "E_RESOURCE_LIMIT" in str(error), error
                return
            raise AssertionError(f"pressure admitted {kind} while all candidates were protected")

        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(attempt, [(endpoint, ref, kind, i)
                                   for i, (endpoint, ref) in enumerate(((primary, scope_a), (secondary, scope_b)))
                                   for kind in ("launch", "fork", "restore")]))
        assert budget()["allocated"] == before
        print(f"Two Serve routes shared the {unit} ledger under pressure. Six launch, fork and restore requests were refused, and both protected VMs remained live.", flush=True)
        if admission_worker_digest:
            assert not select.select(descriptors, [], [], 0)[0]
            memory = {bundle: {"pid": pid, "bytes": process_memory(pid)} for bundle, pid in zip((a, b), pids)}
            print(json.dumps({"memory_by_bundle": memory, "worker_budget": before, "slice_bytes": slice_bytes(group),
                              "registered_source_pids": pids, "launch_order": [a, b]}), flush=True)
            return

        call(b, scope_b, "ReleaseRunningLease", dict(protection_id="protected-second", principal="pressure-test",
            expected_revision=lease["revision"], token="pressure-test-lease-token-private"))
        facts(b, scope_b)

        def queued_candidate():
            candidate = status(b, scope_b)["last_decision"]
            if candidate and candidate["stage"] == "queued":
                return candidate

        queued = until(queued_candidate, 15)
        protected = call(b, scope_b, "AcquireActivityHold", dict(protection_id="racing-access", principal="pressure-test",
                                                                 reason="inbound access"))
        after_access = status(b, scope_b)
        assert after_access["last_decision"]["operation_id"] == queued["operation_id"]
        assert after_access["last_decision"]["stage"] == "cancelled" and after_access["next_action"] is None
        assert after_access["power"] == "RUNNING"
        call(b, scope_b, "ReleaseActivityHold", dict(protection_id="racing-access", principal="pressure-test",
                                                    expected_revision=protected["revision"]))
        queued = until(queued_candidate, 15)
        assert policy(b, scope_b, 2, 0, keep=True)["applied_revision"] == 2
        kept = status(b, scope_b)
        assert kept["last_decision"]["operation_id"] == queued["operation_id"]
        assert kept["last_decision"]["stage"] == "cancelled" and kept["next_action"] is None
        assert kept["power"] == "RUNNING" and "keep_running" in kept["blockers"]
        print("Both a scoped Access hold and an applied keep-running policy cancelled queued pressure before dispatch.", flush=True)

        properties(unit, "infinity")
        wait_pressure(False)

        policy(b, scope_b, 3, 0)
        policy(a, scope_a, 2, 90)
        facts(a, scope_a)
        facts(b, scope_b)
        pressure_on()

        def reclaim():
            live_b = scope(secondary, "test-second")
            facts(a, scope_a)
            if live_b["incarnation_id"] is not None:
                facts(b, live_b)
            left = status(a, scope_a)
            right = status(b, live_b)
            assert left["last_decision"] is None, (left, right)
            decision = right["last_decision"]
            return decision if (right["power"] == "HIBERNATED" and decision and decision["stage"] == "completed") else None

        decision = until(reclaim, 90)
        assert decision["origin"] == "pressure" and select.select(descriptors, [], [], 0)[0] == [descriptors[1]]
        assert decision["start_worker_memory_bytes"] > decision["end_worker_memory_bytes"]
        print(json.dumps({"slice": unit, "pressure_sample": sample, "priority_reclaim": decision,
                          "resident_growth_bytes": current_with_both - current_before_second,
                          "measured_bytes": decision["start_worker_memory_bytes"] - decision["end_worker_memory_bytes"]}), flush=True)
        properties(unit, "infinity")
        wait_pressure(False)

        policy(a, scope_a, 3, 90, keep=True)
        parked = scope(secondary, "test-second")
        policy(b, parked, 4, 0, grace=20, idle_after=1)
        principal = "pressure-test"
        hold = call(a, scope_a, "AcquireActivityHold", dict(protection_id="open-pty", principal=principal, reason="PTY"))
        report = dict(collector="guest", session=proof_session(scope_a), seq=serial+1, valid_for_ms=15000,
                      counts={"task": 0, "exec": 0, "inbound": 0, "outbound": 0})
        received = call(a, scope_a, "ReportActivity", report, key="report-before-crash")
        wake = dict(protection_id="wake-with-lost-reply", principal=principal, trigger="api_access",
                    expected_binding_revision=status(b, parked)["binding_revision"], authorization_revision=1,
                    endpoint_revision=1)
        abandon_reply(worker, "RequestWake", wake, **envelope(b, parked, "lost-wake-request"))
        waiting = call(b, parked, "QueryProtection", dict(protection_id=wake["protection_id"], principal=principal))
        assert waiting["state"] == "pending"
        other_wake = {**wake, "protection_id": "independent-wake"}
        call(b, parked, "RequestWake", other_wake)
        restart_worker(stack, root, worker)
        if same_bundle or peer_bundle:
            assert rpc(worker, "Health")["executable_sha256"] == expected_worker
            print(f"The replacement Worker is the same installed executable {expected_worker}.", flush=True)
        assert not select.select([descriptors[0]], [], [], 0)[0]
        assert http(primary, f"{EXT}/instances/{scope_a['instance_id']}/inventory")["execution"] == inventory["execution"]
        left = status(a, scope_a)
        assert left["applied_revision"] == 3 and "unknown:guest" in left["blockers"] and left["next_action"] is None, left
        restored_hold = call(a, scope_a, "QueryProtection", dict(protection_id=hold["protection_id"], principal=principal))
        assert restored_hold["state"] == "suspect" and restored_hold["revision"] == hold["revision"] + 1
        assert call(a, scope_a, "ReportActivity", report, key="report-before-crash") == received
        try:
            call(a, scope_a, "ReportActivity", report)
        except RuntimeError as error:
            assert "E_STALE_REVISION" in str(error), error
        else:
            raise AssertionError("a stale collector sample was treated as proof after restart")
        assert "unknown:guest" in status(a, scope_a)["blockers"]
        receipt = call(b, parked, "RequestWake", wake, key="lost-wake-request")
        assert receipt["protection_id"] == waiting["protection_id"] and receipt["revision"] == 1

        def restored_execution():
            ref = scope(secondary, "test-second")
            view = status(b, ref)
            if ref["incarnation_id"] and view["power"] == "RUNNING" and (view["last_decision"] or {}).get("stage") == "completed":
                return ref, view

        resumed, view = until(restored_execution, 100)
        assert resumed["execution_epoch"] == scope_b["execution_epoch"] + 1, resumed
        for authorized, item in ((True, wake), (False, other_wake)):
            demand = call(b, resumed, "QueryProtection", dict(protection_id=item["protection_id"], principal=principal))
            assert demand["wake_operation"] == view["last_decision"]["operation_id"]
            authorized_hold = call(b, resumed, "AuthorizeWakeActivation", dict(protection_id=item["protection_id"], principal=principal,
                wake_operation=demand["wake_operation"], authorized=authorized, expected_revision=demand["revision"],
                authorization_revision=2, endpoint_revision=1))
            if authorized:
                assert authorized_hold["state"] == "active" and authorized_hold["incarnation_id"] == resumed["incarnation_id"]
                call(b, resumed, "ReleaseActivityHold", dict(protection_id=item["protection_id"], principal=principal,
                                                            expected_revision=authorized_hold["revision"]))
            else:
                assert authorized_hold["state"] == "released"
        try:
            call(b, scope_b, "RenewRunningLease", dict(protection_id=lease["protection_id"], principal=principal,
                expected_revision=lease["revision"], ttl_seconds=120, token="pressure-test-lease-token-private"))
        except RuntimeError as error:
            assert "E_STALE_EXECUTION" in str(error), error
        else:
            raise AssertionError("a lease renewal from the prior execution was accepted")
        print("After an actual Worker SIGKILL and restart, the existing VMM and policy survived, the old PTY hold became suspect, stale activity remained unknown, and a wake with a lost reply coalesced into one exact restore.", flush=True)

        facts(b, resumed)
        next_action = status(b, resumed)["next_action"]
        assert next_action and next_action["origin"] == "idle" and next_action["kind"] == "hibernate", next_action
        assert 8_000 < next_action["eligible_after_ms"] <= 20_000, next_action
        pressure_on()
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            facts(b, resumed)
            actual = status(b, resumed)
            assert actual["power"] == "RUNNING" and actual["last_decision"]["operation_id"] == view["last_decision"]["operation_id"], actual
            time.sleep(0.4)

        def grace_reclaim():
            live = scope(secondary, "test-second")
            if live["incarnation_id"] is not None:
                facts(b, live)
            final = status(b, live)
            decision = final["last_decision"]
            if final["power"] == "HIBERNATED" and decision["stage"] == "completed" and decision["kind"] == "hibernate":
                return decision

        assert until(grace_reclaim, 100)["origin"] == "pressure"
        print("Under sustained cgroup pressure the restored VM stayed live for its configured wake grace, then hibernated after the timer elapsed.", flush=True)
        properties(unit, "infinity")
        wait_pressure(False)

        parent_lease = call(a, scope_a, "AcquireRunningLease", dict(protection_id="parent-only-lease", principal=principal,
            semantics_version=2, ttl_seconds=180, token="pressure-test-parent-lease-token"))
        children = ["shared-first", "shared-last"]
        submitted = submit(primary, "pressure-shared-fork", scope_a, "fork_batch", {"children": children})
        finished = settled(primary, "pressure-shared-fork")
        assert finished["phase"] == "COMPLETED" and all(ch["phase"] == "COMPLETED" for ch in finished["fork"]["children"]), finished
        resource = submitted["fork"]["capture_id"]
        child_refs = [scope(primary, name) for name in children]
        child_inventories = [http(primary, f"{EXT}/instances/{ref['instance_id']}/inventory") for ref in child_refs]
        child_pids = [record["execution"]["pid"] for record in child_inventories]
        child_fds = [stack.enter_context(open_pidfd(pid)) for pid in child_pids]
        manager = unix_peer(worker)
        shared = memfd_identities(child_pids[0]) & memfd_identities(child_pids[1]) & memfd_identities(manager)
        assert shared, "the two sibling VMMs did not retain a common Worker RAM backing"
        # The platform normally publishes the child's inherited policy to the Worker.
        inherited = status(a, scope_a)["effective_policy"]
        call(a, child_refs[0], "ApplyLifecyclePolicy",
             dict(expected_applied_revision=0, new_revision=1, effective_policy=inherited))
        try:
            call(a, child_refs[0], "RenewRunningLease", dict(protection_id=parent_lease["protection_id"], principal=principal,
                expected_revision=parent_lease["revision"], ttl_seconds=180, token="pressure-test-parent-lease-token"))
        except RuntimeError as error:
            assert "E_NOT_FOUND" in str(error), error
        else:
            raise AssertionError("a fork child renewed a lease that belonged to the parent execution")
        initial = slice_bytes(group)

        def hibernate_child(index):
            key = "hibernate-" + children[index]
            submit(primary, key, child_refs[index], "hibernate", {"capture_id": key + "-capture"})
            result = settled(primary, key)
            assert result["phase"] == "COMPLETED" and result["statepoint"]["phase"] == "hibernated", result
            assert select.select([child_fds[index]], [], [], 5)[0]

        start_ticks = len(until(lambda: guest_ticks(root, child_refs[1]), 15))
        hibernate_child(0)
        assert not select.select([child_fds[1]], [], [], 0)[0]
        assert shared <= memfd_identities(child_pids[1]) & memfd_identities(manager)
        assert rpc(worker, "QueryResource", {"resource_id": resource})["state"] == "available"
        assert len(until(lambda: guest_ticks(root, child_refs[1]), 10)) > start_ticks
        remaining = slice_bytes(group)
        hibernate_child(1)
        until(lambda: (rpc(worker, "QueryResource", {"resource_id": resource})["state"] == "deleted"
                       and not (shared & memfd_identities(manager))), 10)
        assert not select.select([descriptors[0]], [], [], 0)[0]
        after_siblings = slice_bytes(group)
        retained_by_parent = shared & memfd_identities(pids[0])
        print(json.dumps({"shared_worker_memfd_inodes": sorted(inode for _, inode in shared),
                          "retained_by_running_parent": sorted(inode for _, inode in retained_by_parent),
                          "before_either_sibling_exit": initial, "one_sibling_remaining": remaining,
                          "after_worker_closed_last_sibling_reference": after_siblings}), flush=True)
        call(a, scope_a, "ReleaseActivityHold", dict(protection_id=restored_hold["protection_id"], principal=principal,
                                                    expected_revision=restored_hold["revision"]))
        submit(primary, "hibernate-last-parent", scope_a, "hibernate", {"capture_id": "last-parent-capture"})
        parent_closed = settled(primary, "hibernate-last-parent")
        assert parent_closed["phase"] == "COMPLETED" and select.select([descriptors[0]], [], [], 5)[0], parent_closed
        final = until(lambda: current if (current := slice_bytes(group))["memory_current"] <
                                         after_siblings["memory_current"] else None, 10)
        print(json.dumps({"after_last_parent_exit": final,
                          "actual_reclaimed_bytes": initial["memory_current"] - final["memory_current"]}), flush=True)

        if peer_bundle:
            point = captures[secondary]
            name = "original-reader"
            key = "restore-original-reader"
            target = scope(secondary, name)
            assert submit(secondary, key, target, "vm_restore",
                          {"name": name, "capture_id": point["capture_id"], "mode": "clone_conflicts"})["phase"] == "NEW"
            receipt = settled(secondary, key)
            assert receipt["phase"] == "COMPLETED" and receipt["statepoint"]["stage"] == "released", receipt
            assert receipt["statepoint"]["manifest_digest"] == point["manifest_digest"], receipt
            assert receipt["statepoint"]["activation_decision"] == "commit", receipt
            restored = scope(secondary, name)
            assert restored["execution_epoch"] == 1 and restored["incarnation_id"], restored
            ticks = until(lambda: ticks if len(ticks := guest_ticks(root, restored, "state-second")) >= 2 else None, 20)
            source_ticks = guest_ticks(root, scope_b, "state-second")
            first, fresh = ticks[:2]
            original_tick = next((row for row in source_ticks if row[1] == first[1]), None)
            assert original_tick, (first, source_ticks[-2:])
            assert int(first[1]) > 1 and first[2] == fresh[2] == original_tick[2], (first, fresh, original_tick)
            assert first[5:7] == original_tick[5:7] and fresh[3] == name, (first, fresh, original_tick)
            print(f"The original installed reader restored {point['manifest_digest']} after the shared Worker restart. "
                  f"Guest PID {first[2]} continued at tick {first[1]} with both original disk markers {first[5:7]}.", flush=True)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument("--guest", type=lambda s: Path(s).resolve(), help="prebuilt static kvm-parked-block-guest executable")
    parser.add_argument("--historical-bundle", type=lambda s: Path(s).resolve(),
                        help="bundle whose Worker predates the vm_slice capability")
    parser.add_argument("--admission-only", action="store_true",
                        help="measure two authorized routes, their protected VMs and bounded concurrent admission")
    parser.add_argument("--reverse", action="store_true",
                        help="start the peer Serve first, keeping the same installed Worker")
    parser.add_argument("--work-dir", type=Path, default=Path("/var/tmp"))
    layout = parser.add_mutually_exclusive_group()
    layout.add_argument("--same-bundle", action="store_true",
                        help="use the supplied measured Bundle unchanged on both Serve routes")
    layout.add_argument("--peer-bundle", type=lambda s: Path(s).resolve(strict=True),
                        help="use an older installed Bundle unchanged from a nested systemd manager")
    args = parser.parse_args()
    if args.admission_only and not args.peer_bundle:
        parser.error("--admission-only requires two installed bundles")
    if args.reverse and not args.admission_only:
        parser.error("--reverse requires --admission-only")
    if os.geteuid() != 0:
        parser.error("Linux root, KVM, systemd, and cgroup v2 are required")
    if args.peer_bundle:
        manager = Path("/proc/1/environ").read_bytes().split(b"\0")
        if b"container=smolvm-frozen-proof" not in manager:
            parser.error("an installed peer requires the isolated manager from run_frozen_worker_pressure_in_systemd.sh")
    if os.environ.get("SMOLVM_PRESSURE_TEST_NAMESPACE") != "1":
        os.execvp("unshare", ["unshare", "--mount", "--propagation", "private", "--net", "--",
                             "/usr/bin/env", "SMOLVM_PRESSURE_TEST_NAMESPACE=1", "PYTHONDONTWRITEBYTECODE=1",
                             sys.executable, __file__, *sys.argv[1:]])
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="smp-") as directory, ExitStack() as stack:
        root = Path(directory)
        root.chmod(0o755)
        if args.historical_bundle:
            default_compatibility(args.bundle, args.historical_bundle, root)
        unit = ("smolvmdeep.slice" if args.peer_bundle else
                f"smolvmproof{os.getpid()}_{os.urandom(4).hex()}.slice")
        group = create_slice(unit, stack)
        os.environ.update(SMOLVM_WORKER_SLICE_NAME=unit, SMOLVM_WORKER_PRESSURE_HIGH_HEADROOM_MIB="192",
                          SMOLVM_WORKER_PRESSURE_LOW_HEADROOM_MIB="224", SMOLVM_WORKER_CACHE_RECLAIM_MIB="4",
                          SMOLVM_WORKER_STORAGE_BUDGET_BYTES=str(768 * MIB))
        properties(unit, str(3 << 30))
        try:
            if args.admission_only:
                first, second = (args.peer_bundle, args.bundle) if args.reverse else (args.bundle, args.peer_bundle)
                first = stack.enter_context(installed_bundle(first, root, "bundle"))
                second = stack.enter_context(installed_bundle(second, root, "bundle-secondary"))
                manifest = json.loads((args.bundle / "runtime-bundle.json").read_text())
                worker_digest = artifact_digest(manifest, "smolvm-resourced")
                verify(first, root, args.guest, None, False, False, False, False, stage_bundle=False,
                       worker_binary=args.bundle / "smolvm-resourced",
                       observer=lambda *values: pressure_proof(*values, group, False, second, worker_digest))
                return
            verify(args.bundle, root, args.guest, None, False, False, False, False,
                   observer=lambda *values: pressure_proof(*values, group, args.same_bundle, args.peer_bundle))
        except BaseException:
            logs = [root / log for log in ("serve.log", "serve-second.log", "worker.log")]
            for state in ("state", "state-second"):
                logs.extend((root / state / "managed").glob("*.log"))
            for path in logs:
                if path.exists():
                    print(path.relative_to(root), file=sys.stderr)
                    print(path.read_text(errors="replace")[-4500:], file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
