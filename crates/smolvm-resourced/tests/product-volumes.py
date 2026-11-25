"""Run the product volume journal against real managed block objects and writer OFDs."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("generation", Path(__file__).with_name("kvm-generation.py"))
generation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generation)
rpc, require, until = generation.rpc, generation.require, generation.until

CAPACITY = 2 * 1024 * 1024
OWNER = "principal"
INSTANCE = "closed-machine"
FINISH = {"expected_revision": 1, "abort": False}


def worker(path):
    launch = generation.operation(INSTANCE, "launch")
    rpc(path, "RegisterExecution", {"launch_permit": input()}, **launch)
    print("registered", flush=True)
    require(input() == "write", "unexpected fixture command")
    writers = generation.operation(INSTANCE, "writer")
    grant, entries, fds = rpc(path, "AcquireWriterSet", {"grant_id": "fixture-grant", "expected_revision": 1},
                              reply_fds=True, **writers)
    require(grant["grant"]["state"] == "offered" and entries[0]["role"] == "block_writer", grant)
    rpc(path, "AckWriterSetAttached", {"grant_id": "fixture-grant", "expected_revision": 1}, **writers)
    require(os.pwrite(fds[0], b"persistent", 512) == 10, "short volume write")
    os.fsync(fds[0])
    print("written", flush=True)
    require(input() == "exit", "unexpected fixture command")
    for fd in fds:
        os.close(fd)


def run(broker):
    broker = Path(broker).resolve()
    with tempfile.TemporaryDirectory(prefix="product-volume-") as temporary:
        directory = Path(temporary)
        path, state = directory / "worker.sock", directory / "state"
        process = subprocess.Popen([broker, "serve", "--state-dir", state, "--socket", path])
        guest = None

        def call(method, args=None, **scope):
            return rpc(path, method, args, **scope)

        def mutate(volume, label, revision, action, **fields):
            return call("ApplyProductVolume", {"volume_id": volume, "owner_id": OWNER,
                        "expected_revision": revision, "command": {"action": action, **fields}},
                        **generation.operation(volume, label, 0))

        def query(volume):
            return call("QueryProductVolume", {"volume_id": volume, "owner_id": OWNER},
                        **generation.operation(volume, "query", 0))

        def rejects(code, action):
            try:
                action()
            except RuntimeError as error:
                require(code in str(error), code, error)
            else:
                raise RuntimeError("unexpected volume mutation success", code)

        try:
            until(path.exists, process, "Worker socket")
            digest = "sha256:" + hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            call("RegisterBundle", {"executable_sha256": digest}, bundle_digest=generation.BUNDLE)
            created = mutate("user-data", "create", 0, "create", capacity_bytes=CAPACITY, lifecycle="persistent")
            original = created["volume"]["head_resource_id"]
            require(mutate("user-data", "create", 0, "create", capacity_bytes=CAPACITY, lifecycle="persistent") == created,
                    "volume create replay changed")
            require(query("user-data")["capacity_bytes"] == CAPACITY)
            attached = mutate("user-data", "attach", 1, "attach", attachment_id="disk-attachment",
                              instance_id=INSTANCE, execution_epoch=0, device_key="data0", mode="rw", fork_policy="clone")
            require(attached["volume"]["attachments"][0]["state"] == "reserved", attached)
            rejects("E_VOLUME_BUSY", lambda: mutate("user-data", "second-attach", 2, "attach",
                attachment_id="other", instance_id="other-machine", execution_epoch=0,
                device_key="data0", mode="rw", fork_policy="clone"))
            rejects("E_STALE_REVISION", lambda: mutate("user-data", "stale", 1, "delete"))
            print("PRODUCT_VOLUME_EXCLUSIVE_OFFLINE_RESERVATION", flush=True)

            guest = subprocess.Popen([sys.executable, "-B", __file__, "writer", path], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True)
            call("BeginOperation", {"kind": "launch"}, **generation.operation(INSTANCE, "launch", 0))
            launch = generation.operation(INSTANCE, "launch")
            permit = call("IssueLaunchPermit", {"pid": guest.pid, "uid": os.getuid()}, **launch)
            guest.stdin.write(permit["launch_permit"] + "\n")
            guest.stdin.flush()
            require(guest.stdout.readline().strip() == "registered")
            call("FinishOperation", FINISH, **launch)
            writer = generation.operation(INSTANCE, "writer")
            call("BeginOperation", {"kind": "writer_reservation"}, **writer)
            call("ReserveWriterSet", {"heads": [{"volume_id": "user-data", "head_resource_id": original}]}, **writer)
            guest.stdin.write("write\n")
            guest.stdin.flush()
            require(guest.stdout.readline().strip() == "written")
            call("FinishOperation", FINISH, **writer)
            require(query("user-data")["attachments"][0]["state"] == "attached")
            rejects("E_VOLUME_BUSY", lambda: mutate("user-data", "live-snapshot", 2, "snapshot", snapshot_id="unsafe"))
            rejects("E_VOLUME_BUSY", lambda: mutate("user-data", "live-detach", 2, "detach",
                attachment_id="disk-attachment", execution_epoch=1, instance_id=INSTANCE))
            guest.stdin.write("exit\n")
            guest.stdin.flush()
            require(guest.wait(10) == 0, "fixture writer exited unexpectedly")
            call("FinalizeExecutionExit", **launch)
            require((state / f"objects/{original}/data").is_file(), "compute exit removed persistent volume")
            mutate("user-data", "detach", 2, "detach", attachment_id="disk-attachment", execution_epoch=1, instance_id=INSTANCE)
            print("PRODUCT_VOLUME_SURVIVES_CONFIRMED_COMPUTE_EXIT", flush=True)

            saved = mutate("user-data", "snapshot", 3, "snapshot", snapshot_id="disk-snapshot")
            require(saved["volume"]["snapshots"][0]["generation_id"] == original)
            require(saved["volume"]["head_resource_id"] != original)
            cloned = mutate("disk-clone", "create", 0, "create", capacity_bytes=CAPACITY, lifecycle="persistent",
                            source_snapshot_id="disk-snapshot")
            require(cloned["volume"]["generation_id"] == original)
            expanded = mutate("disk-clone", "grow", 1, "grow", capacity_bytes=CAPACITY * 2)
            require(expanded["block_capacity_applied"] and expanded["filesystem_resize_status"] == "not_requested", expanded)
            raw = state / "objects" / expanded["volume"]["head_resource_id"] / "data"
            with raw.open("rb") as fd:
                require(os.pread(fd.fileno(), 10, 512) == b"persistent", "grown clone changed disk content")
                require(os.pread(fd.fileno(), 512, CAPACITY) == bytes(512), "new capacity was not zeroed")
            closure = call("QueryOwnerClosure", {"owner_kind": "product_snapshot", "owner_id": "disk-snapshot"})
            require(closure["resources"] == [{"resource_id": original, "state": "available"}], closure)
            rejects("E_RESOURCE_PINNED", lambda: call("MarkResourceForGC", {"resource_id": original, "expected_revision": 2}))
            mutate("user-data", "delete", 4, "delete")
            require(query("user-data")["state"] == "deleted" and query("disk-clone")["capacity_bytes"] == CAPACITY * 2)
            print("PRODUCT_VOLUME_SNAPSHOT_CLONE_GROW_AND_CAPTURE_PIN", flush=True)
        finally:
            for item in (guest, process):
                if item is not None and item.poll() is None:
                    item.terminate()
                    item.wait(10)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "writer":
        worker(sys.argv[2])
    elif len(sys.argv) == 2:
        run(sys.argv[1])
    else:
        sys.exit(f"usage: {sys.argv[0]} RESOURCED")
