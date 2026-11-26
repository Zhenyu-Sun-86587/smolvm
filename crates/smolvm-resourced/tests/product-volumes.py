"""Run the product volume journal against real managed block objects and writer OFDs."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
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
            rejects("E_VOLUME_REQUIRES_STOPPED", lambda: mutate("user-data", "live-grow", 2, "grow", capacity_bytes=2 * CAPACITY))
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

            name = "machine-volumes"
            instance = f"i-{'a' * 32}-{hashlib.sha256(name.encode()).hexdigest()}"
            machine = {"instance_id": instance, "execution_epoch": 0, "mode": "rw", "fork_policy": "clone"}
            lifetime = mutate("machine-data", "create", 0, "create", capacity_bytes=CAPACITY, lifecycle="machine")["volume"]
            require(lifetime["lifecycle"] == "machine" and "machine_instance_id" not in lifetime, lifetime)
            saved = mutate("machine-data", "snapshot", 1, "snapshot", snapshot_id="machine-disk-snapshot")["volume"]
            prior = saved["snapshots"][0]["generation_id"]
            current = saved["head_resource_id"]
            readonly = dict(execution_epoch=0, mode="ro", fork_policy="share_immutable", snapshot_id="machine-disk-snapshot")
            view = saved
            for consumer in ("reader-one", "reader-two"):
                view = mutate("machine-data", "attach-" + consumer, view["revision"], "attach", attachment_id=consumer,
                              instance_id=consumer, device_key="archive", **readonly)["volume"]
                require("machine_instance_id" not in view and all(a["generation_id"] == prior for a in view["attachments"]), view)
            owned = mutate("machine-data", "attach", view["revision"], "attach", attachment_id="machine-disk",
                           device_key="data", **machine)["volume"]
            require(owned["machine_instance_id"] == instance, owned)
            mutate("machine-data", "detach", owned["revision"], "detach",
                   attachment_id="machine-disk", instance_id=instance, execution_epoch=0)
            detached = query("machine-data")
            require(detached["machine_instance_id"] == instance, detached)
            require({item["attachment_id"] for item in detached["attachments"]} == {"reader-one", "reader-two"}, detached)
            legacy = mutate("old-ephemeral", "create", 0, "create", capacity_bytes=CAPACITY, lifecycle="ephemeral")["volume"]
            mutate("old-ephemeral", "attach", legacy["revision"], "attach",
                   attachment_id="legacy-disk", device_key="legacy", **machine)
            held_machine = mutate("machine-also-attached", "create", 0, "create",
                capacity_bytes=CAPACITY, lifecycle="machine")["volume"]
            mutate("machine-also-attached", "attach", held_machine["revision"], "attach",
                   attachment_id="second-owned-disk", device_key="next", **machine)
            # A long-lived machine can own more than one packet's worth of
            # detached volumes while using very few device slots.
            prior_heads = []
            for index in range(63):
                volume = f"retired-disk-{index}"
                attachment = f"owned-attachment-{index}"
                item = mutate(volume, "create", 0, "create", capacity_bytes=4096, lifecycle="machine")["volume"]
                attached = mutate(volume, "attach", item["revision"], "attach",
                                  attachment_id=attachment, device_key="spare", **machine)["volume"]
                mutate(volume, "detach", attached["revision"], "detach", attachment_id=attachment,
                       instance_id=instance, execution_epoch=0)
                prior_heads.append(item["head_resource_id"])
            retirement = generation.operation(instance, "retire", 0)
            accepted = call("RetireStoppedInstance", {"name": name}, **retirement)
            require(accepted["phase"] == "NEW", accepted)
            until(lambda: call("QueryOperation", **retirement)["phase"] == "COMPLETED",
                  process, "machine retirement")
            require(call("RetireStoppedInstance", {"name": name}, **retirement)["phase"] == "COMPLETED")
            retired = query("machine-data")
            require(retired["state"] == "deleted" and retired["revision"] == detached["revision"] + 1, retired)
            require(retired["attachments"] == detached["attachments"], retired)
            replacement = mutate("machine-data", "attach-after-head-retirement", retired["revision"], "attach",
                                  attachment_id="reader-three", instance_id="reader-three", device_key="archive", **readonly)["volume"]
            require(replacement["machine_instance_id"] == instance and replacement["state"] == "deleted", replacement)
            after = mutate("machine-data", "detach-after-head-retirement", replacement["revision"], "detach",
                           attachment_id="reader-one", instance_id="reader-one", execution_epoch=0)["volume"]
            require({item["attachment_id"] for item in after["attachments"]} == {"reader-two", "reader-three"}, after)
            require(query("machine-also-attached")["state"] == "deleted" and not query("machine-also-attached")["attachments"])
            for head in (current, held_machine["head_resource_id"], *prior_heads):
                until(lambda: not (state / "objects" / head).exists(), process, "retired machine data file")
                require(call("QueryResource", {"resource_id": head})["state"] == "deleted", head)
            require((state / "objects" / prior / "data").is_file(), "pinned immutable generation was collected")
            require(query("machine-data")["snapshots"] == saved["snapshots"], "retirement discarded a snapshot")
            survivor = query("old-ephemeral")
            require(survivor["lifecycle"] == "ephemeral" and survivor["state"] == "available"
                    and not survivor["attachments"] and "machine_instance_id" not in survivor, survivor)
            mutate("old-ephemeral", "move-to-another-machine", survivor["revision"], "attach",
                   attachment_id="legacy-moved", device_key="legacy",
                   **{**machine, "instance_id": "other-machine"})
            print("OWNED_MACHINE_VOLUMES_RETIRED_WITH_65_ATTACHED_AND_DETACHED_HEADS", flush=True)
            print("IMMUTABLE_MACHINE_VOLUME_READERS_RETAINED_AND_DETACHED_AFTER_OWNER_RETIRED", flush=True)
        finally:
            for item in (guest, process):
                if item is not None and item.poll() is None:
                    item.terminate()
                    item.wait(10)


def verify_upgrade(old_binary, new_binary):
    with tempfile.TemporaryDirectory(prefix="volume-upgrade-") as temporary:
        root = Path(temporary)
        socket, state = root / "worker.sock", root / "state"
        catalog = f"file:{state}/catalog.sqlite?mode=ro"
        name = "legacy-ephemeral-owner"
        instance = f"i-{'a' * 32}-{hashlib.sha256(name.encode()).hexdigest()}"
        volume = "legacy-ephemeral"
        lookup = dict(volume_id=volume, owner_id=OWNER)

        def call(method, payload=None, **scope):
            return rpc(socket, method, payload, **scope)

        def schema():
            with sqlite3.connect(catalog, uri=True) as database:
                return database.execute("PRAGMA user_version").fetchone()[0]

        def start(binary):
            return subprocess.Popen([Path(binary).resolve(strict=True), "serve", "--socket", socket, "--state-dir", state])

        def health(process):
            def listen():
                try:
                    return call("Health")
                except (FileNotFoundError, ConnectionRefusedError):
                    return None
            return until(listen, process, "Worker health")

        def observation():
            return call("QueryProductVolume", lookup, **generation.operation(volume, "query", 0))

        old = start(old_binary)
        try:
            first = health(old)
            require(schema() == 28, "fixture requires an actual schema 28 Worker")
            binary_digest = "sha256:" + hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            call("RegisterBundle", {"executable_sha256": binary_digest}, bundle_digest=generation.BUNDLE)
            for revision, label, command in (
                (0, "create", dict(action="create", capacity_bytes=CAPACITY, lifecycle="ephemeral")),
                (1, "attach", dict(action="attach", attachment_id="legacy-attachment", device_key="data",
                                   instance_id=instance, execution_epoch=0, mode="rw", fork_policy="clone")),
            ):
                call("ApplyProductVolume", {**lookup, "expected_revision": revision, "command": command},
                     **generation.operation(volume, label, 0))
            original = observation()
            original_data = state / "objects" / original["head_resource_id"] / "data"
            original_inode = original_data.stat().st_ino
        finally:
            old.terminate()
            old.wait(10)
        new = start(new_binary)
        try:
            second = health(new)
            require(schema() == 29 and second["state"] == "recovering")
            require(call("CompleteRecovery", {"broker_session_id": second["broker_session_id"]})["state"] == "ready")
            require(original == observation(), "upgrade changed the old volume or its existing attachment")
            retirement = generation.operation(instance, "retire", 0)
            call("RetireStoppedInstance", {"name": name}, **retirement)
            until(lambda: call("QueryOperation", **retirement)["phase"] == "COMPLETED", new, "legacy compute retirement")
            survivor = observation()
            require(survivor["lifecycle"] == "ephemeral" and survivor["state"] == "available"
                    and not survivor["attachments"] and "machine_instance_id" not in survivor, survivor)
            require(original_data.stat().st_ino == original_inode, "legacy data was replaced or removed")
            print(json.dumps({"case": "volume-schema-28-to-29", "before": first["executable_sha256"],
                              "after": second["executable_sha256"], "legacy_volume": survivor,
                              "original_inode": original_inode}, sort_keys=True), flush=True)
        finally:
            new.terminate()
            new.wait(10)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "writer":
        worker(sys.argv[2])
    elif len(sys.argv) == 2:
        run(sys.argv[1])
    elif len(sys.argv) == 4 and sys.argv[1] == "--upgrade":
        verify_upgrade(sys.argv[2], sys.argv[3])
    else:
        sys.exit(f"usage: {sys.argv[0]} RESOURCED | --upgrade OLD_SCHEMA_28_WORKER RESOURCED")
