#!/usr/bin/env python3
"""Check the Worker block ownership matrix with real processes and SCM_RIGHTS."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, suppress
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import tempfile
import time

FIXTURE = Path(__file__).resolve()
generation_spec = importlib.util.spec_from_file_location("generation", FIXTURE.with_name("kvm-generation.py"))
generation = importlib.util.module_from_spec(generation_spec)
generation_spec.loader.exec_module(generation)
rpc = generation.rpc
CAPACITY = 4096
# Linux 64-bit struct flock: type, whence, start, length, pid.
FLOCK = struct.Struct("@hhqqi4x")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fingerprint(path):
    with path.open("rb") as file:
        return "sha256:" + hashlib.file_digest(file, "sha256").hexdigest()


def fd_observation(fd):
    info = os.fstat(fd)
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE,
        "prefix": os.pread(fd, 32, 0).hex(),
    }


def peer_main(path):
    held = {}
    keepers = []
    for line in sys.stdin:
        command = json.loads(line)
        try:
            action = command["action"]
            name = command.get("resource")
            if action == "rpc":
                result = rpc(path, command["method"], command.get("payload"),
                             fds=[held[resource] for resource in command.get("send", [])],
                             reply_fds=command.get("receive", False), expect_error=command.get("error"),
                             **command["scope"])
                if command.get("receive") and not command.get("error"):
                    result, table, fds = result
                    assert len(table) == len(fds)
                    observed = {}
                    for entry, fd in zip(table, fds, strict=True):
                        resource = entry["resource_id"]
                        assert resource not in held
                        held[resource] = fd
                        observed[resource] = {**fd_observation(fd), "role": entry["role"]}
                    result = {"receipt": result, "descriptors": observed}
            elif action == "observe":
                result = fd_observation(held[name])
            elif action == "reopen":
                held[name] = os.open(command["path"], os.O_RDWR | os.O_CLOEXEC)
                result = fd_observation(held[name])
            elif action == "write":
                expected = bytes.fromhex(command["data"])
                assert os.pwrite(held[name], expected, 0) == len(expected)
                os.fsync(held[name])
                result = fd_observation(held[name])
            elif action == "readonly":
                try:
                    os.pwrite(held[name], b"x", 0)
                except OSError as error:
                    assert error.errno == errno.EBADF
                    result = error.errno
                else:
                    raise AssertionError("readonly descriptor accepted a write")
            elif action == "retain-ofd":
                keeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(90)"],
                                          pass_fds=(held[name],), stdin=subprocess.DEVNULL,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                keepers.append(keeper)
                result = {"pid": keeper.pid, "fd": held[name]}
            else:
                raise ValueError(action)
            print(json.dumps({"result": result}), flush=True)
        except Exception as error:
            print(json.dumps({"error": str(error)}), flush=True)


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def stop_keeper(pidfd):
    with suppress(ProcessLookupError):
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
    assert select.select([pidfd], [], [], 10)[0], "the test OFD keeper did not exit"


class Peer:
    def __init__(self, stack, socket, bundle, name):
        self.name, self.bundle = name, bundle
        self.process = subprocess.Popen(
            [sys.executable, "-B", FIXTURE, "--peer", socket],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        stack.callback(stop, self.process)

    def command(self, action, **fields):
        self.process.stdin.write(json.dumps({"action": action, **fields}) + "\n")
        self.process.stdin.flush()
        assert select.select([self.process.stdout], [], [], 15)[0], self.name
        result = json.loads(self.process.stdout.readline())
        assert "result" in result, (self.name, action, result)
        return result["result"]

    def call(self, scope, method, payload=None, *, receive=False, error=None, send=()):
        return self.command("rpc", scope=scope, method=method, payload=payload,
                            receive=receive, error=error, send=send)

    def scope(self, purpose, epoch=1):
        name = f"{self.name}-{purpose}"
        return {"operation_id": name, "bundle_digest": self.bundle, "route_id": "deep",
                "request_digest": digest(name.encode()),
                "expected": {"instance_id": self.name, "execution_epoch": epoch,
                             "incarnation_id": f"{self.name}-exec" if epoch else None}}


def ofd_lock(path, expected_conflict=False):
    with path.open("r+b") as file:
        try:
            fcntl.fcntl(file.fileno(), fcntl.F_OFD_SETLK, FLOCK.pack(fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0))
        except OSError as error:
            assert expected_conflict and error.errno in (errno.EAGAIN, errno.EACCES), error
            return error.errno
        assert not expected_conflict, (path, "independent OFD unexpectedly obtained the lock")
        return 0


def start_worker(stack, worker, socket, directory, log, expected_digest):
    process = subprocess.Popen([worker, "serve", "--socket", socket, "--state-dir", directory],
                               stdout=log, stderr=log)
    stack.callback(stop, process)
    for _ in range(100):
        assert process.poll() is None, process.returncode
        try:
            health = rpc(socket, "Health")
        except (OSError, ValueError):
            time.sleep(.02)
        else:
            assert health["executable_sha256"] == expected_digest
            assert Path(f"/proc/{process.pid}/exe").resolve(strict=True) == worker
            return process, health
    raise TimeoutError("Worker did not open its private socket")


def exercise(worker, root, worker_identity):
    socket = root / "worker.sock"
    state = root / "catalog"
    actual_executable = fingerprint(Path(sys.executable).resolve())
    bundles = {
        name: digest(json.dumps({"test_scope": name, "peer_executable_sha256": actual_executable},
                                sort_keys=True).encode())
        for name in ("a", "b")
    }
    results = {"case": "A10", "worker": worker_identity, "test_bundle_scopes": bundles,
               "measured_peer_executable": actual_executable}

    def call(method, payload=None, **scope):
        return rpc(socket, method, payload, **scope)

    def begin(scope, kind):
        assert call("BeginOperation", {"kind": kind}, **scope)["phase"] == "NEW"

    def finish(scope, abort=False):
        assert call("FinishOperation", {"abort": abort, "expected_revision": 1}, **scope)["phase"] == (
            "ABORTED" if abort else "COMPLETED")

    def launch(peer):
        begin(peer.scope("launch", 0), "launch")
        scope = peer.scope("launch")
        permit = call("IssueLaunchPermit", {"pid": peer.process.pid, "uid": os.getuid()}, **scope)
        registered = peer.call(scope, "RegisterExecution", {"launch_permit": permit["launch_permit"]})["execution"]
        assert (registered["pid"], registered["bundle_digest"], registered["execution_epoch"]) == (
            peer.process.pid, peer.bundle, 1)
        finish(scope)
        return {key: registered[key] for key in ("instance_id", "pid", "bundle_digest", "execution_epoch")}

    def writer_grant(peer, scope, grant, head):
        reserved = call("ReserveWriterSet", {"heads": [head]}, **scope)
        assert reserved["state"] == "reserved" and not reserved["writer_authority"]
        payload = {"grant_id": grant, "expected_revision": 1}
        received = peer.call(scope, "AcquireWriterSet", payload, receive=True)
        assert received["receipt"]["grant"]["state"] == "offered"
        data = received["descriptors"][head["head_resource_id"]]
        assert data["mode"] == os.O_RDWR and data["role"] == "block_writer", data
        assert peer.call(scope, "AckWriterSetAttached", payload)["state"] == "attached"
        finish(scope)
        return data

    def denied_read(peer, purpose, head):
        scope = peer.scope(purpose)
        begin(scope, "resource_lease")
        lease = {"lease_id": scope["operation_id"], "resource_id": head, "access": "ro"}
        refusal = peer.call(scope, "AcquireResourceLease", lease, receive=True, error="E_VOLUME_WRITER_CONFLICT")
        finish(scope, abort=True)
        return refusal

    with ExitStack() as stack:
        log = stack.enter_context((root / "worker.log").open("ab"))
        broker, initial = start_worker(stack, worker, socket, state, log, worker_identity["executable_sha256"])
        for bundle in bundles.values():
            call("RegisterBundle", {"executable_sha256": actual_executable}, bundle_digest=bundle)
        owner, contender, reader_a, reader_b = (
            Peer(stack, socket, bundles[route], name)
            for route, name in (("a", "writer-a"), ("b", "writer-b"), ("a", "reader-a"), ("b", "reader-b"))
        )
        peers = (owner, contender, reader_a, reader_b)
        results["executions"] = [launch(peer) for peer in peers]

        head = {"volume_id": "main-volume", "head_resource_id": "main-head"}
        free = {"volume_id": "first-free-volume", "head_resource_id": "free-head"}
        alias = {"volume_id": "last-alias-volume", "head_resource_id": "hardlink-head"}
        setup = owner.scope("catalog")
        begin(setup, "catalog")
        for volume in (head, free):
            call("CreateVolumeHead", {"volume_id": volume["volume_id"], "resource_id": volume["head_resource_id"],
                                      "capacity_bytes": CAPACITY}, **setup)
        main = state / "objects/main-head/data"
        unrelated = state / "objects/free-head/data"
        hardlink = state / "objects/hardlink-head/data"
        hardlink.parent.mkdir()
        os.link(main, hardlink)
        assert os.path.samefile(main, hardlink)
        call("RegisterVolumeHead", alias, **setup)
        symlink = state / "objects/symlink-head"
        symlink.symlink_to(main.parent, target_is_directory=True)
        results["symlink_registration"] = call(
            "RegisterVolumeHead", {"volume_id": "path-alias-volume", "head_resource_id": "symlink-head"},
            expect_error="E_HOST_IO", **setup)
        finish(setup)

        results["mutable_read_before_writer"] = denied_read(reader_b, "early-read", "main-head")
        first = owner.scope("writer")
        competing = contender.scope("writer")
        same_bundle = reader_a.scope("writer")
        for scope in (first, competing, same_bundle):
            begin(scope, "writer_reservation")
        with hardlink.open("r+b") as external:
            fcntl.fcntl(external.fileno(), fcntl.F_OFD_SETLK, FLOCK.pack(fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0))
            results["unregistered_alias_holder"] = call(
                "ReserveWriterSet", {"heads": [head]}, expect_error="E_VOLUME_WRITER_CONFLICT", **first)
        hardlink.unlink()
        original = writer_grant(owner, first, "g-a", head)
        marker_a = b"original-writer".ljust(32, b".").hex()
        results["original_writer"] = owner.command("write", resource="main-head", data=marker_a)
        assert results["original_writer"]["prefix"] == marker_a
        os.link(main, hardlink)
        results["same_inode_independent_ofd_errno"] = ofd_lock(hardlink, expected_conflict=True)
        with ThreadPoolExecutor(max_workers=2) as pool:
            attempts = {
                label: pool.submit(call, "ReserveWriterSet", {"heads": [head]},
                                   expect_error="E_VOLUME_WRITER_CONFLICT", **scope)
                for label, scope in (("same_bundle", same_bundle), ("different_bundle", competing))
            }
            results["simultaneous_writer_attempts"] = {label: pending.result() for label, pending in attempts.items()}
        finish(same_bundle, abort=True)
        results["mutable_read_during_writer"] = {
            "same_bundle": denied_read(reader_a, "live-read", "main-head"),
            "different_bundle": denied_read(reader_b, "live-read", "main-head"),
        }
        results["hardlink_group_conflict"] = call(
            "ReserveWriterSet", {"heads": [free, alias]}, expect_error="E_VOLUME_WRITER_CONFLICT", **competing)
        empty = call("QueryWriterSet", operation_id=competing["operation_id"])
        assert empty["state"] == "absent" and not empty["heads"] and ofd_lock(unrelated) == 0
        results["failed_group_left_unrelated_ofd_unlocked"] = True
        results["failed_group_writer_export"] = contender.call(
            competing, "AcquireWriterSet", {"grant_id": "unreserved", "expected_revision": 1},
            receive=True, error="E_NOT_FOUND")

        broker.kill()
        broker.wait(timeout=10)
        broker, restarted = start_worker(stack, worker, socket, state, log, worker_identity["executable_sha256"])
        assert restarted["state"] == "recovering" and restarted["broker_session_id"] != initial["broker_session_id"]
        unknown = call("QueryWriterSet", operation_id=first["operation_id"])
        assert unknown["state"] == "unknown" and not unknown["writer_authority"]
        session = {"broker_session_id": restarted["broker_session_id"]}
        blocked = call("ReserveWriterSet", {"heads": [head]}, expect_error="E_RECOVERING", **competing)
        finish(competing, abort=True)
        for peer in peers:
            reconciled = peer.call(peer.scope("launch"), "ReconcileExecution")
            assert reconciled["pid"] == peer.process.pid and reconciled["phase"] == "registered"
        barrier = call("CompleteRecovery", session, expect_error="E_RECOVERING")
        update = {"grant_id": "g-a", "expected_revision": unknown["revision"]}
        table = [{"index": 0, "resource_id": "main-head", "role": "block_writer"}]
        reexport = {**first, "fd_table": table}
        aliased = owner.call(reexport, "ReconcileWriterSet", update, send=["main-head"],
                             receive=True, error="E_BLOCK_BACKING_CHANGED")
        assert call("QueryWriterSet", operation_id=first["operation_id"])["state"] == "unknown"
        hardlink.unlink()
        reopened = owner.command("reopen", resource="independent-fd", path=str(main))
        assert (reopened["device"], reopened["inode"], reopened["mode"], reopened["prefix"]) == (
            original["device"], original["inode"], os.O_RDWR, marker_a)
        wrong_ofd = owner.call(reexport, "ReconcileWriterSet", update, send=["independent-fd"],
                               receive=True, error="E_FENCE_UNPROVEN")
        assert call("QueryWriterSet", operation_id=first["operation_id"])["state"] == "unknown"
        observed = owner.call(reexport, "ReconcileWriterSet", update, send=["main-head"])
        assert observed["state"] == "attached"
        assert call("CompleteRecovery", session)["state"] == "ready"
        results["restart"] = {"unknown_writer": unknown["state"], "other_bundle": blocked,
                              "barrier_after_process_reconcile": barrier,
                              "reexport_with_extra_link": aliased,
                              "reexport_independent_ofd": wrong_ofd,
                              "reexported_writer": observed["state"], "writer_pid": owner.process.pid,
                              "session_before": initial["broker_session_id"],
                              "session_after": restarted["broker_session_id"]}
        still = owner.command("observe", resource="main-head")
        assert (still["device"], still["inode"], still["prefix"]) == (original["device"], original["inode"], marker_a)
        competing = contender.scope("writer-after-recovery")
        begin(competing, "writer_reservation")
        call("ReserveWriterSet", {"heads": [head]}, expect_error="E_VOLUME_WRITER_CONFLICT", **competing)

        keeper = owner.command("retain-ofd", resource="main-head")
        keeper_fd = os.pidfd_open(keeper["pid"])
        stack.callback(os.close, keeper_fd)
        stack.callback(stop_keeper, keeper_fd)
        held = Path(f"/proc/{keeper['pid']}/fd/{keeper['fd']}").stat()
        assert (held.st_dev, held.st_ino) == (original["device"], original["inode"])
        stop(owner.process)
        blocked = call("FinalizeExecutionExit", expect_error="E_FENCE_UNPROVEN", **owner.scope("launch"))
        call("ReserveWriterSet", {"heads": [head]}, expect_error="E_VOLUME_WRITER_CONFLICT", **competing)
        assert ofd_lock(main, expected_conflict=True) in (errno.EAGAIN, errno.EACCES)
        stop_keeper(keeper_fd)
        fenced = call("FinalizeExecutionExit", **owner.scope("launch"))
        assert fenced["phase"] == "exited"
        takeover = writer_grant(contender, competing, "g-b", head)
        assert (takeover["device"], takeover["inode"], takeover["prefix"]) == (
            original["device"], original["inode"], marker_a)
        results["escaped_ofd"] = {"original_owner_exited": True, "fence_while_held": blocked,
                                 "verified_after_close": fenced["phase"], "same_inode_writer_after_fence": takeover}

        marker_b = b"next-authorized-writer".ljust(32, b".").hex()
        assert contender.command("write", resource="main-head", data=marker_b)["prefix"] == marker_b
        stop(contender.process)
        assert call("FinalizeExecutionExit", **contender.scope("launch"))["phase"] == "exited"
        seal = reader_a.scope("seal")
        begin(seal, "catalog")
        call("SealVolumeHeads", {"heads": [head]}, **seal)
        call("DropOwnerRef", {"owner_kind": "operation", "owner_id": seal["operation_id"],
                              "resource_id": "main-head", "expected_revision": 1}, **seal)
        finish(seal)
        assert call("QueryResource", {"resource_id": "main-head"})["immutable"]
        sealed_digest = fingerprint(main)

        def attach_read(peer):
            scope = peer.scope("sealed-reader")
            begin(scope, "resource_lease")
            lease = {"lease_id": scope["operation_id"], "resource_id": "main-head", "access": "ro"}
            offer = peer.call(scope, "AcquireResourceLease", lease, receive=True)
            file = offer["descriptors"]["main-head"]
            assert (file["device"], file["inode"], file["mode"], file["prefix"], file["role"]) == (
                original["device"], original["inode"], os.O_RDONLY, marker_b, "block_ancestor"), file
            receipt = peer.call(scope, "AckAttached", {"lease_id": lease["lease_id"], "expected_revision": 1})
            assert receipt["state"] == "attached"
            rejected_write = peer.command("readonly", resource="main-head")
            finish(scope)
            return {**file, "lease_id": lease["lease_id"], "pwrite_errno": rejected_write}

        with ThreadPoolExecutor(max_workers=2) as pool:
            reads = [pool.submit(attach_read, peer) for peer in (reader_a, reader_b)]
            results["concurrent_immutable_readers"] = [pending.result() for pending in reads]
        assert results["concurrent_immutable_readers"][0]["lease_id"] != results["concurrent_immutable_readers"][1]["lease_id"]
        writer_on_sealed = reader_b.scope("writer-on-sealed")
        begin(writer_on_sealed, "writer_reservation")
        results["writer_on_shared_sealed_generation"] = call(
            "ReserveWriterSet", {"heads": [head]}, expect_error="E_STALE_REVISION", **writer_on_sealed)
        finish(writer_on_sealed, abort=True)
        for peer in (reader_a, reader_b):
            assert peer.command("observe", resource="main-head")["prefix"] == marker_b
        assert fingerprint(main) == sealed_digest
        results["sealed_generation_sha256"] = sealed_digest
        print(json.dumps(results, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker", type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    binary = args.worker
    identity = {"executable": str(binary), "executable_sha256": fingerprint(binary)}
    manifest = binary.with_name("runtime-bundle.json")
    if manifest.is_file():
        installed = json.loads(manifest.read_text())
        entry, = [entry for entry in installed["artifacts"] if entry["path"] == binary.name]
        assert "sha256:" + entry["sha256"] == identity["executable_sha256"]
        identity["installed_bundle_digest"] = installed["bundle_digest"]
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="block-matrix-") as directory:
        root = Path(directory)
        try:
            exercise(binary, root, identity)
        except BaseException:
            if (root / "worker.log").is_file():
                print((root / "worker.log").read_text(errors="replace")[-4000:], file=sys.stderr)
            raise


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--peer":
        peer_main(Path(sys.argv[2]))
    else:
        main()
