"""Exercise WorkerResource/1 through the real Linux daemon and kernel sockets."""

import array
import fcntl
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


BINARY = Path(sys.argv.pop(1)).resolve()
PROTOCOL = "WorkerResource/1"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def rpc(path, request, fds=()):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(3)
        client.connect(str(path))
        message = json.dumps(request).encode() if isinstance(request, dict) else request
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
        client.sendmsg([message], ancillary)
        return json.loads(client.recv(65536))


def receive_lease(path, packet):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(3)
        client.connect(str(path))
        client.send(json.dumps(packet).encode())
        body, ancillary, flags, _ = client.recvmsg(
            65536, socket.CMSG_SPACE(array.array("i").itemsize * 64), socket.MSG_CMSG_CLOEXEC)
    fds = array.array("i")
    for _, _, contents in ancillary:
        fds.frombytes(contents)
    return json.loads(body), fds, flags


def request(method, payload=None, **scope):
    return {"protocol": PROTOCOL, "request_id": "test-request", "method": method, "payload": payload, **scope}


def fence(instance, epoch=0):
    return {"instance_id": instance, "incarnation_id": f"{instance}-exec" if epoch else None, "execution_epoch": epoch}


def operation(bundle, identifier, target):
    return {"bundle_digest": bundle, "route_id": "deep", "expected": target,
            "operation_id": identifier, "request_digest": digest(identifier.encode())}


class WorkerResource(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.path = self.root / "worker.sock"
        self.state = self.root / "state"
        self.bundle_a = digest(b"bundle-a")
        self.bundle_b = digest(b"bundle-b")
        self.start()
        binary = digest(Path(sys.executable).read_bytes())
        for bundle in (self.bundle_a, self.bundle_b):
            self.call("RegisterBundle", {"executable_sha256": binary}, bundle_digest=bundle)

    def start(self):
        self.process = subprocess.Popen(
            [BINARY, "serve", "--socket", self.path, "--state-dir", self.state],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop, self.process)
        for _ in range(100):
            if self.process.poll() is not None:
                self.fail(f"daemon exited with status {self.process.returncode}")
            try:
                rpc(self.path, request("Health"))
                return
            except (ConnectionError, FileNotFoundError):
                time.sleep(0.02)
        self.fail("daemon never listened")

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=5)

    def call(self, method, payload=None, *, error=None, **scope):
        response = rpc(self.path, request(method, payload, **scope))
        self.assertEqual(response["protocol"], PROTOCOL)
        if error:
            self.assertEqual(response.get("error", {}).get("code"), error, response)
            return
        self.assertIn("result", response, response)
        return response["result"]

    def process_peer(self):
        code = (
            "import json, socket, sys\n"
            "for line in sys.stdin:\n"
            "  with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:\n"
            "    client.connect(sys.argv[1])\n"
            "    client.send(line.encode())\n"
            "    print(client.recv(65536).decode(), flush=True)\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", code, self.path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        self.addCleanup(self.stop, process)
        return process

    def peer_call(self, process, method, data=None, **scope):
        process.stdin.write(json.dumps(request(method, data, **scope)) + "\n")
        process.stdin.flush()
        response = json.loads(process.stdout.readline())
        self.assertIn("result", response, response)
        return response["result"]

    def finish(self, scope, abort=False):
        return self.call("FinishOperation", {"abort": abort, "expected_revision": 1}, **scope)

    def launch(self, bundle, node):
        process = self.process_peer()
        launch = operation(bundle, f"launch-{node}", fence(node))
        self.call("BeginOperation", {"kind": "launch"}, **launch)
        launch["expected"] = fence(node, 1)
        permit = self.call("IssueLaunchPermit", {"pid": process.pid, "uid": os.getuid()}, **launch)
        token = {"launch_permit": permit["launch_permit"]}
        self.call("RegisterExecution", token, error="E_LAUNCH_PERMIT", **launch)
        result = self.peer_call(process, "RegisterExecution", token, **launch)
        self.assertEqual(result, self.peer_call(process, "RegisterExecution", token, **launch))
        self.assertEqual(result["execution"]["pid"], process.pid)
        self.assertEqual(result["network_state"], "closed")
        self.finish(launch)
        return process, launch

    def test_operation_replay_graph_and_gc(self):
        scope = operation(self.bundle_a, "catalog", fence("machine"))
        first = self.call("BeginOperation", {"kind": "catalog"}, **scope)
        self.assertEqual(first, self.call("BeginOperation", {"kind": "catalog"}, **scope))
        self.assertEqual(first, self.call("QueryOperation", operation_id="catalog", route_id="deep",
                                          bundle_digest=self.bundle_a))
        self.call("QueryOperation", operation_id="catalog", route_id="deep", bundle_digest=self.bundle_b,
                  error="E_NOT_FOUND")
        self.call("QueryOperation", operation_id="catalog", route_id="official", bundle_digest=self.bundle_a,
                  error="E_NOT_FOUND")
        conflict = {**scope, "request_digest": digest(b"other request")}
        self.call("BeginOperation", {"kind": "catalog"}, error="E_IDEMPOTENCY_CONFLICT", **conflict)
        self.call("BeginOperation", {"kind": "launch"}, error="E_IDEMPOTENCY_CONFLICT", **scope)

        for resource in ("root", "backing"):
            self.call("RegisterResource", {"resource_id": resource, "durability": "durable",
                                           "descriptor": {"name": resource}}, **scope)
        edge = {"owner_resource_id": "root", "child_resource_id": "backing", "role": "backing"}
        self.call("AddResourceEdge", edge, **scope)
        self.call("AddResourceEdge", {**edge, "owner_resource_id": "backing", "child_resource_id": "root"},
                  error="E_RESOURCE_CYCLE", **scope)
        owner = {"owner_kind": "checkpoint", "owner_id": "checkpoint-A"}
        root = {**owner, "resource_id": "root", "expected_revision": 0}
        self.call("AddOwnerRef", root, **scope)
        self.assertEqual([r["resource_id"] for r in self.call("QueryOwnerClosure", owner)["resources"]],
                         ["backing", "root"])
        self.finish(scope)
        for resource in ("root", "backing"):
            self.call("MarkResourceForGC", {"resource_id": resource, "expected_revision": 1},
                      error="E_RESOURCE_PINNED")

        drop = operation(self.bundle_a, "drop", fence("machine"))
        self.call("BeginOperation", {"kind": "catalog"}, **drop)
        dropped = self.call("DropOwnerRef", {**root, "expected_revision": 1}, **drop)
        self.assertEqual(dropped, self.call("DropOwnerRef", {**root, "expected_revision": 1}, **drop))
        self.finish(drop)
        for resource in ("root", "backing"):
            self.call("MarkResourceForGC", {"resource_id": resource, "expected_revision": 1})
            result = self.call("CollectResource", {"resource_id": resource, "expected_revision": 2})
            self.assertEqual(result["state"], "deleted")

    def test_alias_exclusion_and_recovery(self):
        process_a, launch_a = self.launch(self.bundle_a, "first")
        process_b, launch_b = self.launch(self.bundle_b, "second")
        self.call("FinalizeExecutionExit", error="E_FENCE_UNPROVEN", **launch_a)

        scope = operation(self.bundle_a, "volumes", fence("volumes"))
        self.call("BeginOperation", {"kind": "catalog"}, **scope)
        for head in ("head-a", "head-b", "unique"):
            (self.state / "objects" / head).mkdir()
        backing = self.state / "objects/head-a/data"
        backing.write_bytes(b"backing test")
        os.link(backing, self.state / "objects/head-b/data")
        (self.state / "objects/unique/data").write_bytes(b"second backing")
        heads = [{"volume_id": volume, "head_resource_id": head}
                 for volume, head in (("volume-a", "head-a"), ("volume-b", "head-b"), ("unique", "unique"))]
        for head in heads:
            self.call("RegisterVolumeHead", head, **scope)
        self.finish(scope)

        first = operation(self.bundle_a, "reserve-a", fence("first", 1))
        second = operation(self.bundle_b, "reserve-b", fence("second", 1))
        for scope in (first, second):
            self.call("BeginOperation", {"kind": "writer_reservation"}, **scope)
        pending = self.call("ReserveWriterSet", {"heads": [heads[0]]}, **first)
        self.assertEqual(pending["state"], "reserved")
        self.assertFalse(pending["writer_authority"])
        self.assertEqual(pending, self.call("ReserveWriterSet", {"heads": [heads[0]]}, **first))
        self.call("ReserveWriterSet", {"heads": [heads[0]]}, error="E_VOLUME_WRITER_CONFLICT", **second)
        self.call("ReserveWriterSet", {"heads": [heads[2], heads[1]]}, error="E_VOLUME_WRITER_CONFLICT", **second)
        self.assertEqual(self.call("QueryWriterSet", operation_id="reserve-b")["state"], "absent")
        self.call("AcquireWriterSet", {"heads": [heads[1]]}, error="E_CAPABILITY_UNSUPPORTED", **second)

        self.stop(self.process)
        self.start()
        health = self.call("Health")
        self.assertEqual(health["state"], "recovering")
        self.assertEqual(self.call("QueryWriterSet", operation_id="reserve-a")["state"], "unknown")
        self.call("ReserveWriterSet", {"heads": [heads[2]]}, error="E_RECOVERING", **second)
        self.call("MarkResourceForGC", {"resource_id": "absent", "expected_revision": 1}, error="E_RECOVERING")
        session = {"broker_session_id": health["broker_session_id"]}
        self.call("CompleteRecovery", session, error="E_RECOVERING")
        self.peer_call(process_a, "ReconcileExecution", **launch_a)
        self.peer_call(process_b, "ReconcileExecution", **launch_b)
        released = self.call("ReleaseWriterReservation", {"expected_revision": 1}, **first)
        self.assertEqual(released["state"], "released")
        self.assertEqual(released, self.call("ReserveWriterSet", {"heads": [heads[0]]}, **first))
        self.finish(first)
        self.finish(second, abort=True)
        self.assertEqual(self.call("CompleteRecovery", session)["state"], "ready")

        followup = operation(self.bundle_b, "reserve-after-recovery", fence("second", 1))
        self.call("BeginOperation", {"kind": "writer_reservation"}, **followup)
        self.assertEqual(self.call("ReserveWriterSet", {"heads": [heads[1], heads[2]]}, **followup)["state"], "reserved")
        self.call("ReleaseWriterReservation", {"expected_revision": 1}, **followup)
        self.finish(followup)
        self.stop(process_b)
        self.assertEqual(self.call("FinalizeExecutionExit", **launch_b)["phase"], "exited")

    def test_packet_bounds_protocol_and_descriptor_rejection(self):
        self.assertEqual(rpc(self.path, b"x" * 65537)["error"]["code"], "E_PACKET_TRUNCATED")
        wrong = {**request("Health"), "protocol": "WorkerResource/2"}
        self.assertEqual(rpc(self.path, wrong)["error"]["code"], "E_PROTOCOL_UNSUPPORTED")
        with open(self.root / "descriptor", "w") as file:
            self.assertEqual(rpc(self.path, request("Health"), [file.fileno()])["error"]["code"],
                             "E_CAPABILITY_UNSUPPORTED")
            self.assertEqual(rpc(self.path, request("Health"), [file.fileno()] * 65)["error"]["code"],
                             "E_PACKET_TRUNCATED")
        self.assertEqual(self.call("Health")["state"], "ready")

    def test_sealed_generation_and_readonly_lease(self):
        launch = operation(self.bundle_a, "launch-escrow", fence("escrow"))
        self.call("BeginOperation", {"kind": "launch"}, **launch)
        launch["expected"] = fence("escrow", 1)
        permit = self.call("IssueLaunchPermit", {"pid": os.getpid(), "uid": os.getuid()}, **launch)
        self.call("RegisterExecution", {"launch_permit": permit["launch_permit"]}, **launch)
        self.finish(launch)

        scope = operation(self.bundle_a, "generation-op", fence("escrow", 1))
        self.call("BeginOperation", {"kind": "generation"}, **scope)
        page = os.sysconf("SC_PAGE_SIZE")
        descriptor = {"backing_sizes": {"ram-a": page, "ram-b": page}, "regions": [{
            "gpa": 0, "length": page * 2,
            "extents": [{"offset": n * page, "length": page, "backing_id": f"ram-{name}", "backing_offset": 0}
                        for n, name in enumerate(("a", "b"))],
        }]}
        transfer = {"transfer_id": "transfer"}
        start = {**transfer, "resource_id": "generation", "descriptor": descriptor,
                 "descriptor_digest": digest(json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode())}
        self.call("RegisterGenerationBegin", start, **scope)
        self.call("RegisterGenerationCommit", transfer, error="E_INCOMPLETE_TRANSFER", **scope)
        self.call("QueryResource", {"resource_id": "generation"}, error="E_NOT_FOUND")

        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
        for batch, name in enumerate(("a", "b")):
            fd = os.memfd_create(f"ram-{name}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            backing = os.fdopen(fd, "wb")
            self.addCleanup(backing.close)
            os.ftruncate(fd, page)
            os.pwrite(fd, name.encode(), 0)
            packet = request("RegisterGenerationBatch", {**transfer, "batch_index": batch},
                             fd_table=[{"index": 0, "resource_id": f"ram-{name}", "role": "immutable_backing"}], **scope)
            self.assertEqual(rpc(self.path, packet, [fd])["error"]["code"], "E_INVALID_REQUEST")
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            receipt = rpc(self.path, packet, [fd])
            self.assertEqual(receipt["result"]["next_batch"], batch + 1, receipt)
            self.assertEqual(rpc(self.path, packet, [fd]), receipt)
            backing.close()

        self.assertEqual(self.call("RegisterGenerationCommit", transfer, **scope)["state"], "committed")
        self.assertEqual(self.call("QueryResource", {"resource_id": "generation"})["fd_state"], "committed")
        self.call("DropOwnerRef", {"owner_kind": "operation", "owner_id": "generation-op",
                                   "resource_id": "generation", "expected_revision": 1}, **scope)
        self.finish(scope)

        lease_scope = operation(self.bundle_a, "lease-op", fence("escrow", 1))
        self.call("BeginOperation", {"kind": "resource_lease"}, **lease_scope)
        lease = {"lease_id": "lease", "resource_id": "generation", "access": "ro"}
        self.call("AcquireResourceLease", {**lease, "access": "rw"}, error="E_CAPABILITY_UNSUPPORTED", **lease_scope)
        response, held, flags = receive_lease(self.path, request("AcquireResourceLease", lease, **lease_scope))
        holds = [os.fdopen(fd, "rb") for fd in held]
        for backing in holds:
            self.addCleanup(backing.close)
        self.assertEqual(response["result"]["total"], 2, response)
        self.assertEqual([entry["resource_id"] for entry in response["fd_table"]], ["ram-a", "ram-b"])
        self.assertEqual(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 0)
        for key, byte in zip(held, (b"a", b"b"), strict=True):
            self.assertEqual(os.pread(key, 1, 0), byte)
            self.assertEqual(fcntl.fcntl(key, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.assertEqual(fcntl.fcntl(key, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, fcntl.FD_CLOEXEC)
        self.assertEqual(self.call("AckAttached", {"lease_id": "lease", "expected_revision": 1},
                                   **lease_scope)["state"], "attached")
        self.finish(lease_scope)
        self.call("MarkResourceForGC", {"resource_id": "generation", "expected_revision": 1},
                  error="E_RESOURCE_PINNED")

        self.stop(self.process)
        self.start()
        self.assertEqual(self.call("QueryResource", {"resource_id": "generation"})["state"], "missing")
        self.call("ReconcileExecution", **launch)
        session = {"broker_session_id": self.call("Health")["broker_session_id"]}
        self.call("CompleteRecovery", session, error="E_RECOVERING")
        for backing in holds:
            backing.close()
        self.call("ReleaseResourceLease", {"lease_id": "lease", "expected_revision": 3}, **lease_scope)
        self.assertEqual(self.call("QueryResource", {"resource_id": "generation"})["state"], "lost")
        self.assertEqual(self.call("CompleteRecovery", session)["state"], "ready")


if __name__ == "__main__":
    unittest.main()
