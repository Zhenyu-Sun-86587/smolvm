"""Exercise WorkerResource/1 through the real Linux daemon and kernel sockets."""

import array
import errno
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

    def test_private_network_reservation_is_scoped_and_unpublished(self):
        for network_id in ("home", "alternate"):
            self.call("RegisterPrivateNetwork", {
                "network_id": network_id, "route_domain_id": f"router-{network_id}",
                "cidr": "10.20.0.0/30",
            })
        a = operation(self.bundle_a, "net-a", fence("a"))
        b = operation(self.bundle_a, "net-b", fence("b"))
        for scope in (a, b):
            self.call("BeginOperation", {"kind": "network_reservation"}, **scope)
        native = {"attachment_id": "a-net", "network_id": "home", "device_id": "net0", "mode": "native"}
        receipt = self.call("ReserveNetworkAttachment", native, **a)
        self.assertEqual(receipt["state"], "reserved")
        self.assertEqual(receipt["guest_ipv4"], "10.20.0.2")
        self.assertEqual(receipt, self.call("ReserveNetworkAttachment", native, **a))
        self.call("QueryNetworkReservation", {"attachment_id": "a-net"}, error="E_NOT_FOUND", **b)
        fixed = {"attachment_id": "b-net", "network_id": "home", "device_id": "net0",
                 "mode": "fixed_internal", "guest_ipv4": "192.168.4.2"}
        self.call("ReserveNetworkAttachment", fixed, error="E_RESOURCE_EXHAUSTED", **b)
        other = self.call("ReserveNetworkAttachment", {**fixed, "network_id": "alternate"}, **b)
        self.assertEqual(other["private_ipv4"], receipt["private_ipv4"])
        self.assertNotEqual(other["route_domain_id"], receipt["route_domain_id"])
        self.assertEqual(other["guest_ipv4"], "192.168.4.2")
        release = {"attachment_id": "a-net", "expected_revision": receipt["revision"]}
        released = self.call("ReleaseNetworkReservation", release, **a)
        self.assertEqual(released["state"], "released")
        self.assertEqual(released, self.call("ReleaseNetworkReservation", release, **a))

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
        with backing.open("r+b") as external:
            fcntl.lockf(external, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.call("ReserveWriterSet", {"heads": [heads[0]]}, error="E_VOLUME_WRITER_CONFLICT", **first)
            fcntl.lockf(external, fcntl.LOCK_UN)
        pending = self.call("ReserveWriterSet", {"heads": [heads[0]]}, **first)
        self.assertEqual(pending["state"], "reserved")
        self.assertFalse(pending["writer_authority"])
        with (self.state / "objects/head-b/data").open("r+b") as external:
            with self.assertRaises(OSError) as blocked:
                fcntl.lockf(external, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIn(blocked.exception.errno, (errno.EACCES, errno.EAGAIN))
        self.assertEqual(pending, self.call("ReserveWriterSet", {"heads": [heads[0]]}, **first))
        self.call("ReserveWriterSet", {"heads": [heads[0]]}, error="E_VOLUME_WRITER_CONFLICT", **second)
        self.call("ReserveWriterSet", {"heads": [heads[2], heads[1]]}, error="E_VOLUME_WRITER_CONFLICT", **second)
        self.assertEqual(self.call("QueryWriterSet", operation_id="reserve-b")["state"], "absent")
        self.call("AcquireWriterSet", {"grant_id": "unauthorized", "expected_revision": 1},
                  error="E_PERMISSION_DENIED", **second)

        self.stop(self.process)
        self.start()
        health = self.call("Health")
        self.assertEqual(health["state"], "recovering")
        self.assertEqual(self.call("QueryWriterSet", operation_id="reserve-a")["state"], "unknown")
        with backing.open("r+b") as external:
            fcntl.lockf(external, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
        update = {"lease_id": "lease", "expected_revision": 3}
        first, second = (request(
            "ReconcileExecutionExports", update,
            fd_table=[{"index": 0, "resource_id": f"ram-{name}", "role": "immutable_backing"}],
            **lease_scope,
        ) for name in ("a", "b"))
        self.assertEqual(rpc(self.path, first, [held[1]])["error"]["code"], "E_FENCE_UNPROVEN")
        self.assertEqual(rpc(self.path, first, [held[0]])["result"]["received"], 1)
        self.assertEqual(self.call("QueryResource", {"resource_id": "generation"})["state"], "missing")
        self.call("CompleteRecovery", session, error="E_RECOVERING")
        receipt = rpc(self.path, second, [held[1]])["result"]
        self.assertEqual(receipt["lease"]["state"], "attached")
        self.assertEqual(receipt["received"], 2)
        self.assertEqual(rpc(self.path, second, [held[1]])["result"], receipt)
        self.assertEqual(self.call("QueryResource", {"resource_id": "generation"})["state"], "available")
        self.assertEqual(self.call("CompleteRecovery", session)["state"], "ready")

        self.stop(self.process)
        self.start()
        self.call("ReconcileExecution", **launch)
        session = {"broker_session_id": self.call("Health")["broker_session_id"]}
        self.call("CompleteRecovery", session, error="E_RECOVERING")
        for backing in holds:
            backing.close()
        self.call("ReleaseResourceLease", {"lease_id": "lease", "expected_revision": 5}, **lease_scope)
        self.assertEqual(self.call("QueryResource", {"resource_id": "generation"})["state"], "lost")
        self.assertEqual(self.call("CompleteRecovery", session)["state"], "ready")

    def test_generation_publisher_recovers_while_operation_pin_is_held(self):
        launch = operation(self.bundle_a, "launch-publisher", fence("publisher"))
        self.call("BeginOperation", {"kind": "launch"}, **launch)
        launch["expected"] = fence("publisher", 1)
        permit = self.call("IssueLaunchPermit", {"pid": os.getpid(), "uid": os.getuid()}, **launch)
        self.call("RegisterExecution", {"launch_permit": permit["launch_permit"]}, **launch)
        self.finish(launch)
        scope = operation(self.bundle_a, "publisher-op", fence("publisher", 1))
        self.call("BeginOperation", {"kind": "generation"}, **scope)
        page = os.sysconf("SC_PAGE_SIZE")
        descriptor = {"backing_sizes": {"base": page}, "regions": [{
            "gpa": 0, "length": page,
            "extents": [{"offset": 0, "length": page, "backing_id": "base", "backing_offset": 0}],
        }]}
        transfer = {"transfer_id": "publisher-transfer"}
        resource = {"resource_id": "publisher-generation"}
        self.call("RegisterGenerationBegin", {**transfer, **resource, "descriptor": descriptor,
            "descriptor_digest": digest(json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode())}, **scope)
        table = [{"index": 0, "resource_id": "base", "role": "immutable_backing"}]
        fd = os.memfd_create("publisher-ram", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        with os.fdopen(fd, "wb"):
            os.ftruncate(fd, page)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
            batch = request("RegisterGenerationBatch", {**transfer, "batch_index": 0}, fd_table=table, **scope)
            self.assertEqual(rpc(self.path, batch, [fd])["result"]["next_batch"], 1)
            self.call("RegisterGenerationCommit", transfer, **scope)

            self.stop(self.process)
            self.start()
            self.assertEqual(self.call("QueryResource", resource)["state"], "missing")
            reconcile = request("ReconcileExecutionExports", transfer, fd_table=table, **scope)
            self.assertEqual(rpc(self.path, reconcile, [fd])["error"]["code"], "E_PERMISSION_DENIED")
            self.call("ReconcileExecution", **launch)
            receipt = rpc(self.path, reconcile, [fd])
            self.assertEqual(receipt["result"]["state"], "committed")
            self.assertEqual(rpc(self.path, reconcile, [fd]), receipt)
            self.assertEqual(self.call("QueryResource", resource)["state"], "available")

            self.stop(self.process)
            self.start()
            self.assertEqual(self.call("QueryResource", resource)["state"], "missing")
            self.call("ReconcileExecution", **launch)
            self.call("DropOwnerRef", {**resource, "owner_kind": "operation",
                      "owner_id": "publisher-op", "expected_revision": 1}, **scope)
            self.assertEqual(rpc(self.path, reconcile, [fd])["error"]["code"], "E_RESOURCE_UNAVAILABLE")
            self.assertEqual(self.call("QueryResource", resource)["state"], "lost")
            self.finish(scope)
            session = {"broker_session_id": self.call("Health")["broker_session_id"]}
            self.assertEqual(self.call("CompleteRecovery", session)["state"], "ready")

    def test_managed_block_read_lease_recovery_and_physical_gc(self):
        setup = operation(self.bundle_a, "prepare-blocks", fence("blocks"))
        self.call("BeginOperation", {"kind": "catalog"}, **setup)
        data = b"r" * 512
        imported = self.root / "raw-base"
        imported.write_bytes(data)
        payload = {"resource_id": "base", "capacity_bytes": len(data), "content_sha256": digest(data)}
        table = [{"index": 0, "resource_id": "base", "role": "block_import"}]
        with imported.open("rb") as source:
            wrong = request("ImportImmutableBlock", dict(payload, content_sha256=digest(b"wrong")),
                            fd_table=table, **setup)
            self.assertEqual(rpc(self.path, wrong, [source.fileno()])["error"]["code"], "E_CONTENT_MISMATCH")
            self.call("FinishOperation", {"abort": False, "expected_revision": 1},
                      error="E_OPERATION_HAS_EFFECTS", **setup)
            self.call("AbortBlockCreation", {"resource_id": "base"}, **setup)
            self.call("AbortBlockCreation", {"resource_id": "base"}, **setup)
            valid = request("ImportImmutableBlock", payload, fd_table=table, **setup)
            self.assertTrue(rpc(self.path, valid, [source.fileno()])["result"]["immutable"])
        self.call("CreateVolumeHead", {"resource_id": "raw-head", "volume_id": "vol", "capacity_bytes": len(data)}, **setup)
        self.finish(setup)
        imported.unlink()

        launch = operation(self.bundle_a, "launch-block-reader", fence("reader"))
        self.call("BeginOperation", {"kind": "launch"}, **launch)
        launch["expected"] = fence("reader", 1)
        permit = self.call("IssueLaunchPermit", {"pid": os.getpid(), "uid": os.getuid()}, **launch)
        self.call("RegisterExecution", {"launch_permit": permit["launch_permit"]}, **launch)
        self.finish(launch)
        scope = operation(self.bundle_a, "read-block", fence("reader", 1))
        self.call("BeginOperation", {"kind": "resource_lease"}, **scope)
        lease = {"lease_id": "read-base", "resource_id": "base", "access": "ro"}
        self.call("AcquireResourceLease", dict(lease, resource_id="raw-head"),
                  error="E_VOLUME_WRITER_CONFLICT", **scope)
        reply, fds, flags = receive_lease(self.path, request("AcquireResourceLease", lease, **scope))
        self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
        self.assertEqual(reply["fd_table"][0]["role"], "block_ancestor")
        with os.fdopen(fds[0], "rb") as held:
            self.assertEqual(os.pread(held.fileno(), len(data), 0), data)
            self.assertEqual(fcntl.fcntl(held.fileno(), fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.call("AckAttached", {"lease_id": "read-base", "expected_revision": 1}, **scope)
            self.finish(scope)
            self.call("MarkResourceForGC", {"resource_id": "base", "expected_revision": 1},
                      error="E_RESOURCE_PINNED")
            self.stop(self.process)
            self.start()
            self.call("ReconcileExecution", **launch)
            reconcile = request("ReconcileExecutionExports", {"lease_id": "read-base", "expected_revision": 3},
                                fd_table=reply["fd_table"], **scope)
            receipt = rpc(self.path, reconcile, [held.fileno()])["result"]
            self.assertEqual(receipt["lease"]["state"], "attached")
            self.assertEqual(os.pread(held.fileno(), len(data), 0), data)
        session = {"broker_session_id": self.call("Health")["broker_session_id"]}
        self.assertEqual(self.call("CompleteRecovery", session)["state"], "ready")
        self.call("ReleaseResourceLease", {"lease_id": "read-base", "expected_revision": 4}, **scope)
        self.call("MarkResourceForGC", {"resource_id": "base", "expected_revision": 1})
        collect = {"resource_id": "base", "expected_revision": 2}
        self.assertEqual(self.call("CollectResource", collect)["state"], "deleted")
        self.assertFalse((self.state / "objects/base").exists())
        self.assertEqual(self.call("CollectResource", collect)["state"], "deleted")


if __name__ == "__main__":
    unittest.main()
