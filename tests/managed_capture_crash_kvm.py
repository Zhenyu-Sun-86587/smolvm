#!/usr/bin/env python3
"""Crash the real Worker or source VMM at a committed stage of a managed capture."""

import argparse
from contextlib import ExitStack, closing
import grp
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

from test_deep_managed_launch import EXT, digest, http, installed_bundle, rpc, settled, until, verify


STAGES = ("arming", "parking", "standby", "holding", "pivoting", "exporting", "source_return", "waking", "children")


def sample(db, op):
    row = db.execute("""SELECT b.stage, b.capture_id, b.checkpoint IS NOT NULL AS checkpoint,
            b.session, p.state AS writer_pivot, f.state AS ram_export
        FROM managed_fork_batches b LEFT JOIN writer_pivots p USING(operation_id)
        LEFT JOIN fd_transfers f ON f.resource_id=b.capture_id WHERE b.operation_id=?""", (op,)).fetchone()
    return dict(row) if row else {}


def worker_pid(path, binary):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.connect(str(path))
        pid, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert uid == 0 and os.path.samefile(f"/proc/{pid}/exe", binary)
    return pid


def kill_and_wait(fd):
    signal.pidfd_send_signal(fd, signal.SIGKILL)
    assert select.select([fd], [], [], 8)[0], "process did not exit"


def ticks(root, ref):
    path = root / "state/managed" / (ref["incarnation_id"] + ".log")
    if not path.exists():
        return []
    return [line.split() for line in path.read_text(errors="replace").splitlines(keepends=True)
            if line.endswith("\n") and line.startswith("PARKED_BLOCK_TICK ") and len(line.split()) >= 5]


def run_cut(args, bundle, endpoint, root, source, identity, stack):
    actor, stage = args.actor, args.stage
    worker = root / "ipc/worker.sock"
    binary = args.worker or bundle / "smolvm-resourced"
    op = f"crash-{actor}-{stage}"
    name = "capture-survivor"
    call = {"kind": "independent_fork", "operation_id": op, "request_digest": digest(op.encode()),
            "expected": source, "parameters": {"children": [name]}}
    old = rpc(worker, "Health")
    bundle_digest = http(endpoint, EXT + "/capabilities")["bundle_digest"]
    unrelated = {"operation_id": "unfinished-catalog", "request_digest": digest(b"unfinished-catalog"),
                 "route_id": "deep", "bundle_digest": bundle_digest,
                 "expected": {"instance_id": "unrelated-slot", "incarnation_id": None, "execution_epoch": 0}}
    if args.unrelated_intent:
        assert rpc(worker, "BeginOperation", {"kind": "catalog"}, **unrelated)["phase"] == "NEW"
    broker = worker_pid(worker, binary)
    broker_fd = os.pidfd_open(broker)
    vm_fd = os.pidfd_open(identity["pid"])
    stack.callback(os.close, broker_fd)
    stack.callback(os.close, vm_fd)
    start = Path(f"/proc/{identity['pid']}/stat").read_text().rsplit(")", 1)[1].split()[19]
    assert int(start) == identity["pid_start_time"]
    original = until(lambda: ticks(root, source))
    accepted = http(endpoint, EXT + "/operations", call)
    assert accepted["phase"] == "NEW"
    capture = accepted["fork"]["capture_id"]
    db_path = root / "catalog/catalog.sqlite"
    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        deadline = time.monotonic() + 40
        while (cut := sample(db, op)).get("stage") != stage:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"missed {stage}: {cut}")
            time.sleep(.003)
        # Hold the actor while checking its exact stage again. This also makes a
        # source death deterministic relative to the Worker's next transaction.
        signal.pidfd_send_signal(broker_fd, signal.SIGSTOP)
        try:
            until(lambda: Path(f"/proc/{broker}/status").read_text().split("State:", 1)[1].lstrip().startswith("T"), 5)
            cut = sample(db, op)
            assert cut["stage"] == stage and cut["capture_id"] == capture, cut
            print("Cut", json.dumps(cut, sort_keys=True), flush=True)
            kill_and_wait(broker_fd if actor == "worker" else vm_fd)
        finally:
            if not select.select([broker_fd], [], [], 0)[0]:
                signal.pidfd_send_signal(broker_fd, signal.SIGCONT)
        if actor == "worker":
            assert not select.select([vm_fd], [], [], 0)[0]
            replacement = args.restart_worker or binary
            with (root / "replacement.log").open("ab") as log:
                new = subprocess.Popen([replacement, "serve", "--socket", worker, "--state-dir", root / "catalog",
                                        "--socket-gid", str(grp.getgrnam("kvm").gr_gid)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            stack.callback(new.wait)
            stack.callback(new.kill)

            if args.unrelated_intent:
                def restored_ownership():
                    current = rpc(worker, "Health")
                    if current["broker_session_id"] == old["broker_session_id"]:
                        return None
                    row = db.execute("""SELECT e.phase,g.state FROM executions e JOIN writer_grants g USING(incarnation_id)
                        WHERE e.incarnation_id=? AND g.state!='released'""", (source["incarnation_id"],)).fetchone()
                    if row and tuple(row) == ("registered", "attached") and sample(db, op)["ram_export"] == "committed":
                        return current

                current = until(restored_ownership, 30)
                assert current["state"] == "recovering"
                rpc(worker, "CompleteRecovery", {"broker_session_id": current["broker_session_id"]},
                    expect_error="E_RECOVERING")
                rpc(worker, "FinishOperation", {"abort": True, "expected_revision": 1}, **unrelated)
                print("Independent unfinished catalog intent blocked admission after writer and RAM recovery.", flush=True)

            def recovered():
                try:
                    health = rpc(worker, "Health")
                except (OSError, RuntimeError, AssertionError):
                    return None
                return health if health["state"] == "ready" else None

            try:
                health = until(recovered, 65)
            except TimeoutError:
                print("Recovery stalled", rpc(worker, "Health"), sample(db, op),
                      [tuple(r) for r in db.execute("SELECT kind,phase FROM operations WHERE phase='NEW'")],
                      flush=True)
                raise
            assert health["broker_session_id"] != old["broker_session_id"]
            with replacement.open("rb") as file:
                assert health["executable_sha256"] == "sha256:" + hashlib.file_digest(file, "sha256").hexdigest()
            assert worker_pid(worker, replacement) == new.pid
            print("Reconciled Worker", old["executable_sha256"], health["executable_sha256"], flush=True)
        final = settled(endpoint, op, timeout=95)
        fork = final["fork"]
        assert fork["capture_id"] == capture and fork["source_released"], final
        assert http(endpoint, EXT + "/operations", call) == final
        assert db.execute("SELECT count(*) FROM managed_fork_batches WHERE operation_id=?", (op,)).fetchone()[0] == 1
        assert not db.execute("SELECT 1 FROM managed_budget_holds WHERE operation_id=? AND state='reserved'",
                              (op,)).fetchone()
        if actor == "source" and not cut["checkpoint"]:
            assert final["phase"] == "ABORTED" and fork["completed_count"] == 0, final
            assert "before the managed capture was committed" in fork["error"], fork
            assert http(endpoint, EXT + f"/machines/{name}/binding")["execution_epoch"] == 0
        else:
            assert final["phase"] == "COMPLETED" and fork["completed_count"] == 1, final
            child, = fork["children"]
            # The restored serial queue can still flush a source heartbeat
            # produced before capture. Require two new, named child heartbeats.
            def activated_output():
                rows = ticks(root, child)
                for index, row in enumerate(rows):
                    if row[3] == name:
                        return rows[index:] if len(rows) - index >= 2 else None
                    assert row[2:4] == original[-1][2:4], (row, original[-1])
            child_rows = until(activated_output, 25)
            first, later = child_rows[0], child_rows[-1]
            assert all(row[2] == original[-1][2] and row[3] == name for row in child_rows), child_rows
            assert int(later[1]) > int(first[1]) > int(original[-1][1])
            assert sample(db, op)["writer_pivot"] == "complete"
            if actor == "worker":
                active = http(endpoint, EXT + f"/instances/{source['instance_id']}/inventory")
                assert active["execution"] == identity and active["inventory"]["source_disposition"] == "RUNNING"
                until(lambda: int(ticks(root, source)[-1][1]) > int(first[1]))
        if actor == "source":
            assert http(endpoint, EXT + "/machines/test-managed/binding")["incarnation_id"] is None
            assert not db.execute("SELECT 1 FROM writer_grants WHERE incarnation_id=? AND state!='released'",
                                  (source["incarnation_id"],)).fetchone()
        print(json.dumps({"actor": actor, "cut": cut, "operation": op, "terminal": final["phase"],
                          "capture": capture, "children": fork["completed_count"], "guest_pid": original[-1][2],
                          "bundle": bundle_digest, "worker_sha256": old["executable_sha256"]},
                         sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument("--guest", type=lambda path: Path(path).resolve(strict=True),
                        help="prebuilt guest with the two-disk PARKED_BLOCK_TICK workload")
    parser.add_argument("--worker", type=lambda path: Path(path).resolve(strict=True),
                        help="run a development Worker alongside the installed VMM and Serve")
    parser.add_argument("--restart-worker", type=lambda path: Path(path).resolve(strict=True),
                        help="start this Worker after cutting the installed daemon")
    parser.add_argument("--work-dir", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--actor", choices=("source", "worker"), required=True)
    parser.add_argument("--stage", choices=STAGES, required=True)
    parser.add_argument("--unrelated-intent", action="store_true",
                        help="keep a separate unfinished operation during recovery of an exported capture")
    parser.add_argument("--local", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.unrelated_intent and (args.actor != "worker" or args.stage not in ("source_return", "waking")):
        parser.error("--unrelated-intent requires a Worker cut after the RAM export")
    if not args.local:
        subprocess.run(["unshare", "--mount", "--propagation", "private", "--net", "--", sys.executable, "-B",
                        __file__, *sys.argv[1:], "--local"], check=True)
        return
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="capture-crash-") as folder, ExitStack() as stack:
        root = Path(folder)
        root.chmod(0o755)
        bundle = stack.enter_context(installed_bundle(args.bundle, root))

        def observe(endpoint, root, source, inventory, _):
            run_cut(args, bundle, endpoint, root, source, inventory["execution"], stack)

        try:
            verify(bundle, root, args.guest, None, False, False, False, False,
                   observer=observe, stage_bundle=False, worker_binary=args.worker, check_launch_rejections=False)
        except BaseException:
            for log in ("worker.log", "replacement.log", "serve.log"):
                if (root / log).exists():
                    print(log, (root / log).read_text(errors="replace")[-3000:], file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
