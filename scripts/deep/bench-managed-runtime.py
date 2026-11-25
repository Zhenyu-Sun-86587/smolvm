#!/usr/bin/env python3
"""Measure isolated managed KVM launches and capture/restore with real Guest I/O."""

import argparse
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from test_deep_managed_launch import EXT, digest, http, until, verify


def scope(binding):
    return {field: binding[field] for field in ("instance_id", "incarnation_id", "execution_epoch")}


def elapsed(start):
    return (time.monotonic_ns() - start) / 1_000_000


class GuestLog:
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.lines = []

    def read(self):
        if self.path.is_file():
            with self.path.open(encoding="utf-8", errors="replace") as log:
                log.seek(self.offset)
                while line := log.readline():
                    if not line.endswith("\n"):
                        break
                    self.lines.append(line.split())
                    self.offset = log.tell()
        return self.lines

    def ticks(self):
        return [(int(line[1]), int(line[2]), line[3], int(line[4])) for line in self.read()
                if len(line) == 5 and line[0] == "PARKED_BLOCK_TICK"]

    def first_tick(self, hostname):
        # A restored serial queue can still contain a heartbeat from the source.
        return next((tick for tick in self.ticks() if tick[2] == hostname), None)

    def first_task(self, hostname):
        for part in self.read():
            if len(part) == 4 and part[:2] == ["BENCH_TASK", hostname]:
                return {"runtime_ms": int(part[2]) / 1_000_000, "read_bytes": int(part[3])}
        return None


def process_metrics(pid):
    fields = {}
    for name in ("status", "smaps_rollup", "io"):
        path = Path(f"/proc/{pid}/{name}")
        for line in path.read_text().splitlines():
            key, _, value = line.partition(":")
            if key in ("Threads", "VmHWM", "Pss", "read_bytes", "write_bytes"):
                fields[key] = int(value.split()[0])
    return fields


class Bench:
    def __init__(self, endpoint, root, source, inventory):
        self.endpoint = endpoint
        self.catalog = root / "catalog/catalog.sqlite"
        self.logs = root / "state/managed"
        self.source = source
        self.source_pid = inventory["execution"]["pid"]
        self.sequence = 0
        self.rows = []

    def request(self, path, body=None):
        return http(self.endpoint, EXT + path, body)

    def boot_logs(self, ref):
        return GuestLog(self.logs / (ref["incarnation_id"] + ".log"))

    def operation(self, kind, expected, parameters):
        self.sequence += 1
        key = f"bench-{kind}-{self.sequence}"
        start = time.monotonic_ns()
        receipt = self.request("/operations", {
            "kind": kind, "operation_id": key, "request_digest": digest(key.encode()),
            "expected": scope(expected), "parameters": parameters,
        })
        if receipt["phase"] != "NEW":
            raise RuntimeError(receipt)
        return key, start, elapsed(start)

    def settled(self, key, start, progress, poll=None):
        marks = {}
        latest = None

        def finished():
            nonlocal latest
            latest = self.request("/operations/" + key)
            state = latest.get(progress) or {}
            if poll:
                poll(latest, state)
            if state.get("stage"):
                stage = "stage_" + state["stage"]
                if stage not in marks:
                    marks[stage] = elapsed(start)
            for milestone in ("source_released", "activation_decision", "manifest_digest"):
                if state.get(milestone) and milestone not in marks:
                    marks[milestone] = elapsed(start)
            if latest["phase"] == "ABORTED":
                raise RuntimeError(latest)
            return latest if latest["phase"] == "COMPLETED" else None

        try:
            return until(finished, 150), marks
        except TimeoutError as error:
            raise RuntimeError(f"Worker operation timed out: {latest}") from error

    def receipt(self, name):
        return self.request(f"/machines/{name}/execution")

    def guest(self, name, start):
        ref = self.receipt(name)
        log = self.boot_logs(ref)
        task = until(lambda: log.first_task(name), 25)
        inventory = self.request(f"/instances/{ref['instance_id']}/inventory")
        blocks = [d["block"]["managed_attachment"] for d in inventory["inventory"]["devices"] if d.get("block")]
        if len(blocks) != 3 or sum(bool(b["writable_head_id"]) for b in blocks) != 2:
            raise RuntimeError("Guest did not open its complete Worker disk set")
        task.update({
            "observed_ms": elapsed(start),
            "process": process_metrics(inventory["execution"]["pid"]),
            "writable_heads": sorted(b["writable_head_id"] for b in blocks if b["writable_head_id"]),
        })
        return ref, task

    def fence(self, name):
        ref = self.receipt(name)
        inventory = self.request(f"/instances/{ref['instance_id']}/inventory")
        vm = inventory["execution"]
        handle = os.pidfd_open(vm["pid"])
        try:
            stat = Path(f"/proc/{vm['pid']}/stat").read_text().rsplit(")", 1)[1].split()
            if int(stat[19]) != vm["pid_start_time"]:
                raise RuntimeError("Guest exit proof changed")
            signal.pidfd_send_signal(handle, signal.SIGKILL)
        finally:
            os.close(handle)

        def stopped():
            binding = self.request(f"/machines/{name}/binding")
            return binding["incarnation_id"] is None and binding["execution_epoch"] == ref["execution_epoch"]
        until(stopped, 25)

    def fork(self, scenario, source, names):
        """Record the source heartbeat gap and target work from one held cut."""
        log = self.boot_logs(source)
        tail = log.ticks()
        if len(tail) < 2:
            until(lambda: len(log.ticks()) >= 2)
            tail = log.ticks()
        before = len(tail)
        kind = "independent_fork" if len(names) == 1 else "fork_batch"
        key, start, accepted = self.operation(kind, source, {"children": names})
        child_logs, work_ready = {}, {}

        def identify_work(_, progress):
            for child in progress.get("children", []):
                name = child["name"]
                incarnation = child["incarnation_id"]
                if incarnation and name not in work_ready:
                    if name not in child_logs:
                        child_logs[name] = GuestLog(self.logs / (incarnation + ".log"))
                    if child_logs[name].first_task(name):
                        work_ready[name] = elapsed(start)

        receipt, timings = self.settled(key, start, "fork", identify_work)
        ready = elapsed(start)
        progress = receipt["fork"]
        if progress["outcome"] != "applied" or not progress["source_released"]:
            raise RuntimeError(receipt)
        with closing(sqlite3.connect(self.catalog)) as store:
            encoded = store.execute(
                "SELECT descriptor_json FROM fd_transfers WHERE resource_id=?", (progress["capture_id"],)
            ).fetchone()
        resource = {} if encoded is None else json.loads(encoded[0])
        ref, tasks = [], []
        used = set()
        cut = None
        for name in names:
            guest, task = self.guest(name, start)
            child_log = self.boot_logs(guest)
            child_tick, child_pid, _, _ = until(lambda: child_log.first_tick(name), 25)
            if child_pid != tail[-1][1] or child_tick <= tail[-1][0]:
                raise RuntimeError("fork target did not continue its source process and disks")
            if cut is not None and cut != child_tick:
                raise RuntimeError("fork siblings resumed different capture cuts")
            cut = child_tick
            if used.intersection(task["writable_heads"]):
                raise RuntimeError("fork targets shared a writable disk head")
            used.update(task["writable_heads"])
            task["observed_ms"] = work_ready.get(name, task["observed_ms"])
            ref.append(guest)
            tasks.append(task)
        until(lambda: len(log.ticks()) >= before + 2)
        timestamps = [tick[3] for tick in log.ticks()[before - 1:]]
        heartbeat = max((later - earlier) / 1_000_000 for earlier, later in zip(timestamps, timestamps[1:]))
        self.rows.append({
            "scenario": scenario, "op_id": key, "capture_id": progress["capture_id"], "fanout": len(names),
            "api_ms": accepted, "ready_ms": ready, "source_heartbeat_gap_ms": heartbeat,
            "source_release_ms": timings["source_released"], "tasks": tasks,
            "milestones_ms": timings,
            "targets_per_sec": len(names) / (ready / 1000),
            "target_pss_kib": sum(task["process"]["Pss"] for task in tasks),
            "target_threads": sum(task["process"]["Threads"] for task in tasks),
            "ram_files": len(resource.get("backing_sizes", {})),
            "logical_backing_bytes": sum(resource.get("backing_sizes", {}).values()),
            "ram_extents": sum(len(region["extents"]) for region in resource.get("regions", [])),
        })
        return ref

    def durable(self):
        key, start, accepted = self.operation("vm_snapshot", self.source, {})
        receipt, timings = self.settled(key, start, "statepoint")
        point = receipt["statepoint"]
        if point["phase"] != "durable" or not point["source_released"]:
            raise RuntimeError(receipt)
        self.rows.append({
            "scenario": "checkpoint", "op_id": key, "capture_id": point["capture_id"],
            "api_ms": accepted, "ready_ms": elapsed(start), "milestones_ms": timings,
        })
        restored = None
        for group in ("first_read", "repeat_read"):
            name = f"bench-{group.replace('_', '-')}"
            expected = self.request(f"/machines/{name}/binding")
            key, start, accepted = self.operation("vm_restore", expected, {
                "name": name, "capture_id": point["capture_id"], "mode": "clone_conflicts",
            })
            receipt, timings = self.settled(key, start, "statepoint")
            ready = elapsed(start)
            if receipt["statepoint"]["activation_decision"] != "commit":
                raise RuntimeError(receipt)
            guest, task = self.guest(name, start)
            child_log = self.boot_logs(guest)
            child_tick, child_pid, _, _ = until(lambda: child_log.first_tick(name), 25)
            identity = (child_tick, child_pid)
            if restored is not None and identity != restored:
                raise RuntimeError("durable targets resumed different capture cuts")
            restored = identity
            self.rows.append({"scenario": f"durable_{group}", "op_id": key, "tasks": [task],
                              "api_ms": accepted, "ready_ms": ready, "milestones_ms": timings})
            self.fence(name)


def local_case(args):
    with tempfile.TemporaryDirectory(prefix="smbench-", dir="/var/tmp") as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        dirty = 16 if args.mode == "dirty" else 0
        if args.guest_dir:
            guest = args.guest_dir / f"bench-guest-{args.mode}"
        else:
            guest = root / "guest"
            subprocess.run(["cc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", f"-DDIRTY_MIB={dirty}",
                            ROOT / "tests/fixtures/managed-runtime-bench.c", "-o", guest], check=True)
        output = {}

        def measure(endpoint, root, source, inventory, launch):
            bench = Bench(endpoint, root, source, inventory)
            source_log = bench.boot_logs(source)
            task = source_log.first_task("capture-source")
            if task is None:
                raise RuntimeError("cold Guest task did not complete")
            bench.rows.append({"scenario": "cold", "first_task_observed_upper_bound_ms": elapsed(launch),
                               "tasks": [{**task, "process": process_metrics(bench.source_pid)}]})
            until(lambda: len(source_log.ticks()) >= 10)
            bench.fork("first_fork", source, ["bench-first"])
            bench.fence("bench-first")
            bench.fork("repeat_fork", source, ["bench-repeat"])
            bench.fence("bench-repeat")
            siblings = [f"bench-wide-{i}" for i in range(args.fanout)]
            bench.fork("concurrent_fanout", source, siblings)
            for name in siblings:
                bench.fence(name)
            parent, parent_name = source, None
            for depth in range(1, args.depth + 1):
                name = f"bench-depth-{depth}"
                (child,) = bench.fork(f"recursive_depth_{depth}", parent, [name])
                if parent_name is not None:
                    bench.fence(parent_name)
                parent, parent_name = child, name
            if parent_name is not None:
                bench.fence(parent_name)
            if args.durable:
                bench.durable()
            with guest.open("rb") as binary:
                guest_digest = hashlib.file_digest(binary, "sha256").hexdigest()
            output.update({"workload": args.mode, "dirty_mib_per_tick": dirty, "read_lanes": args.lane,
                           "guest_sha256": guest_digest, "rows": bench.rows})

        try:
            verify(args.bundle, root, guest, None, False, False, False, False, observer=measure)
        except BaseException:
            for log in (root / "serve.log", root / "worker.log", *sorted((root / "state/managed").glob("*.log"))):
                if log.exists():
                    print(f"{log.name}\n{log.read_text(errors='replace')[-3000:]}", file=sys.stderr)
            raise
        print(json.dumps(output))


def summarize(samples):
    groups = {}
    for sample in samples:
        for row in sample["rows"]:
            key = (sample["workload"], sample["read_lanes"], row["scenario"])
            values = groups.setdefault(key, {})
            for name in ("api_ms", "ready_ms", "source_release_ms", "source_heartbeat_gap_ms",
                         "first_task_observed_upper_bound_ms", "targets_per_sec", "target_pss_kib", "target_threads"):
                if name in row:
                    values.setdefault(name, []).append(row[name])
            for task in row.get("tasks", []):
                values.setdefault("task_runtime_ms", []).append(task["runtime_ms"])
                if "observed_ms" in task:
                    values.setdefault("first_task_observed_upper_bound_ms", []).append(task["observed_ms"])
                if task["runtime_ms"] > 0:
                    rate = (task["read_bytes"] / (1024 * 1024)) / (task["runtime_ms"] / 1000)
                    values.setdefault("task_read_mib_per_sec", []).append(rate)
                values.setdefault("threads", []).append(task["process"]["Threads"])
                values.setdefault("Pss_kib", []).append(task["process"]["Pss"])
                values.setdefault("VmHWM_kib", []).append(task["process"]["VmHWM"])
    return [{"workload": key[0], "read_lanes": key[1], "scenario": key[2],
             "metrics": {name: {"count": len(values), "p50": statistics.median(values),
                                "p95": sorted(values)[math.ceil(0.95 * len(values)) - 1]}
                         for name, values in group.items()}} for key, group in groups.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--output", type=Path)
    parser.add_argument("--samples", type=int, default=2)
    parser.add_argument("--modes", nargs="+", choices=("clean", "dirty"), default=["clean", "dirty"])
    parser.add_argument("--read-lanes", nargs="+", type=int, default=[16])
    parser.add_argument("--fanout", type=int, default=2)
    parser.add_argument("--depth", type=int, default=3, help="Recursive fork depth, or 0 to skip the depth sweep")
    parser.add_argument("--durable", action="store_true")
    parser.add_argument("--guest-dir", type=lambda value: Path(value).resolve(),
                        help="Directory with prebuilt bench-guest-clean and bench-guest-dirty binaries")
    parser.add_argument("--local-case", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--mode", choices=("clean", "dirty"), help=argparse.SUPPRESS)
    parser.add_argument("--lane", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path("/dev/kvm").exists():
        parser.error("measured Worker KVM fixture requires root and /dev/kvm")
    if args.fanout < 2 or args.depth < 0 or args.samples < 1 or any(not 0 <= count <= 16 for count in args.read_lanes):
        parser.error("invalid benchmark dimensions")
    if args.local_case:
        return local_case(args)
    if not args.output:
        parser.error("--output is required")
    manifest = json.loads((args.bundle / "runtime-bundle.json").read_text())
    cpu = next((line.partition(":")[2].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), platform.processor())
    report = {"schema": "ManagedRuntimeBench/1", "bundle_digest": manifest["bundle_digest"],
              "kernel": platform.release(), "machine_arch": platform.machine(),
              "cpu_model": cpu, "cpu_count": len(os.sched_getaffinity(0)),
              "host_load_before": os.getloadavg(), "previous_global_caches_retained": True, "samples": []}
    for sample in range(args.samples):
        for mode in args.modes:
            counts = args.read_lanes if sample % 2 == 0 else list(reversed(args.read_lanes))
            for lanes in counts:
                command = ["unshare", "--mount", "--propagation", "private", "--net", "--", sys.executable, __file__,
                           "--local-case", "--bundle", str(args.bundle), "--mode", mode, "--lane", str(lanes),
                           "--fanout", str(args.fanout), "--depth", str(args.depth)]
                if args.durable:
                    command.append("--durable")
                if args.guest_dir:
                    command.extend(("--guest-dir", str(args.guest_dir)))
                result = subprocess.run(command, check=True, stdout=subprocess.PIPE, text=True,
                                        env={**os.environ, "KRUN_BLOCK_READ_LANES": str(lanes), "RUST_LOG": "error"})
                report["samples"].append(json.loads(result.stdout.splitlines()[-1]))
                report["summary"] = summarize(report["samples"])
                with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as file:
                    json.dump(report, file, indent=2)
                    file.write("\n")
                    os.fchmod(file.fileno(), 0o644)
                Path(file.name).replace(args.output)
                print(f"Measured sample {sample + 1}, {mode} memory, {lanes} read lanes", flush=True)


if __name__ == "__main__":
    main()
