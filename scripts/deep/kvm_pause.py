"""Bracket a managed capture with per-vCPU KVM tracepoints on the host monotonic clock."""

from contextlib import contextmanager
from pathlib import Path
import re
import signal
import socket
import subprocess
import time


class VcpuTrace:
    def __init__(self, path, threads):
        self.path = path
        self.threads = threads
        self.held = None

    def observe(self, stage, inventory):
        if self.held or stage not in ("pivoting", "exporting", "source_return"):
            return
        before = time.monotonic_ns()
        disposition = inventory()["inventory"]["source_disposition"]
        after = time.monotonic_ns()
        if disposition == "HELD":
            self.held = (before, after)

    def result(self):
        if not self.held:
            raise RuntimeError("no live VMM inventory confirmed HELD during capture")
        sample = subprocess.run(
            ["perf", "script", "--ns", "--show-lost-events", "-F", "tid,time,event", "-i", self.path],
            capture_output=True, text=True, check=True,
        )
        if "lost" in sample.stderr.lower():
            raise RuntimeError(sample.stderr)
        before, after = self.held
        events = {tid: {} for tid in self.threads}
        for line in sample.stdout.splitlines():
            if not line.strip():
                continue
            match = re.fullmatch(r"\s*(\d+)\s+(\d+)\.(\d{9}):\s+kvm:kvm_(entry|exit):?\s*", line)
            if match is None:
                raise RuntimeError(f"unexpected or lost perf event: {line}")
            tid, sec, nsec, kind = match.groups()
            record = events[int(tid)]
            timestamp = int(sec) * 1_000_000_000 + int(nsec)
            if timestamp <= before:
                record["last_before"] = (kind, timestamp)
            elif timestamp >= after:
                record.setdefault("first_after", (kind, timestamp))
            else:
                raise RuntimeError(f"vCPU {tid} entered or exited during HELD inventory")
            record["count"] = record.get("count", 0) + 1
        boundaries = []
        for tid, record in events.items():
            last, first = record.get("last_before"), record.get("first_after")
            if not last or not first or last[0] != "exit" or first[0] != "entry":
                raise RuntimeError(f"incomplete KVM boundaries for vCPU thread {tid}: {record}")
            boundaries.append({"vcpu": self.threads[tid], "tid": tid, "last_exit_ns": last[1],
                               "next_entry_ns": first[1], "event_count": record["count"]})
        start = max(vcpu["last_exit_ns"] for vcpu in boundaries)
        end = min(vcpu["next_entry_ns"] for vcpu in boundaries)
        return {"held_inventory_ns": [before, after], "vcpu_boundaries": boundaries,
                "all_vcpus_out_ms": (end - start) / 1_000_000}


@contextmanager
def record_vcpus(execution, path):
    proc = Path("/proc") / str(execution["pid"])
    if int((proc / "stat").read_text().rsplit(")", 1)[1].split()[19]) != execution["pid_start_time"]:
        raise RuntimeError("source VMM start time differs from the Worker inventory")
    threads = {}
    for task in (proc / "task").iterdir():
        try:
            name = (task / "comm").read_text().strip()
        except FileNotFoundError:
            continue
        match = re.fullmatch(r"fc_vcpu (\d+)", name)
        if match:
            threads[int(task.name)] = int(match[1])
    if sorted(threads.values()) != [0, 1]:
        raise RuntimeError(f"expected both source vCPU threads: {threads}")
    control, recorder = socket.socketpair()
    with control, recorder:
        control.settimeout(10)
        fd = recorder.fileno()
        command = ["perf", "record", "-q", "--no-buildid", "--no-buildid-cache", "--synth", "no",
                   "--per-thread", "-m", "256", "-e", "kvm:kvm_entry", "-e", "kvm:kvm_exit",
                   "--clockid", "mono", "--no-inherit", "--tid", ",".join(map(str, threads)),
                   "--delay", "-1", "--control", f"fd:{fd},{fd}", "-o", path]
        with subprocess.Popen(command, pass_fds=(fd,)) as perf:
            recorder.close()
            try:
                control.sendall(b"enable\n")
                with control.makefile("rb") as reply:
                    if reply.readline() != b"ack\n":
                        raise RuntimeError("perf did not acknowledge both KVM tracepoints")
                yield VcpuTrace(path, threads)
            finally:
                perf.send_signal(signal.SIGINT)
                try:
                    status = perf.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    perf.kill()
                    raise
                if status not in (0, -signal.SIGINT):
                    raise RuntimeError(f"perf record exited with status {status}")
