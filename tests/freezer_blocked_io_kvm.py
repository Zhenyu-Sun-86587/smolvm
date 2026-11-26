#!/usr/bin/env python3
"""Exercise the installed Guest freezer with an uninterruptible ext4 write and an unanswered FUSE lookup."""

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

from capture_transport_kvm import GATE, line, wait_until


def run(root, address, vm):
    def call(command):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(3)
            conn.connect(str(address))
            conn.sendall((command + "\n").encode())
            answer = line(conn)
        assert answer.startswith("OK "), (command, answer)
        return answer[3:]

    def counts():
        return tuple(struct.unpack("<QQ", (root / f"counter-{i}").read_bytes())[0] for i in range(3))

    def advancing():
        previous = counts()
        def advanced():
            now = counts()
            if all(b > a for a, b in zip(previous, now)):
                return now
        return wait_until(advanced, vm)

    def gate(verb, token, args=""):
        reply = call(f"GUEST_GATE_{verb} {token} {args}").split()
        assert reply[:2] == token.split(), reply
        return reply[2], int(reply[3])

    def terminal(token, allowed):
        def observed():
            state = gate("QUERY", token)
            if state[0] in ("preparing", "armed", "aborting") and state not in allowed:
                return None
            assert state in allowed, (state, allowed)
            return state
        return wait_until(observed, vm, 4)

    def blocked(token, pending_cancel=False):
        start = time.monotonic()
        assert gate("PREPARE", token, "450 2500")[0] in ("preparing", "failed_thawed")
        if pending_cancel:
            assert gate("QUERY", token)[0] == "preparing"
            gate("ABORT", token)
        allowed = {("failed_thawed", -errno.EBUSY)}
        if pending_cancel:
            allowed.add(("aborted", 0))
        outcome = terminal(token, allowed)
        duration = time.monotonic() - start
        assert duration < 3 and gate("QUERY", token) == outcome
        print(token.split()[0], "cancel while preparing" if pending_cancel else "blocked I/O",
              outcome, round(duration * 1000, 2), "ms; resumed counters", advancing(), flush=True)

    def cancel_armed(token):
        assert gate("PREPARE", token, "1500 2500")[0] in ("preparing", "armed")
        terminal(token, {("armed", 0)})
        held = counts()
        time.sleep(.15)
        assert counts() == held
        gate("ABORT", token)
        terminal(token, {("aborted", 0)})
        assert gate("QUERY", token) == ("aborted", 0)
        print(token.split()[0], "armed counters", held, "aborted; resumed counters", advancing(), flush=True)

    def note(filename):
        return wait_until(lambda: (root / filename).read_text().strip(), vm, 35)

    def token(number):
        return f"{number} {secrets.token_hex(16)}"
    wait_until(lambda: min(counts()) > 2, vm, 35)
    print(note("ext4-blocked"), flush=True)
    # The ext4 superblock write lock is a freezable D-state wait on this kernel.
    cancel_armed(token(1))
    (root / "release-ext4").touch(exist_ok=False)
    print(note("ext4-completed"), flush=True)
    cancel_armed(token(2))
    (root / "start-fuse").touch(exist_ok=False)
    print(note("fuse-blocked"), flush=True)
    blocked(token(3))
    (root / "inspect-fuse").touch(exist_ok=False)
    tasks = note("fuse-tasks")
    assert "=D" in tasks, tasks
    print(tasks, flush=True)
    blocked(token(4), pending_cancel=True)
    (root / "release-fuse").touch(exist_ok=False)
    print(note("fuse-completed"), flush=True)
    cancel_armed(token(5))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("bundle", "blocker", "counters"):
        parser.add_argument("--" + option, type=lambda value: Path(value).resolve(strict=True), required=True)
    parser.add_argument("--work-dir", type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.bundle / "runtime-bundle.json").read_bytes())
    artifacts = {item["path"]: item["sha256"] for item in manifest["artifacts"]}
    for path in ("lib/libkrun.so.2", "lib/libkrunfw.so.5", "guest/identity-helper"):
        with (args.bundle / path).open("rb") as file:
            assert hashlib.file_digest(file, "sha256").hexdigest() == artifacts[path]
    print("Testing installed bundle", manifest["bundle_digest"], flush=True)
    with tempfile.TemporaryDirectory(prefix="gate-io-", dir=args.work_dir) as directory:
        base = Path(directory)
        root = base / "root"
        root.mkdir()
        for folder in ("sbin", "etc", "run", "blocked-fs"):
            (root / folder).mkdir()
        shutil.copy2(args.blocker, root / "counters")
        shutil.copy2(args.counters, root / "tickers")
        shutil.copy2(args.bundle / "guest/identity-helper", root / "sbin/smolvm-identity-helper")
        for name in ("data0", "archive"):
            with (base / name).open("xb") as image:
                image.truncate(16 << 20)
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", base / "data0"], check=True)
        lib = args.bundle / "lib"
        address = base / "control.sock"
        command = [sys.executable, "-B", GATE / "probe.py", lib / "libkrun.so.2", root,
                   "--guest", address, "--standby", "--expected-helper", artifacts["guest/identity-helper"]]
        with (base / "guest.log").open("wb") as output, subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
            env={**os.environ, "LD_LIBRARY_PATH": str(lib)},
        ) as vm:
            try:
                run(root, address, vm)
            except BaseException:
                print((base / "guest.log").read_text(errors="replace")[-4500:], file=sys.stderr)
                raise
            finally:
                vm.kill()
                vm.wait()


if __name__ == "__main__":
    main()
