#!/usr/bin/env python3
"""Check the native capture decision after the requesting process exits at each handoff."""

import argparse
import array
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

GATE = Path(__file__).resolve().parents[1] / "libkrun/tests/guest_gate"
sys.path.insert(0, str(GATE))
from probe import receive_capture


def line(sock):
    with sock.makefile("rb", buffering=0) as stream:
        reply = stream.readline(1 << 20)
    assert reply.endswith(b"\n"), reply[:128]
    return reply.strip().decode()


def read_bytes(sock, count):
    while count:
        packet = sock.recv(min(count, 65536))
        if not packet:
            raise EOFError("capture export ended during transfer")
        count -= len(packet)


def interrupted_client(address, command, stage):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(10)
        sock.connect(address)
        sock.sendall((command + "\n").encode())
        if stage == "reply":
            assert sock.recv(1, socket.MSG_PEEK) == b"O"
        else:
            header = line(sock)
            assert header.startswith("OK "), header
            sizes = json.loads(header[3:])
            if stage in ("checkpoint", "descriptor", "backing"):
                read_bytes(sock, sizes["checkpoint_bytes"])
            if stage in ("descriptor", "backing"):
                read_bytes(sock, sizes["descriptor_bytes"])
            if stage == "backing":
                marker, ancillary, flags, _ = sock.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
                assert marker == b"F" and not flags & socket.MSG_CTRUNC
                level, kind, data = ancillary[0]
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                fd, = array.array("i", data)
                assert os.fstat(fd).st_size > 0
                # Leave this received descriptor open. Process exit releases the kernel reference.
        print("arrived", flush=True)
        signal.pause()


def cut(address, command, stage):
    with subprocess.Popen([sys.executable, "-B", __file__, "--requester", str(address), command, stage],
                          stdout=subprocess.PIPE) as requester:
        try:
            assert select.select([requester.stdout], [], [], 18)[0] and requester.stdout.readline() == b"arrived\n", stage
        finally:
            requester.kill()
            requester.wait()
        assert requester.returncode == -signal.SIGKILL


def wait_until(predicate, process, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and process.poll() is None:
        try:
            if result := predicate():
                return result
        except (FileNotFoundError, ConnectionRefusedError, struct.error):
            pass
        time.sleep(.015)
    raise RuntimeError(("guest evidence unavailable", process.poll()))


def exercise(args, root, vm):
    address = root.parent / "control.sock"
    def rpc(command):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(12)
            sock.connect(str(address))
            sock.sendall((command + "\n").encode())
            return line(sock)

    def receipt(command):
        raw = rpc(command)
        assert raw.startswith("OK "), raw
        return json.loads(raw[3:])

    def samples():
        counters = [struct.unpack("<QQ", (root / f"counter-{n}").read_bytes())[0] for n in range(3)]
        with (root.parent / "data0").open("rb", buffering=0) as disk:
            disk.seek(512)
            return (*counters, struct.unpack("<Q", disk.read(8))[0])

    wait_until(lambda: min(samples()) > 2, vm, 35)
    for serial, decision in ((1, "FINISH"), (2, "CANCEL")):
        token = f"{serial} {os.urandom(16).hex()}"
        competing = f"{serial + 1} {os.urandom(16).hex()}"
        prepare = f"CAPTURE_PREPARE {token} raw"
        query = f"CAPTURE_QUERY {token}"
        cut(address, prepare, "reply")
        held = receipt(query)
        assert held["source_disposition"] == "HELD" and held["phase"] == "prepared"
        assert receipt(prepare) == held
        fixed = samples()
        first = receive_capture(address, token)
        with ThreadPoolExecutor(max_workers=3) as pool:
            attempts = [pool.submit(rpc, verb) for verb in ("RESUME", f"CAPTURE_PREPARE {competing} raw",
                                                           f"STANDBY_ENTER {competing} raw")]
            assert all(attempt.result().startswith("ERR EBUSY") for attempt in attempts)
        for stage in ("header", "checkpoint", "descriptor", "backing"):
            cut(address, "CAPTURE_EXPORT " + token, stage)
            assert receipt(query) == held and receive_capture(address, token) == first
        cut(address, f"CAPTURE_FINISH {token} KEEP_HELD", "reply")
        assert receipt(query) == held and samples() == fixed
        finish = f"CAPTURE_{decision} {token}" + (" CONTINUE" if decision == "FINISH" else "")
        cut(address, finish, "reply")
        final = receipt(query)
        assert final["source_disposition"] == "RUNNING" and final["phase"] == ("finished" if serial == 1 else "cancelled")
        assert receipt(finish) == final
        if decision == "FINISH":
            assert receive_capture(address, token) == first
        else:
            assert rpc(f"CAPTURE_EXPORT {token}").startswith("ERR EBUSY")
        wait_until(lambda: all(a > b for a, b in zip(samples(), fixed)), vm)
        print("Capture", serial, final["phase"], "after caller exits at Prepare, four export boundaries, KEEP_HELD and decision;",
              "stable checkpoint", first[1].hex(), "descriptor", first[2].hex(), "backings", sorted(first[3]), flush=True)

    if args.open_fault:
        token = f"3 {os.urandom(16).hex()}"
        arm = root.parent / "fail-one-open"
        arm.touch(exist_ok=False)
        error = rpc(f"CAPTURE_PREPARE {token} raw")
        assert not arm.exists() and error.startswith("ERR"), error
        held = receipt("CAPTURE_QUERY " + token)
        assert held["source_disposition"] == "FAILED_HELD" and held["error"], (error, held)
        assert receipt(f"CAPTURE_PREPARE {token} raw") == held
        fixed = samples()
        for op in ("RESUME", f"CAPTURE_FINISH {token} CONTINUE", f"CAPTURE_EXPORT {token}"):
            assert rpc(op).startswith("ERR EBUSY"), op
        time.sleep(.4)
        assert samples() == fixed and receipt("CAPTURE_QUERY " + token) == held
        print("Capture 3 kept the Guest stopped after an injected EMFILE while reopening a sealed RAM descriptor.",
              held["phase"], held["source_disposition"], held["error"], flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=lambda p: Path(p).resolve(strict=True), required=True)
    parser.add_argument("--counter", type=lambda p: Path(p).resolve(strict=True), required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--open-fault", type=lambda p: Path(p).resolve(strict=True),
                        help="test library compiled from fixtures/capture-export-open-fault.c")
    args = parser.parse_args()
    manifest = json.loads((args.bundle / "runtime-bundle.json").read_bytes())
    library = args.bundle / "lib/libkrun.so.2"
    artifact = next(a for a in manifest["artifacts"] if a["path"] == "lib/libkrun.so.2")
    with library.open("rb") as source:
        assert hashlib.file_digest(source, "sha256").hexdigest() == artifact["sha256"]
    print("Testing bundle", manifest["bundle_digest"], "library", artifact["sha256"], flush=True)
    with tempfile.TemporaryDirectory(dir=args.work_dir, prefix="capture-cut-") as folder:
        base = Path(folder)
        root = base / "root"
        root.mkdir()
        shutil.copy2(args.counter, root / "counters")
        for disk in ("data0", "archive"):
            with (base / disk).open("xb") as stream:
                stream.write(b"smolvm-standby-test\0")
                stream.truncate(4 << 20)
        command = [sys.executable, "-B", GATE / "probe.py", library, root, "--guest", base / "control.sock", "--standby"]
        env = {**os.environ, "LD_LIBRARY_PATH": str(library.parent), "SMOLVM_FORKABLE": "1"}
        if args.open_fault:
            env.update(LD_PRELOAD=str(args.open_fault), SMOLVM_TEST_CAPTURE_OPEN_FAULT=str(base / "fail-one-open"))
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              env=env) as vm:
            try:
                exercise(args, root, vm)
            finally:
                vm.kill()
                vm.wait()


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--requester":
        interrupted_client(*sys.argv[2:])
    else:
        main()
