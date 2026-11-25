"""Drive durable Worker standby/wake against a registered KVM VMM. Run as root in a private netns."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def module(path):
    spec = importlib.util.spec_from_file_location("probe_" + path.stem.replace("-", "_"), path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def run(args):
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    wire = module(Path(__file__).with_name("kvm-target-activation.py"))
    probe = module(args.probe)
    worker = str(work / "w.sock")
    control = work / "v.sock"
    children = []
    bundle = wire.digest(b"native-operation-component-test")
    with open(sys.executable, "rb") as exe:
        executable = "sha256:" + hashlib.file_digest(exe, "sha256").hexdigest()

    def start_broker():
        with (work / "broker.log").open("ab") as log:
            broker = subprocess.Popen([args.worker, "serve", "--socket", worker, "--state-dir", work / "state"],
                                      stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(broker)
        probe.until(lambda: wire.rpc(worker, "Health"))
        return broker

    def scoped(name):
        return wire.scope(bundle, "source", name, 1)

    def query(name):
        return wire.rpc(worker, "QueryOperation", route_id="deep", bundle_digest=bundle, operation_id=name)

    def complete(name, phase="COMPLETED"):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = query(name)
            if result["phase"] == phase:
                return result
            time.sleep(.025)
        raise AssertionError((name, query(name), (work / "broker.log").read_text()[-1000:]))

    def submit(name, kind, parameters=None, **extra):
        return wire.rpc(worker, "SubmitNativeOperation", {"kind": kind, "parameters": parameters or {}},
                        **{**scoped(name), **extra})

    try:
        broker = start_broker()
        wire.rpc(worker, "RegisterBundle", {"executable_sha256": executable}, bundle_digest=bundle)
        launch = wire.scope(bundle, "source", "launch")
        wire.rpc(worker, "BeginOperation", {"kind": "launch"}, **launch)
        cfg = work / "source.json"
        cfg.write_text(json.dumps({"scope": scoped("launch"), "worker": worker, "control": str(control),
                                   "disk": str(args.disk.resolve()), "epoch": 1,
                                   "helper": hashlib.sha256(args.helper.read_bytes()).hexdigest()}))
        source_log = work / "source.log"
        with source_log.open("wb") as log:
            source = subprocess.Popen([sys.executable, wire.__file__, args.lib, args.probe, "--boot", cfg],
                                      env={**os.environ, "SMOLVM_FORKABLE": "1", "RUST_LOG": "error"},
                                      stdin=subprocess.PIPE, stdout=log, stderr=log, text=True)
        children.append(source)
        permit = wire.rpc(worker, "IssueLaunchPermit", {"pid": source.pid, "uid": os.getuid()}, **scoped("launch"))
        source.stdin.write(json.dumps(permit) + "\n")
        source.stdin.flush()

        def rows():
            if source.poll() is not None:
                raise RuntimeError(source_log.read_text()[-1600:])
            return probe.ROWS.findall(source_log.read_bytes())

        probe.until(lambda: len(rows()) >= 3, 35)
        observed = wire.rpc(worker, "BindNativeControl", {"control_socket": str(control)}, **scoped("launch"))
        assert observed["execution"]["pid"] == source.pid
        assert observed["inventory"]["source_disposition"] == "RUNNING" and observed["inventory"]["measured_helper"]
        wire.rpc(worker, "FinishOperation", {"expected_revision": query("launch")["revision"], "abort": False},
                 **scoped("launch"))
        stale = {**scoped("stale")["expected"], "execution_epoch": 2}
        wire.rpc(worker, "SubmitNativeOperation", {"kind":"standby"}, expected=stale,
                 **{k:v for k,v in scoped("stale").items() if k != "expected"}, error="E_STALE_EXECUTION")
        wire.rpc(worker, "SubmitNativeOperation", {"kind":"standby", "parameters":{"mode":"other"}},
                 **scoped("bad-mode"), error="E_INVALID_REQUEST")
        initial = rows()[-1]
        for mode in ("managed", "raw"):
            name = mode + "-sleep"
            submit(name, "standby", {"mode": mode})
            sleeping = complete(name)
            assert sleeping["native"]["source_disposition"] == "STANDBY", sleeping
            stopped = rows()
            time.sleep(.6)
            assert rows() == stopped
            assert submit(name, "standby", {"mode": mode}) == sleeping
            wire.rpc(worker, "SubmitNativeOperation", {"kind":"standby",
                     "parameters":{"mode":"raw" if mode == "managed" else "managed"}},
                     **scoped(name), error="E_IDEMPOTENCY_CONFLICT")
            wire.rpc(worker, "CancelNativeOperation", {"expected_revision": sleeping["revision"]},
                     **scoped(name), error="E_ALREADY_COMMITTED")
            if mode == "managed":
                broker.kill()
                broker.wait()
                broker = start_broker()
                assert query(name) == sleeping
                inventory = wire.rpc(worker, "QueryNativeInventory", **scoped(name))
                assert inventory["inventory"]["source_disposition"] == "STANDBY" and rows() == stopped
            wake = mode + "-wake"
            submit(wake, "wake")
            assert complete(wake)["native"]["source_disposition"] == "RUNNING"
            probe.until(lambda: len(rows()) > len(stopped))
            assert rows()[-1][1:] == initial[1:]
            print(mode, "standby/wake confirmed", "guest PID", initial[1].decode(), flush=True)

        # Close before the broker sends its acknowledgement. It owns and
        # completes the submitted operation independently of this connection.
        name = "disconnect"
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
            client.connect(worker)
            client.send(json.dumps({"protocol":"WorkerResource/1", "request_id":name,
                        "method":"SubmitNativeOperation","payload":{"kind":"standby"}, **scoped(name)}).encode())
        assert complete(name)["native"]["source_disposition"] == "STANDBY"
        submit("final-wake", "wake")
        assert complete("final-wake")["native"]["source_disposition"] == "RUNNING"
        print("disconnected submitter, stale epoch, changed replay, late cancellation and Worker restart verified", flush=True)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("lib", "probe", "worker", "disk", "helper", "work"):
        parser.add_argument("--" + option, required=True, type=Path)
    run(parser.parse_args())
