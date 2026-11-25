#!/usr/bin/env python3
"""Check native standby on a named OCI machine using an installed deep Runtime Bundle."""

import argparse
from contextlib import ExitStack, suppress
import grp
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

EXT = "/api/v1/runtime-ext/v1"


def http(endpoint, path, body=None):
    conn = HTTPConnection("localhost", timeout=90)
    try:
        conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.sock.settimeout(conn.timeout)
        conn.sock.connect(str(endpoint))
        conn.request("POST" if body is not None else "GET", path,
                     body=json.dumps(body) if body is not None else None,
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        value = json.loads(response.read())
        if not 200 <= response.status < 300:
            raise RuntimeError(f"{path} returned {response.status}: {value}")
        return value
    finally:
        conn.close()


def until(test, seconds=25):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = test()
        except (FileNotFoundError, ConnectionRefusedError):
            value = None
        if value:
            return value
        time.sleep(.08)
    raise TimeoutError("operation exceeded test deadline")

def worker_ready(path):
    packet = {"method":"Health", "request_id":"ready", "protocol":"WorkerResource/1"}
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(5)
        peer.connect(str(path))
        peer.send(json.dumps(packet).encode())
        return "result" in json.loads(peer.recv(65536))

def confirmed(endpoint, receipt, disposition):
    def query():
        op = http(endpoint, f"{EXT}/operations/{receipt['operation_id']}")
        if op["phase"] == "ABORTED" or op["native"]["last_error"]:
            raise RuntimeError(op)
        return op if op["phase"] == "COMPLETED" else None
    op = until(query)
    assert op["native"]["source_disposition"] == disposition, op
    return op


def verify(bundle, root):
    # A private mount namespace isolates /var/lib and the per-VM UID registry.
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    for directory in ("home", "agent-rootfs", "var-lib", "ipc"):
        (root / directory).mkdir(mode=0o755)
    subprocess.run(["mount", "--bind", root / "var-lib", "/var/lib"], check=True)
    for name in ("smolvm-bin", "smolvm-resourced", "runtime-bundle.json"):
        shutil.copy2(bundle / name, root / name)
    shutil.copytree(bundle / "lib", root / "lib", symlinks=True)
    subprocess.run(["tar", "--no-overwrite-dir", "-xzf", bundle / "guest/oci-rootfs.tar.gz",
                    "-C", root / "agent-rootfs"], check=True)
    binary = root / "smolvm-bin"
    worker = root / "ipc/worker.sock"
    endpoint = root / "api/serve.sock"
    env = {**os.environ, "HOME": str(root / "home"), "SMOLVM_LIB_DIR": str(root / "lib"),
           "LD_LIBRARY_PATH": str(root / "lib"), "SMOLVM_AGENT_ROOTFS": str(root / "agent-rootfs")}
    base = [binary, "--state-dir", root / "state"]
    with ExitStack() as stack:
        def start(command, log_name):
            log = stack.enter_context((root / log_name).open("ab"))
            process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL)
            def stop():
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            stack.callback(stop)
            return process

        def broker():
            return start([root / "smolvm-resourced", "serve", "--socket", worker, "--state-dir", root / "catalog",
                          "--socket-gid", str(grp.getgrnam("kvm").gr_gid)], "worker.log")

        daemon = broker()
        until(lambda: worker_ready(worker))
        start([*base, "serve", "start", "--listen", f"unix://{endpoint}", "--worker-resource-socket", worker,
               "--guest-rollout-port", "37226", "--shutdown-grace", "0"], "serve.log")
        until(lambda: http(endpoint, EXT + "/capabilities"))
        def cli(*args):
            return json.loads(subprocess.check_output([*base, *args, "--socket", endpoint], env=env))

        machine = "/api/v1/machines/native"
        http(endpoint, "/api/v1/machines", {"name": "native", "cpus": 2, "memoryMb": 512,
                                           "storageGb": 1, "overlayGb": 1, "network": False})
        started = http(endpoint, machine + "/start", {})
        def stop_vm():
            with suppress(Exception):
                http(endpoint, machine + "/stop", {})
        stack.callback(stop_vm)
        execution = cli("runtime", "execution", "native")
        def inventory():
            return http(endpoint, f"{EXT}/instances/{execution['instance_id']}/inventory")
        record = inventory()
        assert record["execution"]["pid"] == started["runtime"]["pid"] and record["execution"]["uid"] != 0
        assert record["inventory"]["source_disposition"] == "RUNNING"
        for mode in ("managed", "raw"):
            op_id = "standby-" + mode
            args = ["machine", "standby", "--name", "native", "--operation-id", op_id]
            if mode == "raw":
                args.append("--raw")
            asleep = confirmed(endpoint, cli(*args), "STANDBY")
            assert cli(*args) == asleep
            if mode == "managed":
                daemon.kill()
                daemon.wait()
                daemon = broker()
                until(lambda: worker_ready(worker))
                assert cli("runtime", "operation", "inspect", op_id) == asleep
                assert inventory()["inventory"]["source_disposition"] == "STANDBY"
            wake = cli("machine", "wake", "--name", "native", "--operation-id", "wake-" + mode)
            confirmed(endpoint, wake, "RUNNING")
            assert inventory()["execution"]["pid"] == started["runtime"]["pid"]
        http(endpoint, machine + "/stop", {})
        http(endpoint, machine + "/start", {})
        fresh = cli("runtime", "execution", "native")
        assert fresh["execution_epoch"] == execution["execution_epoch"] + 1
        assert fresh["incarnation_id"] != execution["incarnation_id"]
        print("Named OCI machine passed both standby modes, Worker restart, wake, replay and execution rollover.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root, KVM and systemd")
    if os.stat("/proc/self/ns/mnt").st_ino == os.stat("/proc/1/ns/mnt").st_ino or not os.environ.get("SMOLVM_STANDBY_TEST_ISOLATED"):
        os.execvpe("unshare", ["unshare", "--mount", "--propagation", "private", "--net", "--",
                             sys.executable, __file__, "--bundle", str(args.bundle.resolve())],
                   {**os.environ, "SMOLVM_STANDBY_TEST_ISOLATED": "1"})
    with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="smnx-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        try:
            verify(args.bundle.resolve(), root)
        except BaseException:
            for path in (root / "worker.log", root / "serve.log"):
                if path.exists():
                    print(path.read_text(errors="replace")[-2000:], file=sys.stderr)
            raise


if __name__ == "__main__":
    main()
