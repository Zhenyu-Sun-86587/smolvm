#!/usr/bin/env python3
"""Check that a full private catalog and diagnostic filesystem leave the Worker responsive."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def request(endpoint, method, payload, **scope):
    packet = {"protocol": "WorkerResource/1", "request_id": method,
              "method": method, "payload": payload, **scope}
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(4)
        client.connect(str(endpoint))
        client.sendall(json.dumps(packet).encode())
        response = client.recv(65536)
    if not response:
        raise ConnectionError(f"Worker closed {method} without a receipt")
    decoded = json.loads(response)
    assert (decoded["protocol"], decoded["request_id"]) == ("WorkerResource/1", method), decoded
    return decoded


def exercise(worker_binary, bundle, root):
    manifest = json.loads((bundle / "runtime-bundle.json").read_bytes())
    bundle_digest = manifest["bundle_digest"]
    with (bundle / "smolvm-bin").open("rb") as binary:
        executable_digest = hashlib.file_digest(binary, "sha256").hexdigest()
    assert any(item["path"] == "smolvm-bin" and item["sha256"] == executable_digest
               for item in manifest["artifacts"]), bundle

    storage = root / "catalog"
    storage.mkdir(mode=0o700)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=8M,mode=0700,nosuid,nodev", "tmpfs", storage], check=True)
    try:
        endpoint = root / "worker.sock"
        with (storage / "worker.log").open("wb") as diagnostics:
            worker = subprocess.Popen([worker_binary, "serve", "--socket", endpoint, "--state-dir", storage],
                                      stdin=subprocess.DEVNULL, stdout=diagnostics, stderr=diagnostics)
            try:
                until = time.monotonic() + 12
                while not endpoint.is_socket():
                    assert worker.poll() is None and time.monotonic() < until
                    time.sleep(0.03)
                assert request(endpoint, "Health", {})["result"]["state"] == "ready"
                registered = request(endpoint, "RegisterBundle",
                                     {"executable_sha256": "sha256:" + executable_digest}, bundle_digest=bundle_digest)
                assert registered["result"]["bundle_digest"] == bundle_digest, registered

                filler = storage / "fixture-filler"
                with filler.open("wb") as stream:
                    space = os.statvfs(storage)
                    os.posix_fallocate(stream.fileno(), 0, space.f_bavail * space.f_frsize)
                assert os.statvfs(storage).f_bavail == 0
                scope = {
                    "route_id": "deep", "bundle_digest": bundle_digest, "operation_id": "owned-catalog-operation",
                    "request_digest": "sha256:" + hashlib.sha256(b"owned-catalog-operation").hexdigest(),
                    "expected": {"instance_id": "owned-catalog", "incarnation_id": None, "execution_epoch": 0},
                }
                try:
                    refused = request(endpoint, "BeginOperation", {"kind": "catalog"}, **scope)
                except ConnectionError as error:
                    raise AssertionError(f"{error}; Worker exit status {worker.wait(timeout=4)}") from error
                assert refused["error"]["code"] == "E_CATALOG", refused
                assert request(endpoint, "Health", {})["result"]["state"] == "ready" and worker.poll() is None
                assert request(endpoint, "QueryOperation", {}, **scope)["error"]["code"] == "E_NOT_FOUND"
                filler.unlink()
                retried = request(endpoint, "BeginOperation", {"kind": "catalog"}, **scope)
                assert retried["result"]["phase"] == "NEW", retried
                print(f"Catalog and stderr had zero available blocks. Worker PID {worker.pid} returned E_CATALOG, "
                      "kept serving and accepted the same operation after space returned.", flush=True)
            finally:
                if worker.poll() is None:
                    worker.terminate()
                worker.wait(timeout=5)
    finally:
        subprocess.run(["umount", storage], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=lambda path: Path(path).resolve(strict=True), required=True)
    parser.add_argument("--bundle", type=lambda path: Path(path).resolve(strict=True), required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires a privileged Worker in a private mount namespace")
    if os.environ.get("OWNED_CATALOG_FULL_NAMESPACE") != "1":
        os.execvpe("unshare", ["unshare", "--mount", "--propagation", "private", "--net", "--",
                              sys.executable, "-B", __file__, *sys.argv[1:]],
                   {**os.environ, "OWNED_CATALOG_FULL_NAMESPACE": "1"})
    with tempfile.TemporaryDirectory(prefix="owned-catalog-") as directory:
        exercise(args.worker, args.bundle, Path(directory))


if __name__ == "__main__":
    main()
