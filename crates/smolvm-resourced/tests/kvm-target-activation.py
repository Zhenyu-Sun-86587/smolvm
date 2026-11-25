"""Exercise WorkerResource target activation with two real KVM VMM processes."""

import argparse
import array
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load_probe(path):
    spec = importlib.util.spec_from_file_location("target_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rpc(path, method, payload=None, *, descriptors=(), table=(), roles=(), error=None, **scope):
    request = {"protocol": "WorkerResource/1", "method": method, "request_id": method,
               "payload": payload, "fd_table": table, **scope}
    control = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))] if descriptors else []
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(6)
        client.connect(path)
        client.sendmsg([json.dumps(request).encode()], control)
        body, ancillary, flags, _ = client.recvmsg(65536, socket.CMSG_SPACE(64 * 4), socket.MSG_CMSG_CLOEXEC)
    response = json.loads(body)
    received = array.array("i")
    for level, kind, raw in ancillary:
        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS), response
        received.frombytes(raw)
    assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), response
    assert response["request_id"] == method, response
    assert [item["role"] for item in response.get("fd_table", [])] == list(roles), response
    assert len(roles) == len(received), response
    if error:
        assert response["error"]["code"] == error, response
        return
    assert "result" in response, response
    return (response["result"], received) if received else response["result"]


def scope(bundle, instance, operation, epoch=0):
    return {"route_id": "deep", "bundle_digest": bundle, "operation_id": operation,
            "request_digest": digest(operation.encode()),
            "expected": {"instance_id": instance, "execution_epoch": epoch,
                         "incarnation_id": f"{instance}-execution" if epoch else None}}


def publish_capture(probe, worker, control, command):
    checkpoint, descriptor, backings = probe.export_point(control, command["token"])
    point = Path(command["point"])
    (point / "checkpoint.bin").write_bytes(checkpoint)
    (point / "descriptor.json").write_bytes(descriptor)
    value = json.loads(descriptor)
    ordered = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    identity = {"transfer_id": "capture-transfer"}
    operation = command["scope"]
    rpc(worker, "RegisterGenerationBegin",
        {**identity, "resource_id": "source-ram", "descriptor": value, "descriptor_digest": digest(ordered)},
        **operation)
    try:
        pairs = list(zip(sorted(value["backing_sizes"]), backings, strict=True))
        for index in range(0, len(pairs), 64):
            batch = pairs[index:index+64]
            rpc(worker, "RegisterGenerationBatch", {**identity, "batch_index": index // 64},
                descriptors=[fd for _, fd in batch],
                table=[{"index": n, "resource_id": key, "role": "immutable_backing"}
                       for n, (key, _) in enumerate(batch)], **operation)
        rpc(worker, "RegisterGenerationCommit", identity, **operation)
    finally:
        for fd in backings:
            os.close(fd)
    (point / "published").touch()


def tap_spec(tap):
    fields = ("schema", "attachment_id", "route_domain_id", "private_ipv4", "guest_ipv4",
              "guest_prefix", "gateway_ipv4", "device_id", "mac", "mode")
    att = {key: tap["attachment"][key] for key in fields}
    binding = [tap[key] for key in ("lease_id", "operation_id", "route_id", "bundle_digest", "instance_id",
                                    "incarnation_id", "execution_epoch", "host_boot_id", "broker_session_id")]
    binding.append(att)
    signature = hashlib.sha256(json.dumps(binding, separators=(",", ":")).encode()).digest()

    return {"mac": bytes(att["mac"]).hex(), "digest": signature.hex()}


def boot(args, config):
    probe = load_probe(args.probe)
    worker, operation = config["worker"], config["scope"]
    permit = json.loads(sys.stdin.readline())["launch_permit"]
    registered = rpc(worker, "RegisterExecution", {"launch_permit": permit}, **operation)
    assert registered["execution"]["pid"] == os.getpid(), registered
    net_fd, tap = None, None
    if attachment := config.get("attachment"):
        tap, fds = rpc(worker, "AcquireNetworkAttachment", {"attachment_id": attachment},
                       roles=["network_tap"], **operation)
        net_fd = fds[0]
        assert tap["gate"] == "closed", tap
        config["tap"] = {**tap_spec(tap), "fd": net_fd}

    def configure_restore(point):
        descriptor = (Path(point) / "descriptor.json").read_bytes()
        backing_ids = sorted(json.loads(descriptor)["backing_sizes"])
        fds = []
        for offset in range(0, len(backing_ids), 64):
            ids = backing_ids[offset:offset+64]
            lease, batch = rpc(worker, "AcquireResourceLease",
                {"lease_id": "child-ram", "resource_id": "source-ram", "access": "ro", "offset": offset},
                roles=["immutable_backing"] * len(ids), **operation)
            fds.extend(batch)
        assert len(fds) == lease["total"]
        rpc(worker, "AckAttached", {"lease_id": "child-ram", "expected_revision": lease["lease"]["revision"]},
            **operation)
        Path(config["acquired"]).touch()
        plan = json.loads(sys.stdin.readline())
        authority, endpoint = rpc(worker, "AcquireTargetAuthority",
            {"expected_revision": plan["revision"]}, roles=["target_authority"], **operation)
        config.update(authority=endpoint[0], context=authority["context_digest"],
                      fds=fds, descriptor=descriptor.hex(), anchor=authority["binding"]["input"]["capture_anchor"])

    if not config.get("restore"):
        def await_capture():
            for line in sys.stdin:
                try:
                    publish_capture(probe, worker, config["control"], json.loads(line))
                except Exception:
                    import traceback
                    traceback.print_exc()
                    os._exit(6)
        threading.Thread(target=await_capture, daemon=True).start()

    def tap_attached():
        rpc(worker, "AckNetworkAttachment", {"attachment_id": attachment, "lease_id": tap["lease_id"],
                                               "expected_revision": tap["revision"]}, **operation)
        if point := config.get("restore"):
            configure_restore(point)

    if tap is None and (point := config.get("restore")):
        configure_restore(point)
    probe.boot(args, config, tap_attached=tap_attached if tap else None)


def frame_for(receipt, network):
    epoch = receipt["binding"]["execution"]["epoch"]
    name, machine = b"worker-child", secrets.token_bytes(16)
    head = b"SGI2\x02\0\0\0" if network else b"SGI1\x01\0\0\0"
    frame = (head + bytes.fromhex(receipt["challenge"]) + epoch.to_bytes(8, "little") +
             bytes.fromhex(receipt["context_digest"]) + secrets.token_bytes(32) + machine +
             bytes([len(name)]) + name).ljust(192, b"\0")
    if network:
        old = network["source"]["attachment"]
        new = network["target"]["attachment"]
        mode = 1 if new["mode"] == "native" else 2
        def addr(value):
            return ipaddress.IPv4Address(value).packed
        frame += ((b"NET1" + bytes([mode, old["guest_prefix"], new["guest_prefix"], 0]) +
                  bytes(old["mac"]) + bytes(new["mac"]) + addr(old["guest_ipv4"]) + addr(new["guest_ipv4"]) +
                  addr(old["gateway_ipv4"]) + addr(new["gateway_ipv4"]) + addr(network["dns_ipv4"]) +
                  network["uplink_name"].encode()).ljust(64, b"\0"))
    return frame, machine.hex().encode()


def run(args):
    probe = load_probe(args.probe)
    directory = args.work.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    root = directory / "tree"
    for sub in ("sbin", "dev", "tmp", "run", "proc", "sys", "etc"):
        (root / sub).mkdir(parents=True)
    shutil.copy2(args.counter, root / "counter")
    shutil.copy2(args.helper, root / "sbin/smolvm-identity-helper")
    disk = directory / "base.ext4"
    with disk.open("wb") as output:
        output.truncate(32 * 1024**2)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", str(root), str(disk)], check=True)
    disk.chmod(0o400)

    worker = str(directory / "worker.sock")
    processes = []
    with (directory / "worker.log").open("wb") as log:
        worker_process = subprocess.Popen([args.worker, "serve", "--socket", worker, "--state-dir", directory / "state"],
                                          stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    processes.append(worker_process)

    try:
        probe.until(lambda: rpc(worker, "Health"))
        bundle = digest(b"worker-target-kvm")
        helper = hashlib.sha256(args.helper.read_bytes()).hexdigest()
        rpc(worker, "RegisterBundle", {"executable_sha256": digest(Path(sys.executable).read_bytes())},
            bundle_digest=bundle)
        private_cidr = "10.97.0.0/29" if args.fixed_internal else "10.91.0.0/24"
        router_ip = str(next(ipaddress.IPv4Network(private_cidr).hosts()))
        if args.network:
            rpc(worker, "RegisterPrivateNetwork", {"network_id": "tap-kvm", "route_domain_id": "router-kvm",
                                                   "cidr": private_cidr})

        def private_router():
            for fd in Path(f"/proc/{worker_process.pid}/fd").iterdir():
                try:
                    if not str(fd.readlink()).startswith("net:["):
                        continue
                except FileNotFoundError:
                    continue
                output = subprocess.run(["nsenter", f"--net={fd}", "--", "ip", "-j", "-4", "addr", "show", "dev", "lo"],
                                        capture_output=True, check=True)
                for link in json.loads(output.stdout):
                    if router_ip in [addr["local"] for addr in link["addr_info"]]:
                        return fd
            raise RuntimeError("could not find the isolated private router")

        def ping(namespace, address):
            return subprocess.run(["nsenter", f"--net={namespace}", "--", "ping", "-n", "-q", "-c", "1", "-W", "1",
                                   address], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

        def launch(name, config):
            ctl = directory / (name + ".sock")
            active = scope(bundle, name, name + "-op", 1)
            rpc(worker, "BeginOperation", {"kind": "restore_target" if name == "child" else "launch"},
                **scope(bundle, name, name + "-op"))
            if args.network:
                config["attachment"] = name + "-tap"
                reserve = {"attachment_id": config["attachment"], "network_id": "tap-kvm",
                           "device_id": "net0", "mode": "fixed_internal" if args.fixed_internal else "native"}
                placement = {"attachment_id": config["attachment"]}
                if args.fixed_internal:
                    reserve["guest_ipv4"] = "10.91.0.2"
                    placement.update(guest_gateway_ipv4="10.91.0.1", guest_prefix=24)
                rpc(worker, "ReserveNetworkAttachment", reserve, **scope(bundle, name, name + "-op"))
                rpc(worker, "PrepareNetworkAttachment", placement, **scope(bundle, name, name + "-op"))
            cfg = directory / (name + ".json")
            cfg.write_text(json.dumps({**config, "worker": worker, "scope": active, "epoch": 1,
                                       "control": str(ctl), "disk": str(disk), "helper": helper}))
            path = directory / (name + ".log")
            with path.open("wb") as log:
                proc = subprocess.Popen([sys.executable, __file__, str(args.lib), str(args.probe),
                                         "--boot", str(cfg)],
                    stdin=subprocess.PIPE, stdout=log, stderr=log, text=True,
                    env={**os.environ, "SMOLVM_FORKABLE": "1", "RUST_LOG": "error"})
            processes.append(proc)
            def send(data):
                proc.stdin.write(json.dumps(data) + "\n")
                proc.stdin.flush()
            send(rpc(worker, "IssueLaunchPermit", {"pid": proc.pid, "uid": os.getuid()}, **active))
            def rows():
                if proc.poll() is not None:
                    raise RuntimeError(f"{name} terminated: {path.read_text()[-6000:]}")
                return probe.ROWS.findall(path.read_bytes())
            return active, ctl, send, rows

        src, control, source_command, source_rows = launch("source", {})
        probe.until(lambda: len(source_rows()) >= 3, 35)
        launch_record = rpc(worker, "QueryOperation", **{k: src[k] for k in ("operation_id", "bundle_digest", "route_id")})
        rpc(worker, "FinishOperation", {"abort": False, "expected_revision": launch_record["revision"]}, **src)
        generation = scope(bundle, "source", "capture", 1)
        rpc(worker, "BeginOperation", {"kind": "generation"}, **generation)
        token = "1 " + secrets.token_hex(16)
        anchor = secrets.token_hex(16)
        def gate(verb, suffix=""):
            return probe.wire(control, f"GUEST_GATE_{verb} {token} {suffix}")
        assert gate("PREPARE", "2500 5000").startswith("OK")
        probe.until(lambda: " armed 0" in gate("QUERY"))
        assert gate("PARK_NETWORK" if args.network else "PARK", anchor).startswith("OK")
        probe.until(lambda: " parked 0" in gate("QUERY"))
        assert '"source_disposition":"STANDBY"' in probe.wire(control, f"STANDBY_ENTER {token} managed")
        assert '"source_disposition":"HELD"' in probe.wire(control, f"CAPTURE_PREPARE {token} parked")
        point = directory / "point"
        point.mkdir()
        source_command({"point": str(point), "scope": generation, "token": token})
        probe.until(lambda: (point / "published").exists() and source_rows(), 30)
        assert '"source_disposition":"STANDBY"' in probe.wire(control, f"CAPTURE_FINISH {token} RETURN_STANDBY")
        parked = source_rows()

        acquired = directory / "child-acquired"
        child, child_ctl, child_command, child_rows = launch("child", {"restore": str(point), "acquired": str(acquired)})
        probe.until(lambda: (acquired.exists(), child_rows())[0], 15)
        plan = {"capture_resource_id": "source-ram", "capture_anchor": anchor, "profile_digest": digest(b"profile"),
                "helper_digest": "sha256:" + helper}
        if args.network:
            plan["network"] = {"source_attachment_id": "source-tap", "target_attachment_id": "child-tap",
                               "dns_ipv4": router_ip, "uplink_name": "eth0"}
        prepared = rpc(worker, "PrepareTargetActivation", plan, **child)
        assert prepared["phase"] == "authority_prepared", prepared
        rpc(worker, "FinishOperation", {"abort": False, "expected_revision": 1}, error="E_FENCE_UNPROVEN", **child)
        rpc(worker, "AcquireTargetAuthority", {"expected_revision": prepared["revision"]},
            error="E_PERMISSION_DENIED", **child)
        child_command({"revision": prepared["revision"]})
        probe.until(lambda: (child_ctl.exists(), child_rows())[0], 20)
        assert probe.wire(child_ctl, "RESUME").startswith("ERR EBUSY") and not child_rows()
        offer = rpc(worker, "QueryTargetActivation", **child)
        assert offer["phase"] == "offered", offer
        rpc(worker, "CommitActivation", {"expected_revision": offer["revision"]}, error="E_FENCE_UNPROVEN", **child)
        frame, machine = frame_for(offer, offer["binding"]["network"])
        wrong = bytearray(frame)
        wrong[220 if args.network else 24] ^= 1
        rpc(worker, "BeginTargetIdentity", {"frame_hex": wrong.hex(), "expected_revision": offer["revision"]},
            error="E_STALE_EXECUTION", **child)
        start = {"frame_hex": frame.hex(), "expected_revision": offer["revision"]}
        rpc(worker, "BeginTargetIdentity", start, **child)

        def ready():
            status = rpc(worker, "PollTargetIdentity", **child)
            assert status["phase"] != "failed_held", (status, (directory / "child.log").read_text())
            return status if status["phase"] == "identity_ready" else None
        identity_ready = probe.until(ready)
        assert not child_rows() and source_rows() == parked
        if args.network:
            tap = rpc(worker, "QueryNetworkAttachment", {"attachment_id": "child-tap"}, **child)
            assert tap["gate"] == "closed", tap
            router_ns = private_router()
            assert not ping(router_ns, tap["attachment"]["private_ipv4"])
        rpc(worker, "CommitActivation", {"expected_revision": identity_ready["revision"] - 1},
            error="E_STALE_REVISION", **child)
        choose = {"expected_revision": identity_ready["revision"]}
        commit = rpc(worker, "CommitActivation", choose, **child)
        assert commit["decision"] == "commit" and commit["phase"] in ("committing", "policy_armed", "released"), commit
        released = probe.until(lambda: (receipt if (receipt := rpc(worker, "PollTargetIdentity", **child))["phase"]
                                       == "released" else None))
        assert rpc(worker, "CommitActivation", choose, **child) == released
        probe.until(lambda: len(child_rows()) >= 2)
        assert all(row[1:] == (parked[-1][1], b"worker-child", machine) for row in child_rows())
        if args.network:
            tap = rpc(worker, "QueryNetworkAttachment", {"attachment_id": "child-tap"}, **child)
            assert tap["gate"] == "open", tap
            att = tap["attachment"]
            probe.until(lambda: ping(router_ns, att["private_ipv4"]), 12)
            network_line = f"UPLINK {att['guest_ipv4']} {bytes(att['mac']).hex(':')} nameserver {router_ip}".encode()
            assert network_line in (directory / "child.log").read_bytes()
        assert source_rows() == parked
        rpc(worker, "FinishOperation", {"abort": False, "expected_revision": 1}, **child)
        print(f"Worker pidfd + sealed RAM + KVM target authority passed; network={args.network}; "
              f"source and child retain PID {parked[-1][1].decode()}; journal revision {released['revision']}")
    finally:
        for proc in reversed(processes):
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lib", type=Path)
    parser.add_argument("probe", type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--counter", type=Path)
    parser.add_argument("--helper", type=Path)
    parser.add_argument("--work", type=Path)
    parser.add_argument("--boot", type=Path)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--fixed-internal", action="store_true")
    args = parser.parse_args()
    if args.fixed_internal:
        args.network = True
    args.lib = args.lib.resolve()
    args.probe = args.probe.resolve()
    if args.boot:
        boot(args, json.loads(args.boot.read_text()))
    else:
        run(args)
