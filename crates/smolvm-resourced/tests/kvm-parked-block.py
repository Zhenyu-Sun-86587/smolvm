"""Restore a parked Linux guest with two live Worker-owned writable disks."""

import array
import ctypes as ct
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("kvm_block", Path(__file__).with_name("kvm-block.py"))
block = importlib.util.module_from_spec(spec)
spec.loader.exec_module(block)
Layer, Block = block.Layer, block.Block
rpc, require, until = block.rpc, block.require, block.until

CAPACITY = 2 * 1024 * 1024
SALT = 0xbeef12349876
SRC_ID = "0102030405060708090a0b0c0d0e0f10"
ROWS = re.compile(r"PARKED_BLOCK_TICK (\d+) (\d+) ([\w-]+) ([a-f0-9]{32}) (\d+) (\d+)")
FINISH = {"abort": False, "expected_revision": 1}


def scope(name, kind, epoch=1, instance=None):
    result = block.generation.operation(name, kind, epoch)
    if instance is not None:
        result["expected"]["instance_id"] = instance
    return result


def worker(library, path, config):
    api = ct.CDLL(library)
    api.krun_get_last_error.restype = ct.c_char_p
    config = json.loads(Path(config).read_text())
    name, epoch = config["name"], config["epoch"]
    launch = config.get("launch") or scope(name, "launch", epoch)
    rpc(path, "RegisterExecution", {"launch_permit": input()}, **launch)
    print("registered", flush=True)
    require(input() == "start", "launcher did not authorize boot")
    os.environ["SMOLVM_FORKABLE"] = "1"
    ctx = api.krun_create_ctx()
    require(ctx >= 0, "krun_create_ctx", ctx)

    def call(method, *args):
        result = getattr(api, method)(ctx, *args)
        require(result == 0, method, result, api.krun_get_last_error())

    def config_call(method, value):
        data = json.dumps(value).encode()
        call(method, data, ct.c_size_t(len(data)))

    writers = launch if "durable" in config else scope(name, "writers", epoch)
    grant_id = name + "-grant"
    offered, entries, fds = rpc(path, "AcquireWriterSet",
        {"grant_id": grant_id, "expected_revision": 1}, reply_fds=True, **writers)
    require(len(entries) == len(fds), entries)
    opened = {entry["resource_id"]: fd for entry, fd in zip(entries, fds)}
    if "different_ofd" in config:
        wrong = os.open(config["different_ofd"], os.O_RDWR | os.O_CLOEXEC)
        fds.append(wrong)
        opened[offered["block_sets"][0]["head"]["head_resource_id"]] = wrong
    if "different_ancestor" in config:
        wrong = os.open(config["different_ancestor"], os.O_RDONLY | os.O_CLOEXEC)
        fds.append(wrong)
        opened["base"] = wrong

    disk = Path(config["root"])
    root_fd = os.open(disk, os.O_RDONLY | os.O_CLOEXEC)
    root_layer = Layer(b"root-base", root_fd, 0)
    disks = [Block(ct.sizeof(Block), 1, b"attach-root", b"root0", b"root", b"volume-root",
                   b"root-base", None, None, epoch, disk.stat().st_size, ct.pointer(root_layer), 1)]
    for slot, item in enumerate(offered["block_sets"], 1):
        head = item["head"]
        layers = (Layer * len(item["layers"]))(*[
            Layer(layer["resource_id"].encode(), opened[layer["resource_id"]], layer["format"] == "qcow2")
            for layer in item["layers"]
        ])
        device = f"disk-{slot}".encode()
        disks.append(Block(ct.sizeof(Block), 1, b"attach-" + device, device,
            b"storage" if slot == 1 else b"data", head["volume_id"].encode(),
            item["layers"][0]["backing_id"].encode(), head["head_resource_id"].encode(),
            grant_id.encode(), epoch, CAPACITY, layers, len(layers)))
    call("krun_attach_block_set_v1", (Block * len(disks))(*disks), ct.c_size_t(len(disks)))
    rpc(path, "AckWriterSetAttached", {"grant_id": grant_id, "expected_revision": 1}, **writers)
    os.close(root_fd)
    if "different_ofd" not in config:
        for fd in fds:
            os.close(fd)

    log = os.open(config["log"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    call("krun_set_vm_config", 2, 512)
    call("krun_add_virtio_console_default", os.open("/dev/null", os.O_RDONLY), log, log)
    call("krun_set_kernel_console", b"hvc0")
    call("krun_set_root_disk_remount", b"/dev/vda", b"ext4", b"ro,noload")
    call("krun_set_workdir", b"/")
    empty = (ct.c_char_p * 1)(None)
    call("krun_set_exec", b"/counter", empty, empty)
    call("krun_set_guest_identity_helper_v1", bytes.fromhex(config["helper"]), ct.c_size_t(32))
    call("krun_set_control_socket", os.fsencode(config["control"]))
    call("krun_split_irqchip", False)
    config_call("krun_configure_worker_block_pivot_v1", dict(socket=path, worker_uid=os.getuid(),
        bundle_digest=launch["bundle_digest"], **launch["expected"]))
    if "durable" in config:
        operation = {key: launch[key] for key in ("operation_id", "request_digest")}
        config_call("krun_configure_worker_statepoint_restore_v1", dict(capture_id=config["durable"],
            lease_id=name + "-statepoint", volume_restore_policy=config["volume_restore_policy"], **operation))
        config_call("krun_configure_worker_block_restore_v1", dict(source_pivot_id=config["source_pivot_id"],
            grant_id=grant_id, expected_revision=2, **operation))
        print("statepoint_attached", flush=True)
        authority, _, endpoints = rpc(path, "AcquireTargetAuthority", {"expected_revision": int(input())},
            reply_fds=True, **launch)
        require(len(endpoints) == 1, "missing Worker target authority")
        call("krun_set_guest_target_authority_v1", endpoints[0],
            bytes.fromhex(authority["binding"]["input"]["capture_anchor"]),
            bytes.fromhex(authority["context_digest"]), ct.c_uint64(epoch))
        os.close(endpoints[0])
    elif "restore" in config:
        data = bytes.fromhex(config["descriptor"])
        backings = (ct.c_int * len(config["backings"]))(*config["backings"])
        call("krun_set_snapshot", os.fsencode(config["restore"]))
        call("krun_set_diskless_snapshot_ram_v1", data, ct.c_size_t(len(data)), backings,
             ct.c_size_t(len(backings)))
        call("krun_set_guest_target_authority_v1", config["authority"], bytes.fromhex(config["anchor"]),
             bytes.fromhex(config["context"]), ct.c_uint64(epoch))
        if "source_pivot_id" in config:
            config_call("krun_configure_worker_block_restore_v1", dict(source_pivot_id=config["source_pivot_id"],
                grant_id=grant_id, expected_revision=2, operation_id=writers["operation_id"],
                request_digest=writers["request_digest"]))
    call("krun_start_enter")


def request(path, command, response="OK"):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(20)
        conn.connect(str(path))
        conn.sendall((command + "\n").encode())
        with conn.makefile() as stream:
            line = stream.readline().strip()
    require(line.startswith(response), command, line)
    return line


def export(path, token, directory):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(20)
        conn.connect(str(path))
        conn.sendall(f"CAPTURE_EXPORT {token}\n".encode())
        with conn.makefile("rb", buffering=0) as stream:
            line = stream.readline()
            require(line.startswith(b"OK "), line)
            header = json.loads(line[3:])

            def exact(size):
                data = bytearray()
                while len(data) < size:
                    chunk = stream.read(size - len(data))
                    require(chunk, "truncated capture export")
                    data.extend(chunk)
                return bytes(data)

            require(header["export"] == "parked", header)
            checkpoint = exact(header["checkpoint_bytes"])
            descriptor = exact(header["descriptor_bytes"])
        fds = []
        for _ in range(header["fd_count"]):
            byte, ancillary, flags, _ = conn.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
            require(byte == b"F" and not (flags & socket.MSG_CTRUNC) and len(ancillary) == 1,
                    "truncated capture FD", ancillary)
            level, kind, raw = ancillary[0]
            require((level, kind, len(raw)) == (socket.SOL_SOCKET, socket.SCM_RIGHTS, 4), ancillary)
            fds.append(array.array("i", raw)[0])
    directory.mkdir()
    (directory / "checkpoint.bin").write_bytes(checkpoint)
    return descriptor.hex(), fds


def change_source_epoch(source, destination):
    data = (source / "checkpoint.bin").read_bytes()

    def read_u32(offset):
        return int.from_bytes(data[offset:offset + 4], "little")

    start = 4 + read_u32(0)
    count = read_u32(start)
    start += 4
    for _ in range(count):
        start += 4 + read_u32(start)
    end = start + 4 + read_u32(start)
    devices = json.loads(data[start + 4:end])
    parked = next(device["ParkedGuestGate"] for device in devices["devices"] if "ParkedGuestGate" in device)
    for index, encoded in enumerate(parked["bindings"]):
        binding = json.loads(encoded)
        if binding[1] == 2 and len(binding[5]) == 7:
            binding[5][6]["execution_epoch"] += 1
            parked["bindings"][index] = json.dumps(binding)
    updated = json.dumps(devices).encode()
    destination.mkdir()
    (destination / "checkpoint.bin").write_bytes(data[:start] + len(updated).to_bytes(4, "little")
                                                   + updated + data[end:])


def orchestrate(broker, library, guest, helper, durable=False, mixed_capture=False, interrupt_capture=False):
    broker, library, guest, helper = [Path(path).resolve(strict=True) for path in (broker, library, guest, helper)]
    if interrupt_capture:
        sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))
        import capture_transport_kvm as transport
    with tempfile.TemporaryDirectory(prefix="parked-block-") as temporary:
        work = Path(temporary)
        root = work / "root"
        for sub in ("dev", "etc", "proc", "run", "sbin", "sys", "tmp"):
            (root / sub).mkdir(parents=True)
        shutil.copy2(guest, root / "counter")
        shutil.copy2(helper, root / "sbin/smolvm-identity-helper")
        disk = work / "root.ext4"
        with disk.open("wb") as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", root, disk], check=True)
        disk.chmod(0o400)
        path = work / "worker.sock"
        processes, handles, authorities = [], [], []

        def start_worker():
            process = subprocess.Popen([broker, "serve", "--socket", path, "--state-dir", work / "catalog"])
            processes.append(process)
            def health():
                try:
                    return rpc(path, "Health")
                except OSError:
                    return None
            return process, until(health, process, "Worker started")

        service, _ = start_worker()

        def call(method, payload=None, **kwargs):
            return rpc(path, method, payload, **kwargs)

        def heads_for(name, base):
            setup = scope(name + "-catalog", "setup", 0)
            call("BeginOperation", {"kind": "catalog"}, **setup)
            heads = []
            for slot, backing in enumerate(base):
                head = dict(volume_id=f"{name}-volume-{slot}", head_resource_id=f"{name}-head-{slot}")
                call("CreateVolumeHead", dict(resource_id=head["head_resource_id"], volume_id=head["volume_id"],
                    capacity_bytes=CAPACITY, backing_id=backing), **setup)
                heads.append(head)
            call("FinishOperation", FINISH, **setup)
            return heads

        def launch(name, heads, epoch=1, point=None, instance=None, **overrides):
            addr, log = work / (name + ".sock"), work / (name + ".log")
            options = dict(name=name, root=str(disk), helper=hashlib.sha256(helper.read_bytes()).hexdigest(),
                           epoch=epoch, control=str(addr), log=str(log))
            inherited = []
            authority = child = None
            if point:
                authority, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                authority.settimeout(5)
                authorities.append(authority)
                inherited = point["backings"] + [child.fileno()]
                options.update(point, authority=child.fileno(), context=secrets.token_hex(32))
            options.update(overrides)
            launch_scope = scope(name, "launch", epoch, instance)
            options["launch"] = launch_scope
            config = work / (name + ".json")
            config.write_text(json.dumps(options))
            with (work / (name + ".stderr")).open("wb") as err:
                proc = subprocess.Popen([sys.executable, "-B", __file__, "worker", library, path, config],
                    pass_fds=inherited, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err, text=True)
            processes.append(proc)
            if child:
                child.close()
            recovering = "durable" in options
            begin = scope(name, "launch", epoch - 1, instance)
            begin["expected"]["incarnation_id"] = None
            call("BeginOperation", {"kind": "restore_target" if recovering else "launch"}, **begin)
            intent = launch_scope
            permit = call("IssueLaunchPermit", {"pid": proc.pid, "uid": os.getuid()}, **intent)
            proc.stdin.write(permit["launch_permit"] + "\n")
            proc.stdin.flush()
            require(select.select([proc.stdout], [], [], 10)[0] and proc.stdout.readline().strip() == "registered",
                    name, "registration failed")
            if recovering:
                operation = intent
            else:
                call("FinishOperation", FINISH, **intent)
                operation = scope(name, "writers", epoch)
                call("BeginOperation", {"kind": "writer_reservation"}, **operation)
            call("ReserveWriterSet", {"heads": heads}, **operation)
            proc.stdin.write("start\n")
            proc.stdin.flush()

            def rows():
                return ROWS.findall(log.read_text(errors="replace")) if log.exists() else []

            return proc, addr, rows, authority, options

        def park(guest, name, heads, epoch, grant_id, revision, sequence, instance=None):
            proc, addr, rows, _, _ = guest
            challenge, anchor = secrets.token_hex(16), secrets.token_hex(16)
            token = f"{sequence} {challenge}"
            def confirmed(command):
                if interrupt_capture:
                    transport.cut(addr, command, "reply")
                return request(addr, command)

            def gate_at(phase):
                reply = request(addr, f"GUEST_GATE_QUERY {token}")
                require(reply.split()[-1] == "0", "guest gate failed", reply)
                return reply.endswith(f" {phase} 0")

            confirmed(f"GUEST_GATE_PREPARE {token} 2500 5000")
            until(lambda: gate_at("armed"), proc, "guest armed")
            confirmed(f"GUEST_GATE_PARK {token} {anchor}")
            until(lambda: gate_at("parked"), proc, "guest parked")
            confirmed(f"STANDBY_ENTER {token} managed")
            held = confirmed(f"CAPTURE_PREPARE {token} parked")
            require('"source_disposition":"HELD"' in held,
                    "source did not hold")
            if interrupt_capture:
                require(request(addr, f"CAPTURE_QUERY {token}") == held, "capture reply changed after requester exit")
            fixed = rows()
            request(addr, f"CAPTURE_EXPORT {token}", response="ERR EBUSY")
            request(addr, f"CAPTURE_FINISH {token} RETURN_STANDBY", response="ERR EBUSY")
            pivot = scope(name, f"pivot-{sequence}" if durable else "pivot", epoch, instance)
            call("BeginOperation", {"kind": "writer_pivot"}, **pivot)
            next_heads = {item["volume_id"]: "next-" + item["head_resource_id"] for item in heads}
            command = dict(operation_id=pivot["operation_id"], request_digest=pivot["request_digest"],
                previous_grant_revision=revision, next_grant_id=grant_id, destinations=next_heads)
            receipt = json.loads(confirmed(f"CAPTURE_BLOCK_PIVOT {token} {json.dumps(command)}")[3:])
            require(receipt["state"] == "complete" and rows() == fixed, receipt)
            request(addr, f"CAPTURE_CANCEL {token}", response="ERR EBUSY")
            if durable:
                return token, fixed, pivot
            if interrupt_capture:
                original = transport.receive_capture(addr, token)
                for cut_at in ("header", "checkpoint", "descriptor", "backing"):
                    transport.cut(addr, f"CAPTURE_EXPORT {token}", cut_at)
                    require(transport.receive_capture(addr, token) == original and rows() == fixed,
                            "managed capture changed after a partial transfer", cut_at)
                with sqlite3.connect((work / "catalog/catalog.sqlite").as_uri() + "?mode=ro", uri=True) as db:
                    actual = db.execute("SELECT state,next_grant_id FROM writer_pivots WHERE operation_id=?",
                                        (pivot["operation_id"],)).fetchall()
                    require(actual == [("complete", grant_id)], "pivot was not committed once", actual)
            directory = work / (name + "-capture")
            descriptor, backings = export(addr, token, directory)
            handles.extend(backings)
            require('"source_disposition":"STANDBY"' in confirmed(f"CAPTURE_FINISH {token} RETURN_STANDBY"),
                    "capture did not preserve standby")
            if interrupt_capture:
                require(rows() == fixed and '"source_disposition":"STANDBY"' in request(addr, f"CAPTURE_QUERY {token}"),
                        "source left its original standby after the requester exited")
                print("Interrupted managed capture", name, "retained its Guest counters, two-disk pivot", pivot["operation_id"],
                      "checkpoint", original[1].hex(), "descriptor", original[2].hex(), "and", len(original[3]), "sealed backings",
                      flush=True)
            return token, fixed, dict(restore=str(directory), descriptor=descriptor, backings=backings,
                                      anchor=anchor, source_pivot_id=pivot["operation_id"])

        def check_boundary(rows, previous, hostname, identity):
            tick, pid, _, _, first, second = rows()[0]
            marker = int(previous[0])
            if previous[2] != "capture-source":
                marker ^= ord(previous[2][0]) << 48
            require((int(tick), pid, int(first), int(second)) == (int(previous[0]) + 1, previous[1], marker,
                    marker ^ SALT), "RAM and disk markers do not match the same boundary", previous, rows()[0])
            require(all(row[2:4] == (hostname, identity) for row in rows()), "inherited identity used", rows())

        def activate(guest, previous, hostname):
            proc, addr, rows, authority, options = guest
            until(addr.exists, proc, "parked target")
            request(addr, "RESUME", response="ERR EBUSY")
            identity = secrets.token_hex(16)
            label = hostname.encode()
            frame = (b"SGI1\x01\0\0\0" + secrets.token_bytes(16) + options["epoch"].to_bytes(8, "little")
                + bytes.fromhex(options["context"]) + secrets.token_bytes(32) + bytes.fromhex(identity)
                + bytes([len(label)]) + label).ljust(192, b"\0")

            def exchange(packet):
                authority.sendall(packet)
                return authority.recv(128)

            require(exchange(b"\3" + frame[8:64]).startswith(b"ERR"), "activation replay accepted")
            require(exchange(b"\1" + frame) == b"OK applying", "identity did not begin")
            until(lambda: exchange(b"\2" + frame[8:64]) == b"OK identity_ready", proc, "identity ready")
            require(not rows(), "workload ran before activation")
            require(exchange(b"\3" + frame[8:64]) == b"OK activating", "activation failed")
            until(lambda: len(rows()) >= 2, proc, "target workload resumed")
            check_boundary(rows, previous, hostname, identity)

        def wait_receipt(method, fields, operation, phase, process):
            def query():
                result = call(method, fields, **operation)
                require(not result.get("error"), method, result.get("error"))
                return result if result["phase"] == phase else None
            return until(query, process, method + " " + phase)

        def publish_point(token, operation, capture_id, purpose, release=None):
            session, hold = token.split()
            staged = call("BeginStatePointExport", dict(capture_id=capture_id, representation_id=capture_id + "-disk",
                purpose=purpose, session=int(session), hold_token=hold), **operation)
            require(staged["phase"] == "exporting" and staged["manifest_digest"] is None, staged)
            pins = call("QueryOwnerClosure", {"owner_kind": "operation", "owner_id": operation["operation_id"]})
            require(any(ref["resource_id"].startswith("volatile-") for ref in pins["resources"]), pins)
            if release is not None:
                release()
            return wait_receipt("QueryStatePoint", {"capture_id": capture_id}, operation, "durable", service)

        def stop_point(record, operation, target=None):
            capture_id = record["export"]["capture_id"]
            stop = {"capture_id": capture_id, "expected_revision": record["revision"], "restore_capture_id": target}
            result = call("StopCommit", stop, **operation)
            require(result["phase"] in ("stop_committed", "hibernated"), result)
            stopped = wait_receipt("QueryStatePoint", {"capture_id": capture_id}, operation, "hibernated", service)
            require(call("StopCommit", stop, **operation) == stopped, "STOP_COMMIT receipt changed on replay")
            pins = call("QueryOwnerClosure", {"owner_kind": "operation", "owner_id": operation["operation_id"]})
            require(not pins["resources"], "completed stop retained export pins", pins)

        def restore_durable(name, record, frozen, epoch, policy="clone_conflicts"):
            capture = record["export"]["capture_id"]
            operation = scope(name, "launch", epoch, "source")
            prepared = wait_receipt("PrepareStatePointRestore", {"capture_id": capture, "volume_restore_policy": policy},
                                     operation, "prepared", service)
            branch = prepared["exact_heads"] or heads_for(name, [item for item in record["point"]["disk_generations"] if item != "root-base"])
            target = launch(name, branch, epoch, instance="source", durable=capture,
                            volume_restore_policy=policy, source_pivot_id=record["operation_id"])
            proc, address, rows, _, _ = target
            require(select.select([proc.stdout], [], [], 12)[0] and proc.stdout.readline().strip() == "statepoint_attached",
                    "target did not attach verified StatePoint")
            plan = call("PrepareTargetActivation", {"capture_resource_id": record["point"]["representation_id"],
                "capture_anchor": record["point"]["capture_anchor"], "helper_digest": record["point"]["helper_digest"],
                "profile_digest": "sha256:" + hashlib.sha256(b"parked-block-kvm").hexdigest()}, **operation)
            proc.stdin.write(str(plan["revision"]) + "\n")
            proc.stdin.flush()
            until(address.exists, proc, "durable target paused")
            request(address, "RESUME", response="ERR EBUSY")
            offer = call("QueryTargetActivation", **operation)
            identity = secrets.token_hex(16)
            label = name.encode()
            frame = (b"SGI1\x01\0\0\0" + bytes.fromhex(offer["challenge"]) + epoch.to_bytes(8, "little")
                + bytes.fromhex(offer["context_digest"]) + secrets.token_bytes(32) + bytes.fromhex(identity)
                + bytes([len(label)]) + label).ljust(192, b"\0")
            call("BeginTargetIdentity", {"expected_revision": offer["revision"], "frame_hex": frame.hex()}, **operation)
            ready = wait_receipt("PollTargetIdentity", None, operation, "identity_ready", proc)
            require(not rows(), "durable target executed before identity commit")
            call("CommitActivation", {"expected_revision": ready["revision"]}, **operation)
            wait_receipt("PollTargetIdentity", None, operation, "released", proc)
            until(lambda: len(rows()) >= 2, proc, "durable target workload")
            check_boundary(rows, frozen[-1], name, identity)
            call("FinishOperation", FINISH, **operation)
            call("BindNativeControl", {"control_socket": str(address)}, **operation)
            return target, branch

        try:
            until(path.exists, service, "broker listening")
            executable = "sha256:" + hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            call("RegisterBundle", {"executable_sha256": executable}, bundle_digest=scope("source", "launch")["bundle_digest"])
            setup = scope("base", "import", 0)
            call("BeginOperation", {"kind": "catalog"}, **setup)
            base = work / "base"
            base.write_bytes(bytes(CAPACITY))
            digest = "sha256:" + hashlib.sha256(base.read_bytes()).hexdigest()
            with base.open("rb") as fd:
                call("ImportImmutableBlock", dict(resource_id="base", capacity_bytes=CAPACITY, content_sha256=digest),
                    fds=[fd.fileno()], fd_table=[dict(index=0, resource_id="base", role="block_import")], **setup)
            if durable:
                with disk.open("rb") as fd:
                    call("ImportImmutableBlock", dict(resource_id="root-base", capacity_bytes=disk.stat().st_size,
                        content_sha256="sha256:" + hashlib.sha256(disk.read_bytes()).hexdigest()), fds=[fd.fileno()],
                        fd_table=[dict(index=0, resource_id="root-base", role="block_import")], **setup)
                disk = work / "catalog/objects/root-base/data"
            call("FinishOperation", FINISH, **setup)
            source_heads = heads_for("source", ["base", "base"])
            source = launch("source", source_heads)
            until(lambda: len(source[2]()) >= 3, source[0], "source workload")
            require(source[2]()[-1][2:4] == ("capture-source", SRC_ID), source[2]())
            call("FinishOperation", FINISH, **scope("source", "writers"))
            if durable:
                call("BindNativeControl", {"control_socket": str(source[1])}, **scope("source", "launch"))
                token, old, operation = park(source, "source", source_heads, 1, "source-next-grant", 2, 1)

                def resume_source():
                    request(source[1], f"CAPTURE_FINISH {token} RETURN_STANDBY")
                    request(source[1], f"STANDBY_WAKE {token}")
                    until(lambda: '"source_disposition":"RUNNING"' in request(source[1], f"STANDBY_QUERY {token}"),
                          source[0], "checkpoint source thaw acknowledged")
                    until(lambda: len(source[2]()) > len(old), source[0], "checkpoint released its source")

                checkpoint = publish_point(token, operation, "checkpoint", "checkpoint", resume_source)
                call("FinishOperation", FINISH, **operation)
                closure = call("QueryOwnerClosure", {"owner_kind": "statepoint_checkpoint", "owner_id": "checkpoint"})
                require({item["resource_id"] for item in closure["resources"]} >=
                        {"checkpoint-disk", "source-head-0", "source-head-1", "root-base"}, closure)
                print("DURABLE_CHECKPOINT_PINS_EXACT_DISKS_AND_RELEASES_LIVE_SOURCE", flush=True)
                second = [dict(head, head_resource_id="next-" + head["head_resource_id"]) for head in source_heads]
                token, sleeping, stop = park(source, "source", second, 1, "source-hibernate-grant", 1, 2)
                hibernated = publish_point(token, stop, "hibernate", "hibernate")
                require(source[2]() == sleeping, "hibernation ran while writing chunks")
                commit = {"capture_id": "hibernate", "expected_revision": hibernated["revision"]}
                require(call("StopCommit", commit, **stop)["phase"] == "stop_committed",
                        "STOP_COMMIT did not record before source exit")
                service.terminate()
                service.wait(10)
                service, health = start_worker()
                require(source[0].wait(10) == 0 and source[2]() == sleeping, "source did not exit quiesced")
                hibernated = wait_receipt("QueryStatePoint", {"capture_id": "hibernate"}, stop, "hibernated", service)
                require(call("StopCommit", commit, **stop) == hibernated, "STOP_COMMIT replay changed after restart")
                call("CompleteRecovery", {"broker_session_id": health["broker_session_id"]})
                print("STOP_COMMIT_SURVIVED_WORKER_RESTART_AND_PROVED_OLD_EXECUTION_EXIT", flush=True)
                chunks = work / "catalog/statepoints/hibernate-disk/objects"
                damaged = next(chunks.iterdir())
                saved = work / "missing-object"
                damaged.rename(saved)
                try:
                    wait_receipt("PrepareStatePointRestore", {"capture_id": "hibernate"},
                                 scope("woken", "launch", 2, "source"), "prepared", service)
                except RuntimeError as error:
                    require("E_STATEPOINT_CORRUPT" in str(error), error)
                else:
                    raise RuntimeError("restore accepted a missing checkpoint object")
                finally:
                    saved.rename(damaged)
                print("DURABLE_READER_REFUSED_MISSING_CHUNK_AFTER_WORKER_RESTART", flush=True)
                backing = work / "catalog/objects/base/data"
                backing.chmod(0o600)
                with backing.open("rb+") as file:
                    original = file.read(1)
                    file.seek(0)
                    file.write(bytes([original[0] ^ 1]))
                    file.flush()
                    os.fsync(file.fileno())
                backing.chmod(0o400)
                try:
                    wait_receipt("PrepareStatePointRestore", {"capture_id": "hibernate"},
                                 scope("woken", "launch", 2, "source"), "prepared", service)
                except RuntimeError as error:
                    require("StatePoint disk generation length or hash changed" in str(error), error)
                else:
                    raise RuntimeError("restore accepted changed immutable disk bytes")
                finally:
                    backing.chmod(0o600)
                    with backing.open("rb+") as file:
                        file.write(original)
                        file.flush()
                        os.fsync(file.fileno())
                    backing.chmod(0o400)
                print("DURABLE_READER_REFUSED_CHANGED_DISK_BYTES", flush=True)
                woken, branch = restore_durable("woken", hibernated, sleeping, 2, policy="exact")
                require([head["volume_id"] for head in source_heads] == [head["volume_id"] for head in branch], branch)
                print("DURABLE_HIBERNATE_RESTORED_PID_RAM_AND_EXACT_VOLUMES_AFTER_RESTART", flush=True)

                token, _, rescue = park(woken, "woken", branch, 2, "rescue-grant", 2, 3, instance="source")
                saved = publish_point(token, rescue, "rescue", "rollback_rescue")
                try:
                    call("PrepareStatePointRestore", {"capture_id": "checkpoint", "volume_restore_policy": "exact"}, **rescue)
                except RuntimeError as error:
                    require("E_VOLUME_GENERATION_MISMATCH" in str(error), error)
                else:
                    raise RuntimeError("exact restore silently rewound active volumes")
                wait_receipt("PrepareStatePointRestore", {"capture_id": "checkpoint"}, rescue, "prepared", service)
                stop_point(saved, rescue, "checkpoint")
                require(woken[0].wait(10) == 0, "rollback source did not exit quiesced")
                rescue_root = call("QueryOwnerClosure", {"owner_kind": "statepoint_rescue", "owner_id": "rescue"})
                require({entry["resource_id"] for entry in rescue_root["resources"]} >=
                    {"rescue-disk", *(head["head_resource_id"] for head in branch)}, rescue_root)
                restore_durable("rolled-back", checkpoint, old, 3)
                print("DURABLE_ROLLBACK_KEPT_RESCUE_AND_RESTORED_EARLIER_PID_RAM_AND_DISKS", flush=True)
                return
            token, fixed, point = park(source, "source", source_heads, 1, "source-next-grant", 2, 1)
            sealed = [head["head_resource_id"] for head in source_heads]
            objects = work / "catalog/objects"
            fingerprints = [hashlib.sha256((objects / key / "data").read_bytes()).hexdigest() for key in sealed]
            print("PARKED_BLOCK_EXPORT_REQUIRES_WHOLE_PIVOT", flush=True)

            for case in ("wrong-lineage", "wrong-ofd", "wrong-ancestor", "wrong-epoch"):
                bases = ["base", sealed[1]] if case == "wrong-lineage" else sealed
                heads = heads_for(case, bases)
                overrides = {}
                if case == "wrong-ofd":
                    overrides["different_ofd"] = str(objects / heads[0]["head_resource_id"] / "data")
                if case == "wrong-ancestor":
                    overrides["different_ancestor"] = str(base)
                if case == "wrong-epoch":
                    destination = work / "wrong-epoch-capture"
                    change_source_epoch(Path(point["restore"]), destination)
                    overrides["restore"] = str(destination)
                bad = launch(case, heads, point=point, **overrides)
                require(bad[0].wait(20) != 0 and not bad[1].exists() and not bad[2](), case)
                error = (work / (case + ".stderr")).read_text(errors="replace")
                expected = "exact captured block generation" if case == "wrong-lineage" else "E_FENCE_UNPROVEN"
                require(expected in error, case, error)
                call("FinalizeExecutionExit", **scope(case, "launch"))
                print(f"PARKED_BLOCK_REJECTED_{case.upper().replace('-', '_')}", flush=True)

            child_heads = heads_for("child", sealed)
            child = launch("child", child_heads, point=point)
            activate(child, fixed[-1], "child-target")
            require(source[2]() == fixed, "child activation resumed the source")
            require(request(source[1], f"STANDBY_WAKE {token}").startswith("OK"), "wake failed")
            until(lambda: len(source[2]()) > len(fixed) + 1, source[0], "source woke on its replacement heads")
            require(source[2]()[-1][2:4] == ("capture-source", SRC_ID), source[2]())
            require(fingerprints == [hashlib.sha256((objects / key / "data").read_bytes()).hexdigest() for key in sealed],
                    "source or target changed immutable generations")
            print("PARKED_BLOCK_SOURCE_AND_CHILD_ADVANCED_WITH_INDEPENDENT_WRITERS", flush=True)

            call("FinishOperation", FINISH, **scope("child", "writers"))
            _, branch, recursive = park(child, "child", child_heads, 1, "child-next-grant", 2, 2)
            if mixed_capture:
                later = [head["head_resource_id"] for head in child_heads]
                require(point["source_pivot_id"] != recursive["source_pivot_id"] and set(sealed).isdisjoint(later),
                        "expected two independent captured device inventories")
                for name, expected, generations in (
                    ("mixed-original", point, [sealed[0], later[1]]),
                    ("mixed-recursive", recursive, [sealed[0], later[1]]),
                ):
                    target = launch(name, heads_for(name, generations), point=expected)
                    require(target[0].wait(20) != 0 and not target[1].exists() and not target[2](),
                            "mixed-capture target became visible", name)
                    error = (work / (name + ".stderr")).read_text(errors="replace")
                    require("exact captured block generation" in error or "E_FENCE_UNPROVEN" in error, name, error)
                    call("FinalizeExecutionExit", **scope(name, "launch"))
                    print(json.dumps({"case": name, "captured_origin": expected["source_pivot_id"],
                                      "generations": generations, "original_capture": sealed,
                                      "recursive_capture": later, "target_control_socket": False,
                                      "target_guest_output": False, "rejection": error.strip()},
                                     sort_keys=True), flush=True)
                require(child[2]() == branch, "rejected targets advanced the held child")
            for ancestor in (source, child):
                ancestor[0].terminate()
                ancestor[0].wait(10)
                call("FinalizeExecutionExit", **scope(ancestor[4]["name"], "launch"))
            grandchild = launch("grandchild", heads_for("grandchild", [head["head_resource_id"] for head in child_heads]),
                                point=recursive)
            activate(grandchild, branch[-1], "grandchild-target")
            print("PARKED_BLOCK_RECURSIVE_RESTORE_AFTER_SOURCE_EXIT", flush=True)
        except Exception:
            for log in sorted(work.glob("*.log")) + sorted(work.glob("*.stderr")):
                print(log.name, log.read_text(errors="replace"), file=sys.stderr)
            raise
        finally:
            for authority in authorities:
                authority.close()
            for process in reversed(processes):
                if process.poll() is None:
                    process.kill()
                    process.wait(10)
            for fd in handles:
                os.close(fd)


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "worker":
        worker(*sys.argv[2:])
    elif len(sys.argv) == 5:
        orchestrate(*sys.argv[1:])
    elif len(sys.argv) == 6 and sys.argv[1] == "--durable":
        orchestrate(*sys.argv[2:], durable=True)
    elif len(sys.argv) == 6 and sys.argv[1] == "--mixed-capture":
        orchestrate(*sys.argv[2:], mixed_capture=True)
    elif len(sys.argv) == 6 and sys.argv[1] == "--interrupt-capture":
        orchestrate(*sys.argv[2:], interrupt_capture=True)
    else:
        sys.exit(f"usage: {sys.argv[0]} [--durable|--mixed-capture|--interrupt-capture] RESOURCED LIBKRUN STATIC_GUEST IDENTITY_HELPER")
