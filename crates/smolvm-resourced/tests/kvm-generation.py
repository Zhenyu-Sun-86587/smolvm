"""Exercise detached layered RAM across real VMM and broker processes."""

import array
import ctypes as ct
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

PROTOCOL = "WorkerResource/1"
BUNDLE = "sha256:" + hashlib.sha256(b"deep-resource-probe").hexdigest()


def require(condition, *detail):
    if not condition:
        raise RuntimeError(*detail)


def rpc(worker, method, payload=None, *, fds=(), reply_fds=False, **scope):
    request = dict(protocol=PROTOCOL, method=method, request_id=method, payload=payload, **scope)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as conn:
        conn.settimeout(10)
        conn.connect(str(worker))
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
        conn.sendmsg([json.dumps(request).encode()], ancillary)
        if reply_fds:
            received = array.array("i")
            body, messages, flags, _ = conn.recvmsg(
                65536, socket.CMSG_SPACE(64 * received.itemsize), socket.MSG_CMSG_CLOEXEC)
            require(not (flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)), "truncated descriptor receipt")
            for level, tag, data in messages:
                require((level, tag) == (socket.SOL_SOCKET, socket.SCM_RIGHTS), "invalid ancillary data")
                received.frombytes(data)
            result = json.loads(body)
            require("result" in result, result)
            return result["result"], result.get("fd_table", []), list(received)
        result = json.loads(conn.recv(65536))
        require("result" in result, result)
        return result["result"]


def operation(instance, kind, epoch=1):
    label = instance + "-" + kind
    return dict(bundle_digest=BUNDLE, route_id="deep", operation_id=label,
                request_digest="sha256:" + hashlib.sha256(label.encode()).hexdigest(),
                expected=dict(instance_id=instance, execution_epoch=epoch,
                              incarnation_id=instance + "-exec" if epoch else None))


def table(ids):
    return [dict(index=index, resource_id=backing, role="immutable_backing")
            for index, backing in enumerate(ids)]


def resource_id(instance):
    return instance + "-generation"


def generation_upload(worker, instance, directory, krun, reexport=False):
    scope = operation(instance, "generation")
    transfer = {"transfer_id": instance + "-transfer"}
    callback_kind = ct.CFUNCTYPE(ct.c_int, ct.POINTER(ct.c_uint8), ct.c_size_t,
                                 ct.POINTER(ct.c_int), ct.c_size_t, ct.c_void_p)
    outcome = {}

    @callback_kind
    def submit(descriptor, length, fds, count, _):
        try:
            data = json.loads(ct.string_at(descriptor, length))
            ids = sorted(data["backing_sizes"])
            require(len(ids) == count, "exported backing count differs from manifest")
            encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
            digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
            if not reexport:
                rpc(worker, "RegisterGenerationBegin", dict(**transfer, resource_id=resource_id(instance),
                    descriptor_digest=digest, descriptor=data), **scope)
            for offset in range(0, count, 64):
                batch = ids[offset:offset + 64]
                method = "ReconcileExecutionExports" if reexport else "RegisterGenerationBatch"
                payload = transfer if reexport else dict(**transfer, batch_index=offset // 64)
                receipt = rpc(worker, method, payload,
                    fd_table=table(batch), fds=fds[offset:offset + len(batch)], **scope)
            if reexport:
                require(receipt["state"] == "committed", receipt)
            else:
                rpc(worker, "RegisterGenerationCommit", transfer, **scope)
            outcome.update(descriptor=data, fds=count)
            return 0
        except Exception as error:
            outcome["error"] = str(error)
            return -errno.EIO

    result = krun.krun_export_snapshot_ram_v1(os.fsencode(directory), submit, None)
    require(result == 0, result, outcome)
    return outcome


def worker(args):
    krun = ct.CDLL(args[0])
    path, instance, root, control, log = [Path(args[1]), args[2], *map(Path, args[3:])]
    lease = operation(instance, "resource_lease")
    held = {}
    os.environ["SMOLVM_FORKABLE"] = "1"
    for line in sys.stdin:
        cmd = json.loads(line)
        method = cmd["method"]
        try:
            if method == "register":
                result = rpc(path, "RegisterExecution", {"launch_permit": cmd["permit"]},
                             **operation(instance, "launch"))
            elif method in ("export", "recover_source"):
                recovering = method == "recover_source"
                if recovering:
                    rpc(path, "ReconcileExecution", **operation(instance, "launch"))
                result = generation_upload(path, instance, cmd["capture"], krun, reexport=recovering)
            elif method == "recover":
                rpc(path, "ReconcileExecution", **operation(instance, "launch"))
                ids = sorted(held)
                for offset in range(0, len(ids), 64):
                    batch = ids[offset:offset + 64]
                    result = rpc(path, "ReconcileExecutionExports",
                                 {"lease_id": instance + "-lease", "expected_revision": cmd["revision"]},
                                 fd_table=table(batch), fds=[held[name] for name in batch], **lease)
            elif method == "boot":
                ctx = krun.krun_create_ctx()
                require(ctx >= 0, "krun_create_ctx", ctx)

                def check(symbol, *call_args):
                    code = getattr(krun, symbol)(ctx, *call_args)
                    require(code == 0, symbol, code)

                console = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                null = os.open("/dev/null", os.O_RDONLY)
                check("krun_set_vm_config", 2, 512)
                check("krun_add_virtio_console_default", null, console, console)
                check("krun_add_virtiofs3", b"/dev/root", os.fsencode(root), ct.c_uint64(0), ct.c_bool(True))
                check("krun_set_workdir", b"/")
                check("krun_set_exec", b"/bin/state", (ct.c_char_p * 1)(), (ct.c_char_p * 1)())
                check("krun_split_irqchip", ct.c_bool(False))
                check("krun_set_control_socket", os.fsencode(control))
                if "restore" in cmd:
                    offset = 0
                    while True:
                        result, entries, received = rpc(path, "AcquireResourceLease",
                            {"lease_id": instance + "-lease", "resource_id": cmd["resource"],
                             "access": "ro", "offset": offset},
                            reply_fds=True, **lease)
                        require(len(entries) == len(received), "lease FD count mismatch")
                        held.update((entry["resource_id"], fd) for entry, fd in zip(entries, received))
                        offset = result["next_offset"]
                        if offset == result["total"]:
                            break
                    descriptor = json.dumps(cmd["descriptor"]).encode()
                    fds = (ct.c_int * len(held))(*(held[key] for key in sorted(held)))
                    check("krun_set_snapshot", os.fsencode(cmd["restore"]))
                    check("krun_set_diskless_snapshot_ram_v1", ct.c_char_p(descriptor),
                          ct.c_size_t(len(descriptor)), fds, ct.c_size_t(len(held)))
                    rpc(path, "AckAttached", {"lease_id": instance + "-lease", "expected_revision": 1}, **lease)

                def enter():
                    code = krun.krun_start_enter(ctx)
                    os.write(console, ("krun_start_enter=%d\n" % code).encode())

                threading.Thread(target=enter, daemon=True).start()
                result = {"launched": True}
            print(json.dumps({"result": result}), flush=True)
        except Exception as error:
            print(json.dumps({"error": str(error)}), flush=True)


def control(path, command):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(30)
        conn.connect(str(path))
        conn.sendall((command + "\n").encode())
        response = conn.recv(65536).decode()
        require(response.startswith("OK"), response)
        return response.strip()


def until(check, process, detail):
    for _ in range(300):
        value = check()
        if value:
            return value
        require(process.poll() is None, "process exited", process.returncode, detail)
        time.sleep(0.05)
    raise RuntimeError("timed out", detail)


def orchestration(broker, library, guest):
    broker, library, guest = [Path(path).resolve(strict=True) for path in (broker, library, guest)]
    with tempfile.TemporaryDirectory(prefix="deep-resource-kvm-") as temporary:
        work = Path(temporary)
        processes = []
        daemon_path = work / "worker.sock"
        roots = []
        for name in ("source", "child", "grandchild"):
            root = work / name
            for directory in ("bin", "dev", "proc", "run", "sys", "tmp", "etc"):
                (root / directory).mkdir(parents=True)
            shutil.copy2(guest, root / "bin/state")
            roots.append(root)

        def start_broker():
            p = subprocess.Popen([broker, "serve", "--socket", daemon_path, "--state-dir", work / "catalog"])
            processes.append(p)
            def health():
                try:
                    return rpc(daemon_path, "Health")
                except OSError:
                    return None
            return p, until(health, p, "start broker")

        def admin(method, payload=None, **scope):
            return rpc(daemon_path, method, payload, **scope)

        def command(p, method, **kwargs):
            p.stdin.write(json.dumps(dict(method=method, **kwargs)) + "\n")
            p.stdin.flush()
            require(select.select([p.stdout], [], [], 20)[0], "worker command timed out", method)
            message = json.loads(p.stdout.readline())
            require("result" in message, message)
            return message["result"]

        def launch(name, root):
            ctrl, log = work / (name + ".sock"), work / (name + ".log")
            p = subprocess.Popen([sys.executable, "-B", __file__, "worker", library, daemon_path,
                name, root, ctrl, log], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            processes.append(p)
            admin("BeginOperation", {"kind": "launch"}, **operation(name, "launch", 0))
            permit = admin("IssueLaunchPermit", {"pid": p.pid, "uid": os.getuid()}, **operation(name, "launch"))
            command(p, "register", permit=permit["launch_permit"])
            admin("FinishOperation", {"abort": False, "expected_revision": 1}, **operation(name, "launch"))
            return p, ctrl, log

        def ticks(log):
            return [tuple(map(int, (match[0], int(match[1], 16), match[2], match[3])))
                    for match in re.findall(r"RESOURCE_GUEST tick=(\d+) cold=([0-9a-f]+) private=(\d+) pid=(\d+)",
                                             log.read_text(errors="replace"))] if log.exists() else []

        def capture_and_exit(process, name, endpoint, log, before_exit=None):
            capture, detached = work / (name + "-capture"), work / (name + "-detached")
            print(control(endpoint, "FORK " + str(capture)), flush=True)
            last_tick = ticks(log)[-1]
            admin("BeginOperation", {"kind": "generation"}, **operation(name, "generation"))
            outcome = command(process, "export", capture=str(capture))
            if before_exit:
                before_exit(capture, outcome)
            detached.mkdir()
            shutil.copy2(capture / "checkpoint.bin", detached / "checkpoint.bin")
            process.kill()
            require(process.wait(10) != 0, "source process did not die")
            shutil.rmtree(capture)
            return last_tick, detached, outcome

        def retire_exporter(name):
            scope = operation(name, "generation")
            admin("DropOwnerRef", {"owner_kind": "operation", "owner_id": scope["operation_id"],
                "resource_id": resource_id(name), "expected_revision": 1}, **scope)
            admin("FinishOperation", {"abort": False, "expected_revision": 1}, **scope)
            admin("FinalizeExecutionExit", **operation(name, "launch"))

        def boot_from(name, parent, detached, descriptor, root):
            process, endpoint, log = launch(name, root)
            scope = operation(name, "resource_lease")
            admin("BeginOperation", {"kind": "resource_lease"}, **scope)
            command(process, "boot", restore=str(detached), descriptor=descriptor, resource=resource_id(parent))
            admin("FinishOperation", {"abort": False, "expected_revision": 1}, **scope)
            return process, endpoint, log

        def private_mappings(process, descriptor):
            expected = {int(name.rsplit("-", 1)[-1], 16) for name in descriptor["backing_sizes"]}
            fields = (line.split() for line in Path(f"/proc/{process.pid}/maps").read_text().splitlines())
            actual = [field[1] for field in fields if len(field) > 5 and "/memfd:" in field[5]
                      and int(field[4]) in expected]
            require(actual and all(permission.endswith("p") for permission in actual), actual)
            return len(actual)

        try:
            service, status = start_broker()
            require(status["state"] == "ready", status)
            executable = "sha256:" + hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            admin("RegisterBundle", {"executable_sha256": executable}, bundle_digest=BUNDLE)
            source, source_control, source_log = launch("source", roots[0])
            command(source, "boot")
            until(lambda: source_control.exists() and ticks(source_log) and ticks(source_log)[-1][0] >= 3,
                  source, "source guest output")

            def recover_source(capture, outcome):
                nonlocal service, status
                scope = operation("source", "generation")
                admin("AddOwnerRef", {"owner_kind": "capture", "owner_id": "source-capture",
                    "resource_id": resource_id("source"), "expected_revision": 0}, **scope)
                service.terminate()
                service.wait(10)
                service, status = start_broker()
                require(status["state"] == "recovering", status)
                require(admin("QueryResource", {"resource_id": resource_id("source")})["state"] == "missing",
                        "live source must preserve a recovery candidate")
                recovered = command(source, "recover_source", capture=str(capture))
                require(recovered == outcome, outcome, recovered)
                print("SOURCE_REEXPORT", recovered["fds"], flush=True)

            source_last, detached, outcome = capture_and_exit(
                source, "source", source_control, source_log, recover_source)
            print("SOURCE_CAPTURE", source_last, "SEALED_BACKINGS", outcome["fds"], flush=True)
            retire_exporter("source")
            require(admin("CompleteRecovery", {"broker_session_id": status["broker_session_id"]})["state"] == "ready",
                    "broker must complete recovery from source before child acquires")
            child, child_control, child_log = boot_from("child", "source", detached, outcome["descriptor"], roots[1])
            observed = until(lambda: ticks(child_log) if ticks(child_log) and ticks(child_log)[-1][0] >= 9 else None,
                             child, "restored guest execution")
            require(observed[0][0] == source_last[0] + 1, source_last, observed)
            require(observed[-1][1] == 0xa7 and observed[-1][0] == observed[-1][2], observed)
            print("DETACHED_CHILD", observed[0], "COLD_AND_PRIVATE", observed[-1],
                  "MEMFD_MAP_PRIVATE", private_mappings(child, outcome["descriptor"]), flush=True)

            service.terminate()
            service.wait(10)
            service, status = start_broker()
            require(status["state"] == "recovering", status)
            result = command(child, "recover", revision=3)
            require(result["lease"]["state"] == "attached", result)
            require(admin("QueryResource", {"resource_id": resource_id("source")})["state"] == "available", result)
            require(admin("CompleteRecovery", {"broker_session_id": status["broker_session_id"]})["state"] == "ready",
                    "broker must complete same-boot recovery")
            observed_after = until(lambda: ticks(child_log)[-1] if ticks(child_log)[-1][0] > observed[-1][0] else None,
                                   child, "guest continuing while broker reconciles")
            print("BROKER_REEXPORT", result["received"], "CHILD_AFTER", observed_after, flush=True)

            child_last, detached, child_capture = capture_and_exit(child, "child", child_control, child_log)
            require(set(outcome["descriptor"]["backing_sizes"]) < set(child_capture["descriptor"]["backing_sizes"]),
                    "child's capture must share base backings and add a private delta")
            grandchild, _, grandchild_log = boot_from("grandchild", "child", detached, child_capture["descriptor"], roots[2])
            retire_exporter("child")
            next_tick = until(lambda: ticks(grandchild_log), grandchild, "grandchild restored guest")[0]
            require(next_tick[:3] == (child_last[0] + 1, 0xa7, child_last[0] + 1), child_last, next_tick)
            print("DETACHED_GRANDCHILD", next_tick, "SEALED_BACKINGS", child_capture["fds"],
                  "MEMFD_MAP_PRIVATE", private_mappings(grandchild, child_capture["descriptor"]), flush=True)
        except Exception:
            for path in work.glob("*.log"):
                print(path.name, path.read_text(errors="replace"), file=sys.stderr)
            raise
        finally:
            for p in reversed(processes):
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(5)


if __name__ == "__main__":
    if len(sys.argv) == 8 and sys.argv[1] == "worker":
        worker(sys.argv[2:])
    elif len(sys.argv) == 4:
        orchestration(*sys.argv[1:])
    else:
        sys.exit(f"usage: {sys.argv[0]} RESOURCED LIBKRUN STATIC_GUEST")
