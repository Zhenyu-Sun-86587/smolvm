"""Exercise managed block grants and virtio-blk with two Linux guests."""

import ctypes as ct
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time

GENERATION_TEST = Path(__file__).with_name("kvm-generation.py")
spec = importlib.util.spec_from_file_location("kvm_generation", GENERATION_TEST)
generation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generation)
rpc, require, until = generation.rpc, generation.require, generation.until

GRANT_KIND = "writer_reservation"
BUNDLE = {
    name: "sha256:" + hashlib.sha256(name.encode()).hexdigest()
    for name in ("writer", "observer")
}


def operation(name, kind, epoch=1):
    return dict(generation.operation(name, kind, epoch), bundle_digest=BUNDLE[name])


class Layer(ct.Structure):
    _fields_ = [("resource_id", ct.c_char_p), ("fd", ct.c_int), ("format", ct.c_uint32)]


class Block(ct.Structure):
    _fields_ = [
        ("size", ct.c_uint32), ("version", ct.c_uint32),
        *((name, ct.c_char_p) for name in ("attachment_id", "device_id", "role", "volume_id",
                                          "generation_id", "writable_head_id", "grant_id")),
        ("execution_epoch", ct.c_uint64), ("capacity_bytes", ct.c_uint64),
        ("layers", ct.POINTER(Layer)), ("layer_count", ct.c_size_t),
    ]


def attach(krun, ctx, grant, sets, held):
    formats = {"raw": 0, "qcow2": 1}
    specs = []
    for index, item in enumerate(sets):
        head = item["head"]
        volume = head["volume_id"].encode()
        head_id = head["head_resource_id"].encode()
        data = item["layers"]
        layers = (Layer * len(data))(*[
            Layer(layer["resource_id"].encode(), held[layer["resource_id"]], formats[layer["format"]])
            for layer in data
        ])
        specs.append(Block(ct.sizeof(Block), 1, b"attach-" + volume, b"device-" + volume,
                           b"storage" if index == 0 else b"data", volume,
                           (data[0]["backing_id"] or data[0]["resource_id"]).encode(),
                           head_id, grant["grant_id"].encode(), grant["execution_epoch"],
                           data[0]["capacity_bytes"], layers, len(layers)))
    rc = krun.krun_attach_block_set_v1(ctx, (Block * len(specs))(*specs), ct.c_size_t(len(specs)))
    require(rc == 0, "block attach failed", rc)


def worker(library, path, name, root, log):
    import threading
    krun = ct.CDLL(library)
    held = {}
    heads = []
    scope = operation(name, GRANT_KIND)
    for line in sys.stdin:
        cmd = json.loads(line)
        method = cmd["method"]
        try:
            if method == "register":
                result = rpc(path, "RegisterExecution", {"launch_permit": cmd["permit"]}, **operation(name, "launch"))
            elif method == "reconcile":
                rpc(path, "ReconcileExecution", **operation(name, "launch"))
                fd_table = [dict(index=n, resource_id=key, role="block_writer") for n, key in enumerate(heads)]
                result = rpc(path, "ReconcileWriterSet",
                             {"grant_id": name + "-grant", "expected_revision": cmd["revision"]},
                             fds=[held[head] for head in heads], fd_table=fd_table, **scope)
            elif method == "leak":
                helper = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"],
                                          pass_fds=tuple(held[key] for key in heads))
                result = {"pid": helper.pid}
            elif method == "close_writers":
                for key in heads:
                    os.close(held.pop(key))
                heads.clear()
                result = {"closed": True}
            elif method == "boot":
                offered, entries, descriptors = rpc(
                    path, "AcquireWriterSet", {"grant_id": name + "-grant", "expected_revision": 1},
                    reply_fds=True, **scope)
                require(len(entries) == len(descriptors), entries)
                for entry, fd in zip(entries, descriptors):
                    key = entry["resource_id"]
                    readonly = entry["role"] == "block_ancestor"
                    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                    require(flags & os.O_ACCMODE == (os.O_RDONLY if readonly else os.O_RDWR), entry)
                    require(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, entry)
                    held[key] = fd
                    if not readonly:
                        heads.append(key)

                ctx = krun.krun_create_ctx()
                require(ctx >= 0, "krun_create_ctx", ctx)

                def check(symbol, *args):
                    result = getattr(krun, symbol)(ctx, *args)
                    require(result == 0, symbol, result)

                out = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                inp = os.open("/dev/null", os.O_RDONLY)
                check("krun_set_vm_config", 2, 512)
                check("krun_add_virtio_console_default", inp, out, out)
                check("krun_add_virtiofs3", b"/dev/root", os.fsencode(root), ct.c_uint64(0), ct.c_bool(True))
                check("krun_set_workdir", b"/")
                value = b"WORKER_BLOCK_OBSERVE=1" if name == "observer" else None
                if cmd.get("pivot_control"):
                    value = b"WORKER_BLOCK_PIVOT=1"
                    os.environ["SMOLVM_FORKABLE"] = "1"
                    check("krun_enable_guest_gate_v1")
                    check("krun_set_control_socket", os.fsencode(cmd["pivot_control"]))
                    config = json.dumps({
                        "socket": str(path), "worker_uid": os.getuid(), "bundle_digest": BUNDLE[name],
                        "instance_id": name, "incarnation_id": name + "-exec", "execution_epoch": 1,
                    }).encode()
                    check("krun_configure_worker_block_pivot_v1", ct.c_char_p(config), ct.c_size_t(len(config)))
                env = (ct.c_char_p * 2)(value, None)
                check("krun_set_exec", b"/bin/workload", (ct.c_char_p * 1)(), env)
                check("krun_split_irqchip", ct.c_bool(False))
                attach(krun, ctx, offered["grant"], offered["block_sets"], held)
                result = rpc(path, "AckWriterSetAttached",
                             {"grant_id": name + "-grant", "expected_revision": 1}, **scope)

                def enter():
                    code = krun.krun_start_enter(ctx)
                    os.write(out, ("krun_start_enter=%d\n" % code).encode())

                threading.Thread(target=enter, daemon=True).start()
            else:
                raise RuntimeError("unknown worker method", method)
            print(json.dumps({"result": result}), flush=True)
        except Exception as error:
            print(json.dumps({"error": str(error)}), flush=True)


def orchestrate(broker, library, guest, live_pivot=False):
    broker, library, guest = [Path(path).resolve(strict=True) for path in (broker, library, guest)]
    with tempfile.TemporaryDirectory(prefix="deep-block-kvm-") as directory:
        root = Path(directory)
        path = root / "worker.sock"
        processes = []
        escaped = None

        def call(method, payload=None, **kwargs):
            return rpc(path, method, payload, **kwargs)

        def expect_error(code, method, payload=None, **kwargs):
            try:
                call(method, payload, **kwargs)
            except RuntimeError as error:
                require(code in str(error), method, error)
            else:
                raise RuntimeError("expected error", method, code)

        def start_service():
            process = subprocess.Popen([broker, "serve", "--socket", path, "--state-dir", root / "state"])
            processes.append(process)
            def health():
                try:
                    return call("Health")
                except OSError:
                    return None
            return process, until(health, process, "broker listening")

        def command(process, method, **payload):
            process.stdin.write(json.dumps(dict(method=method, **payload)) + "\n")
            process.stdin.flush()
            require(select.select([process.stdout], [], [], 20)[0], "worker command timed out", method)
            response = json.loads(process.stdout.readline())
            require("result" in response, response)
            return response["result"]

        finish = {"abort": False, "expected_revision": 1}

        def launch(name):
            work = root / name
            for base in ("bin", "dev", "etc", "proc", "run", "sys", "tmp"):
                (work / base).mkdir(parents=True)
            shutil.copy2(guest, work / "bin/workload")
            log = root / (name + ".log")
            p = subprocess.Popen([sys.executable, "-B", __file__, "worker", library, path, name, work, log],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            processes.append(p)
            call("BeginOperation", {"kind": "launch"}, **operation(name, "launch", 0))
            scope = operation(name, "launch")
            permit = call("IssueLaunchPermit", {"pid": p.pid, "uid": os.getuid()}, **scope)
            command(p, "register", permit=permit["launch_permit"])
            call("FinishOperation", finish, **scope)
            return p, log

        def await_guest(process, log, marker):
            until(lambda: log.exists() and marker in log.read_text(errors="replace"), process, marker)
            print(marker, flush=True)

        def native(control, command, expected="OK "):
            with socket.socket(socket.AF_UNIX) as conn:
                conn.settimeout(25)
                conn.connect(str(control))
                conn.sendall((command + "\n").encode())
                response = conn.makefile("r").readline().strip()
            require(response.startswith(expected), command, response)
            return json.loads(response[3:]) if expected == "OK " else response

        capacity = 2 * 1024 * 1024
        raw = bytes([0xa7]) * 512 + bytes(capacity - 512)
        base = root / "raw-source"
        base.write_bytes(raw)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        heads = [dict(volume_id="volume-" + key, head_resource_id="head-" + key) for key in ("a", "b")]

        try:
            service, health = start_service()
            require(health["state"] == "ready", health)
            executable = "sha256:" + hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
            for bundle in BUNDLE.values():
                call("RegisterBundle", {"executable_sha256": executable}, bundle_digest=bundle)
            setup = operation("writer", "setup", 0)
            call("BeginOperation", {"kind": "catalog"}, **setup)
            with base.open("rb") as fd:
                shape = {"resource_id":"base", "capacity_bytes":capacity, "content_sha256":digest}
                result = call("ImportImmutableBlock", shape, fds=[fd.fileno()], **setup,
                              fd_table=[{"index":0,"resource_id":"base","role":"block_import"}])
                require(result["immutable"], result)
            for head in heads:
                result = call("CreateVolumeHead", {"resource_id": head["head_resource_id"],
                            "volume_id": head["volume_id"], "capacity_bytes": capacity, "backing_id": "base"}, **setup)
                require(result["kind"] == "block_head", result)
            call("FinishOperation", finish, **setup)
            base.unlink()

            source, source_log = launch("writer")
            writer = operation("writer", GRANT_KIND)
            call("BeginOperation", {"kind": GRANT_KIND}, **writer)
            call("ReserveWriterSet", {"heads": heads}, **writer)
            pivot_control = root / "pivot.sock"
            options = {"pivot_control": str(pivot_control)} if live_pivot else {}
            require(command(source, "boot", **options)["state"] == "attached", "writer was not attached")
            call("FinishOperation", finish, **writer)
            await_guest(source, source_log, "BLOCK_FLUSHED_BOTH")

            if live_pivot:
                await_guest(source, source_log, "BLOCK_RUNNING tick=2")
                hold_token = "ab" * 16
                capture = "7 " + hold_token
                require(native(pivot_control, "CAPTURE_PREPARE " + capture + " raw")["phase"] == "prepared",
                        "source did not hold")
                held_ticks = source_log.read_text(errors="replace").count("BLOCK_RUNNING")
                pivot_scope = operation("writer", "live-pivot")
                call("BeginOperation", {"kind": "writer_pivot"}, **pivot_scope)
                pivot = {
                    "operation_id": pivot_scope["operation_id"], "request_digest": pivot_scope["request_digest"],
                    "previous_grant_revision": 2, "next_grant_id": "live-successor",
                    "destinations": {head["volume_id"]: "next-" + head["head_resource_id"] for head in heads},
                }
                native(pivot_control, "CAPTURE_BLOCK_PIVOT " + capture + " " + json.dumps(
                       dict(pivot, destinations={"volume-a": "only-one"})), expected="ERR EINVAL")
                pivot_command = "CAPTURE_BLOCK_PIVOT " + capture + " " + json.dumps(pivot)
                native(pivot_control, pivot_command, expected="ERR E_FENCE_UNPROVEN")
                pending = call("QueryWriterPivot", **pivot_scope)
                require(pending["state"] == "commit", pending)
                native(pivot_control, "CAPTURE_FINISH " + capture + " CONTINUE", expected="ERR EBUSY")
                require(source_log.read_text(errors="replace").count("BLOCK_RUNNING") == held_ticks,
                        "a pending writer fence released the source")
                print("HELD_SOURCE_BLOCKED_WHILE_OLD_FDS_SURVIVE", flush=True)
                command(source, "close_writers")
                service.terminate()
                service.wait(10)
                service, health = start_service()
                session = {"broker_session_id": health["broker_session_id"]}
                require(call("QueryWriterPivot", **pivot_scope) == pending, "durable decision changed over restart")
                result = native(pivot_control, pivot_command)
                require(result["state"] == "complete", result)
                require(native(pivot_control, pivot_command) == result, "pivot receipt replay changed")
                native(pivot_control, "CAPTURE_CANCEL " + capture, expected="ERR EBUSY")
                print("HELD_KVM_RECONCILED_AND_PIVOTED_BOTH", flush=True)
                captured = [
                    root / "state/objects" / head["head_resource_id"] / "data"
                    for head in heads
                ]
                before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in captured]
                require(native(pivot_control, "CAPTURE_FINISH " + capture + " CONTINUE")["source_disposition"] == "RUNNING",
                        "source did not resume")
                until(lambda: source_log.read_text(errors="replace").count("BLOCK_RUNNING") > held_ticks,
                      source, "source writes on the new heads")
                for head in heads:
                    call("DropOwnerRef", {"owner_kind": "operation", "owner_id": pivot_scope["operation_id"],
                         "resource_id": head["head_resource_id"], "expected_revision": 1}, **pivot_scope)
                call("FinishOperation", finish, **pivot_scope)
                require(call("CompleteRecovery", session)["state"] == "ready", "writer recovery did not settle")

                branch_setup = operation("observer", "branch-setup", 0)
                call("BeginOperation", {"kind": "catalog"}, **branch_setup)
                branch = []
                for head in heads:
                    resource = "branch-" + head["head_resource_id"]
                    volume = "branch-" + head["volume_id"]
                    call("CreateVolumeHead", {"resource_id": resource, "volume_id": volume,
                         "capacity_bytes": capacity, "backing_id": head["head_resource_id"]}, **branch_setup)
                    branch.append({"head_resource_id": resource, "volume_id": volume})
                call("FinishOperation", finish, **branch_setup)
                observer, observer_log = launch("observer")
                following = operation("observer", GRANT_KIND)
                call("BeginOperation", {"kind": GRANT_KIND}, **following)
                call("ReserveWriterSet", {"heads": branch}, **following)
                require(command(observer, "boot")["state"] == "attached", "observer was not attached")
                call("FinishOperation", finish, **following)
                await_guest(observer, observer_log, "BLOCK_OBSERVED_BOTH")
                require([hashlib.sha256(path.read_bytes()).hexdigest() for path in captured] == before,
                        "source writes changed sealed KVM capture generations")
                print("SOURCE_AND_BRANCH_SHARED_IMMUTABLE_CAPTURE", flush=True)
                return

            service.terminate()
            service.wait(10)
            service, health = start_service()
            require(health["state"] == "recovering", health)
            session = {"broker_session_id": health["broker_session_id"]}
            expect_error("E_RECOVERING", "CompleteRecovery", session)
            require(command(source, "reconcile", revision=3)["state"] == "attached", "writer did not reattach")
            require(call("CompleteRecovery", session)["state"] == "ready", "recovery did not complete")
            print("BOTH_WRITER_OFDS_RECONCILED", flush=True)

            observer, observer_log = launch("observer")
            following = operation("observer", GRANT_KIND)
            call("BeginOperation", {"kind": GRANT_KIND}, **following)
            seal = dict(operation("observer", "seal", 0),
                        expected={"instance_id": "volume-seal", "execution_epoch": 0, "incarnation_id": None})
            call("BeginOperation", {"kind": "catalog"}, **seal)
            expect_error("E_FENCE_UNPROVEN", "SealVolumeHeads", {"heads": heads}, **seal)
            expect_error("E_VOLUME_WRITER_CONFLICT", "ReserveWriterSet", {"heads": heads}, **following)
            expect_error("E_FENCE_UNPROVEN", "FinalizeExecutionExit", **operation("writer", "launch"))
            escaped = command(source, "leak")["pid"]
            source.kill()
            source.wait(10)
            expect_error("E_FENCE_UNPROVEN", "FinalizeExecutionExit", **operation("writer", "launch"))
            print("ESCAPED_OFD_BLOCKED_DEATH_FENCE", flush=True)
            os.kill(escaped, 9)
            escaped = None

            def confirm_exit():
                try:
                    return call("FinalizeExecutionExit", **operation("writer", "launch"))
                except RuntimeError as error:
                    require("E_FENCE_UNPROVEN" in str(error), error)
                    return None
            require(until(confirm_exit, observer, "writer and inherited OFDs gone")["phase"] == "exited",
                    "writer exit was not finalized")
            require(call("QueryWriterSet", operation_id=writer["operation_id"])["state"] == "released",
                    "writer set did not release")
            receipt = call("SealVolumeHeads", {"heads": heads}, **seal)
            require(call("SealVolumeHeads", {"heads": heads}, **seal) == receipt, "block seal replay changed")
            require(len(receipt["generations"]) == 2 and all(layer["sealed"] for layer in receipt["generations"]),
                    receipt)
            next_heads = []
            for prior in heads:
                current = "child-" + prior["head_resource_id"]
                call("CreateVolumeHead", {
                    "resource_id": current, "volume_id": prior["volume_id"],
                    "backing_id": prior["head_resource_id"], "capacity_bytes": capacity,
                }, **seal)
                closure = call("QueryBlockClosure", {"resource_id": current})
                require([layer["resource_id"] for layer in closure["layers"]] ==
                        [current, prior["head_resource_id"], "base"], closure)
                call("DropOwnerRef", {"owner_kind": "operation", "owner_id": seal["operation_id"],
                     "resource_id": prior["head_resource_id"], "expected_revision": 1}, **seal)
                next_heads.append(dict(prior, head_resource_id=current))
            call("FinishOperation", finish, **seal)
            print("BOTH_GENERATIONS_SEALED_AND_CLONED", flush=True)
            call("ReserveWriterSet", {"heads": next_heads}, **following)
            require(command(observer, "boot")["state"] == "attached", "observer was not attached")
            call("FinishOperation", finish, **following)
            await_guest(observer, observer_log, "BLOCK_OBSERVED_BOTH")
            require((root / "state/objects/base/data").read_bytes() == raw, "raw immutable base changed")
        except Exception:
            for log in root.glob("*.log"):
                print(log.name, log.read_text(errors="replace"), file=sys.stderr)
            raise
        finally:
            if escaped is not None:
                os.kill(escaped, 9)
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(5)


if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "worker":
        worker(*sys.argv[2:])
    elif len(sys.argv) == 4:
        orchestrate(*sys.argv[1:])
    elif len(sys.argv) == 5 and sys.argv[1] == "--live-pivot":
        orchestrate(*sys.argv[2:], live_pivot=True)
    else:
        sys.exit(f"usage: {sys.argv[0]} [--live-pivot] RESOURCED LIBKRUN STATIC_GUEST")
