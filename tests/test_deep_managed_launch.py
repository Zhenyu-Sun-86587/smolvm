#!/usr/bin/env python3
"""Boot a Worker-owned three-disk KVM through the installed private Serve."""

import argparse
import array
import base64
from contextlib import contextmanager, ExitStack, suppress
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sqlite3
import subprocess
import sys
import tempfile
import time
import shutil

from test_deep_native_standby import EXT, http, until, worker_ready

RESOURCES = Path(__file__).resolve().parents[1] / "crates/smolvm-resourced/tests"
module = importlib.util.spec_from_file_location("worker_resource", RESOURCES / "kvm-generation.py")
worker_resource = importlib.util.module_from_spec(module)
module.loader.exec_module(worker_resource)
rpc = worker_resource.rpc


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@contextmanager
def installed_bundle(source, root, name="measured"):
    """Expose an immutable installation to the VM UID inside the private test namespace."""
    target = root / name
    target.mkdir()
    subprocess.run(["mount", "--bind", source, target], check=True)
    try:
        subprocess.run(["mount", "-o", "remount,bind,ro", target], check=True)
        yield target
    finally:
        # Kernel-held executable references can outlive the last SIGKILL briefly.
        subprocess.run(["umount", "--lazy", target], check=True)


def settled(endpoint, operation_id, timeout=150):
    latest = {}
    def terminal():
        nonlocal latest
        latest=http(endpoint,f"{EXT}/operations/{operation_id}")
        return latest if latest["phase"] in ("COMPLETED","ABORTED") else None
    try: return until(terminal,timeout)
    except TimeoutError: raise AssertionError(latest)


def durable_points(endpoint, source, name, logfile):
    def invoke(kind, key, params, expected=source):
        envelope=dict(kind=kind,operation_id=key,request_digest=digest(key.encode()),expected=expected,parameters=params)
        first=http(endpoint,EXT+"/operations",envelope)
        assert first["phase"]=="NEW",first
        result=settled(endpoint,key,180)
        assert result["phase"]=="COMPLETED",result
        assert http(endpoint,EXT+"/operations",envelope)==result
        return result
    snapshot=invoke("vm_snapshot","managed-checkpoint",{"capture_id":"checkpoint-"+name})["statepoint"]
    assert snapshot["phase"]=="durable" and snapshot["source_released"] and snapshot["manifest_digest"].startswith("sha256:"),snapshot
    count=lambda:sum(line.startswith("PARKED_BLOCK_TICK ") for line in logfile.read_text(errors="replace").splitlines())
    before=count()
    until(lambda:count()>before+1,10)
    invoke("standby","standby-before-hibernate",{"mode":"managed"})
    before=count()
    hibernated=invoke("hibernate","managed-hibernate",{"capture_id":"hibernate-"+name})["statepoint"]
    assert hibernated["phase"]=="hibernated" and hibernated["original_source_disposition"]=="STANDBY" and hibernated["source_released"],hibernated
    assert hibernated["manifest_digest"].startswith("sha256:") and count()==before,hibernated
    binding=http(endpoint,f"{EXT}/machines/{name}/binding")
    assert binding["incarnation_id"] is None and binding["execution_epoch"]==source["execution_epoch"]
    print("Checkpoint publication returned a verified durable manifest while the guest continued. Hibernate stopped the parked execution without advancing its counter.",flush=True)

    def slot(machine):
        result=http(endpoint,f"{EXT}/machines/{machine}/binding")
        return {field:result[field] for field in ("instance_id","incarnation_id","execution_epoch")}

    def watch(machine):
        current=http(endpoint,f"{EXT}/machines/{machine}/execution")
        log=logfile.parent/(current["incarnation_id"]+".log")
        def ticks():
            if log.exists():
                lines=[line.split() for line in log.read_text(errors="replace").splitlines() if line.startswith("PARKED_BLOCK_TICK ")]
                if len(lines)>=2:return lines
        return current,until(ticks,20)

    resumed=invoke("vm_restore","resume-hibernated",{"name":name,"capture_id":hibernated["capture_id"],"mode":"exact"},slot(name))
    assert resumed["statepoint"]["stage"]=="released" and resumed["statepoint"]["manifest_digest"]==hibernated["manifest_digest"],resumed
    volumes=resumed["statepoint"]["volume_map"]
    assert volumes and all(old==new for old,new in volumes.items()),volumes
    again,active_ticks=watch(name)
    old_ticks=[l.split() for l in logfile.read_text(errors="replace").splitlines() if l.startswith("PARKED_BLOCK_TICK ")]
    assert again["execution_epoch"]==source["execution_epoch"]+1 and again["incarnation_id"]!=source["incarnation_id"],again
    assert active_ticks[0][2]==old_ticks[-1][2] and int(active_ticks[0][1])==int(old_ticks[-1][1])+1,(active_ticks[0],old_ticks[-1])
    print("Exact hibernate restore continued the original guest PID and next counter tick with the same writable volume IDs.",flush=True)

    rolled=invoke("vm_rollback","rollback-before-hibernate",{"capture_id":snapshot["capture_id"],"mode":"clone_conflicts"},again)["statepoint"]
    assert rolled["manifest_digest"]==snapshot["manifest_digest"] and rolled["rescue_manifest_digest"].startswith("sha256:") and rolled["rescue_capture_id"]!=snapshot["capture_id"],rolled
    current,ticks=watch(name)
    assert current["execution_epoch"]==again["execution_epoch"]+1 and int(ticks[0][1])<int(active_ticks[0][1]) and ticks[0][2]==old_ticks[0][2],ticks[:2]
    print("Rollback fenced the previous execution, retained its durable rescue and resumed the earlier counter in a new epoch.",flush=True)

    clone="checkpoint-copy"
    clone_op=invoke("vm_restore","clone-checkpoint",{"name":clone,"capture_id":snapshot["capture_id"],"mode":"clone_conflicts"},slot(clone))["statepoint"]
    assert clone_op["manifest_digest"]==snapshot["manifest_digest"] and any(a!=b for a,b in clone_op["volume_map"].items()),clone_op
    copy,clone_ticks=watch(clone)
    assert copy["instance_id"]!=current["instance_id"] and clone_ticks[0][1:3]==ticks[0][1:3] ,clone_ticks[:2]
    # If the cut landed after gethostname(), the suspended loop can print its cached
    # value once. The next iteration reads each target's installed identity.
    assert clone_ticks[1][3]==clone and ticks[1][3]==name and clone_ticks[1][4]!=ticks[1][4],(clone_ticks[1],ticks[1])
    assert clone_ticks[0][5:7]==ticks[0][5:7],(clone_ticks[0],ticks[0])
    print("A separate restore from the original checkpoint reproduced the RAM and two-disk boundary in another logical instance.",flush=True)


def partial_fork(endpoint, root, ref):
    import threading
    names=["partial-keep","partial-retry"]
    key="partial-batch"
    req=dict(kind="fork_batch",operation_id=key,request_digest=digest(key.encode()),expected=ref,parameters={"children":names})
    killed=threading.Event()
    def interrupt_unpublished():
        dbfile=root/"catalog/catalog.sqlite"
        def inject():
            with sqlite3.connect(f"file:{dbfile}?mode=ro",uri=True) as c:
                match=c.execute("""SELECT e.pid,e.pid_start_time FROM managed_fork_children ch
                    JOIN executions e ON e.last_operation_id=ch.operation_id WHERE ch.batch_id=? AND ch.name=?
                    AND NOT EXISTS(SELECT 1 FROM target_activations a WHERE a.operation_id=ch.operation_id AND a.decision='commit')""",
                    (key,names[1])).fetchone()
            if match:
                pid,start=match
                fd=os.pidfd_open(pid)
                try:
                    if int(Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[19])==start:
                        signal.pidfd_send_signal(fd,signal.SIGKILL)
                        killed.set()
                finally:os.close(fd)
            return killed.is_set()
        until(inject,120)
    thread=threading.Thread(target=interrupt_unpublished,daemon=True)
    thread.start()
    original=http(endpoint,EXT+"/operations",req)
    batch=settled(endpoint,key)
    thread.join(5)
    assert killed.is_set() and batch["fork"]["outcome"]=="partial",batch
    good,failed=batch["fork"]["children"]
    assert good["phase"]=="COMPLETED" and failed["phase"]=="ABORTED",batch
    retry=dict(request_digest=req["request_digest"],expected=ref,expected_revision=batch["revision"])
    http(endpoint,f"{EXT}/operations/{key}/retry",retry)
    recovered=settled(endpoint,key)
    assert recovered["fork"]["outcome"]=="applied" and recovered["fork"]["capture_id"]==original["fork"]["capture_id"],recovered
    old,new=recovered["fork"]["children"]
    assert good==old and failed["instance_id"]==new["instance_id"] and new["attempt"]==1
    assert new["execution_epoch"]>failed["execution_epoch"] and new["incarnation_id"]!=failed["incarnation_id"]
    assert http(endpoint,f"{EXT}/operations/{key}/retry",retry)==recovered
    print("One of two targets was killed before activation. Retry kept the successful execution and original capture, and advanced only the failed child's epoch.",flush=True)


def verify(bundle, root, guest, system_image, fork, product_volumes, statepoint, fork_faults, lifecycle=False, *,
           observer=None, stage_bundle=True, worker_binary=None, check_launch_rejections=True, guest_files=(),
           guest_vcpus=2):
    for name in ("var-lib", "home", "ipc", "root-tree", "local-run"):
        (root / name).mkdir(mode=0o755)
    subprocess.run(["mount", "--bind", root / "var-lib", "/var/lib"], check=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    if stage_bundle:
        staged = root / "bundle"
        shutil.copytree(bundle, staged, symlinks=True)
        bundle = staged
    Path("/run/smolvm-custom").mkdir(exist_ok=True)
    subprocess.run(["mount","--bind",root/"local-run","/run/smolvm-custom"],check=True)
    tree = root / "root-tree"
    for name in ("sbin", "dev", "etc", "proc", "sys", "tmp", "run"):
        (tree / name).mkdir()
    if guest:
        shutil.copy2(guest, tree / "counter")
    else:
        subprocess.run(["cc", "-static", "-Os", RESOURCES / "kvm-parked-block-guest.c", "-o", tree / "counter"], check=True)
    for guest_file in guest_files:
        shutil.copy2(guest_file, tree / guest_file.name)
    shutil.copy2(bundle / "guest/identity-helper", tree / "sbin/smolvm-identity-helper")
    root_disk = root / "root.ext4"
    data_disk = root / "data.raw"
    for path, size in ((root_disk, 32 << 20), (data_disk, 8 << 20)):
        with path.open("wb") as f:
            f.truncate(size)
    subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", tree, root_disk], check=True)
    if system_image:
        root_disk=system_image
    worker = root / "ipc/worker.sock"
    endpoint = root / "api/s.sock"
    binary = bundle / "smolvm-bin"
    env = {**os.environ, "HOME": str(root / "home"), "SMOLVM_LIB_DIR": str(bundle / "lib"),
           "LD_LIBRARY_PATH": str(bundle / "lib")}
    with ExitStack() as stack:
        def spawn(command, log):
            file = stack.enter_context((root / log).open("ab"))
            proc = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=file, stderr=file)
            def stop():
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
            stack.callback(stop)
            return proc

        broker = spawn([worker_binary or bundle / "smolvm-resourced", "serve", "--socket", worker, "--state-dir", root / "catalog",
                        "--socket-gid", str(grp.getgrnam("kvm").gr_gid)], "worker.log")
        until(lambda: worker_ready(worker))
        serve_command = [binary, "--state-dir", root / "state", "serve", "start", "--listen", f"unix://{endpoint}",
                         "--worker-resource-socket", worker, "--guest-rollout-port", "37226", "--shutdown-grace", "0"]
        serve = spawn(serve_command, "serve.log")
        handshake = until(lambda: http(endpoint, EXT + "/capabilities"))
        name = "test-managed"
        def binding():
            return http(endpoint, f"{EXT}/machines/{name}/binding")
        before = binding()
        assert before["execution_epoch"] == 0 and before["incarnation_id"] is None
        bundle_id = handshake["bundle_digest"]
        setup = dict(route_id="deep", bundle_digest=bundle_id, operation_id="catalog-import",
                     request_digest=digest(b"import"), expected=dict(instance_id="import", incarnation_id=None, execution_epoch=0))
        rpc(worker, "BeginOperation", {"kind": "catalog"}, **setup)
        for ident, file in (("base-ext4", root_disk), ("empty-data", data_disk)):
            with file.open("rb") as source:
                h=hashlib.sha256()
                for chunk in iter(lambda:source.read(1<<20),b""):h.update(chunk)
                source.seek(0)
                payload=dict(protocol="WorkerResource/1",method="ImportImmutableBlock",request_id="import-block",
                    payload=dict(resource_id=ident,capacity_bytes=file.stat().st_size,content_sha256="sha256:"+h.hexdigest()),
                    fd_table=[dict(index=0,resource_id=ident,role="block_import")],**setup)
                with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as conn:
                    conn.settimeout(240)
                    conn.connect(str(worker))
                    conn.sendmsg([json.dumps(payload).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[source.fileno()]))])
                    result=json.loads(conn.recv(65536))
                    assert "result" in result,result
        rpc(worker, "FinishOperation", dict(abort=False, expected_revision=1), **setup)
        disks = [dict(attachment_id="attach-"+role,device_id=role,role=role,generation_id=generation,read_only=readonly)
                 for role, generation, readonly in (("root","base-ext4",not system_image),("storage","empty-data",False),("data","empty-data",False))]
        wanted_heads = {}
        if product_volumes:
            def volume_operation(op, volume, revision, action, **fields):
                payload = dict(operation_id=op, request_digest=digest(op.encode()),
                               volume_id=volume, owner_id="volume-test", expected_revision=revision,
                               command=dict(action=action, **fields))
                return http(endpoint, EXT + "/volumes", payload)["volume"]

            capacity = data_disk.stat().st_size
            volume_operation("create-storage", "product-storage", 0, "create",
                             capacity_bytes=capacity, lifecycle="persistent")
            source = volume_operation("create-data-source", "product-source", 0, "create",
                                      capacity_bytes=capacity, lifecycle="persistent")
            volume_operation("snapshot-data-source", "product-source", source["revision"], "snapshot",
                             snapshot_id="product-data-snapshot")
            volume_operation("create-data", "product-data", 0, "create", capacity_bytes=capacity,
                             lifecycle="persistent", source_snapshot_id="product-data-snapshot")
            for disk in disks[1:]:
                volume = "product-" + disk["device_id"]
                del disk["generation_id"]
                disk["volume_id"] = volume
                observation = volume_operation(
                    "reserve-" + volume, volume, 1, "attach", attachment_id=disk["attachment_id"],
                    instance_id=before["instance_id"], execution_epoch=0, device_key=disk["device_id"],
                    mode="rw", fork_policy="clone", capture_policy="include",
                )
                assert observation["attachments"][0]["state"] == "reserved", observation
                wanted_heads[volume] = observation["head_resource_id"]
        parameters = dict(name=name,boot_profile="oci-v1",cpus=guest_vcpus,memory_mib=512,disks=disks,init="/counter",args=[])
        if system_image:parameters.update(boot_profile="system-debian-v1",init="/sbin/init",args=["--unit=multi-user.target","--log-target=console"])
        submit = dict(operation_id="launch-managed", request_digest=digest(json.dumps(parameters).encode()),
                      expected={k: before[k] for k in ("instance_id","incarnation_id","execution_epoch")},kind="launch",parameters=parameters)
        limits=rpc(worker,"QueryWorkerBudget")
        assert limits["allocated"]=={"vcpus":0,"memory_mib":0,"storage_bytes":0}
        if check_launch_rejections:
            expensive={**submit,"operation_id":"too-large","parameters":{**parameters,"memory_mib":4294967295}}
            try:http(endpoint,EXT+"/operations",expensive)
            except RuntimeError as error:assert "E_RESOURCE_LIMIT" in str(error)
            else:raise AssertionError("over-budget launch admitted")
            assert rpc(worker,"QueryWorkerBudget")["allocated"]==limits["allocated"]
        if product_volumes and check_launch_rejections:
            wrong_disks = [disks[0], {**disks[1], "device_id": "foreign-slot"}, disks[2]]
            wrong_slot = {**submit, "operation_id": "wrong-slot", "parameters": {**parameters, "disks": wrong_disks}}
            try:
                http(endpoint, EXT + "/operations", wrong_slot)
            except RuntimeError as error:
                assert "E_VOLUME_BUSY" in str(error), error
            else:
                raise AssertionError("another device slot consumed a volume reservation")
            foreign = http(endpoint, EXT + "/machines/foreign-guest/binding")
            wrong_binding = {**submit, "operation_id": "wrong-consumer",
                             "expected": {k: foreign[k] for k in ("instance_id", "incarnation_id", "execution_epoch")},
                             "parameters": {**parameters, "name": "foreign-guest"}}
            try:
                http(endpoint, EXT + "/operations", wrong_binding)
            except RuntimeError as error:
                assert "E_VOLUME_BUSY" in str(error), error
            else:
                raise AssertionError("another machine consumed a volume reservation")
        launch_started = time.monotonic_ns()
        original = http(endpoint, EXT+"/operations",submit)
        assert original["phase"] == "NEW"
        def final():
            try:
                v = http(endpoint, EXT+"/operations/launch-managed")
            except RuntimeError as err:
                if "E_RESOURCED_UNAVAILABLE" in str(err):return None
                raise
            if v["phase"]=="ABORTED":
                raise RuntimeError(v)
            return v if v["phase"]=="COMPLETED" else None
        def cleanup_vm():
            for dbfile in (root/"catalog").glob("*.sqlite*"):
                if dbfile.suffix not in (".sqlite",".sqlite3"):continue
                with suppress(Exception),sqlite3.connect(dbfile) as db:
                    for pid, start in db.execute("select pid,pid_start_time from executions"):
                        try: pidfd = os.pidfd_open(pid)
                        except ProcessLookupError: continue
                        try:
                            actual=int(Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[19])
                            if actual==start: signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                        finally:
                            os.close(pidfd)
        stack.callback(cleanup_vm)
        op = until(final,55)
        ref = http(endpoint,f"{EXT}/machines/{name}/execution")
        assert op["execution"]==ref and ref["execution_epoch"]==1
        assert http(endpoint, EXT+"/operations",submit)==op
        if check_launch_rejections:
            changed={**submit,"parameters":{**parameters,"memory_mib":768}}
            try: http(endpoint, EXT+"/operations",changed)
            except RuntimeError as err: assert "E_IDEMPOTENCY_CONFLICT" in str(err)
            else: raise AssertionError("mutated launch intent was accepted")
        inventory_url=f"{EXT}/instances/{ref['instance_id']}/inventory"
        record=http(endpoint, inventory_url)
        assert record["execution"]["uid"]>0
        heads=[d for d in record["inventory"]["devices"] if d.get("block")]
        assert len(heads)==3, heads
        if product_volumes:
            attached = [d["block"]["managed_attachment"] for d in heads[1:]]
            assert {d["volume_id"]: d["writable_head_id"] for d in attached} == wanted_heads, attached
            for volume in wanted_heads:
                actual = http(endpoint, EXT + "/volumes/" + volume + "?owner_id=volume-test")
                assert actual["attachments"][0]["state"] == "attached", actual
        logs=root/"state/managed"
        def guest_log():
            return (logs/(ref["incarnation_id"]+".log")).read_text(errors="replace")
        if system_image:
            agent=Path("/run/smolvm-custom/managed")/handshake["runtime_instance_id"]/ref["incarnation_id"]/"agent.sock"
            def system_pid():
                message=json.dumps({"method":"vm_exec","command":["/bin/cat","/proc/1/comm"]}).encode()
                try:
                    with socket.socket(socket.AF_UNIX) as conn:
                        conn.settimeout(1)
                        conn.connect(str(agent))
                        conn.sendall(struct.pack(">I",len(message))+message)
                        with conn.makefile("rb") as payload:
                            length=struct.unpack(">I",payload.read(4))[0]
                            response=json.loads(payload.read(length))
                            return base64.b64decode(response.get("stdout",""))==b"systemd\n"
                except (OSError,struct.error,ValueError):
                    return False
            until(system_pid,90)
            print("The managed Debian Guest Agent reported systemd as PID 1 over its incarnation-scoped socket.",flush=True)
        else:
            until(lambda:"PARKED_BLOCK_TICK " in guest_log(),20)
        if observer is not None:
            observer(endpoint, root, ref, record, launch_started)
            return
        serve.kill()
        serve.wait()
        serve=spawn(serve_command,"serve.log")
        until(lambda:http(endpoint,EXT+"/capabilities"))
        assert http(endpoint,EXT+"/operations",submit)==op and http(endpoint,inventory_url)["execution"]==record["execution"]
        assert rpc(worker,"QueryWorkerBudget")["allocated"]["vcpus"]==guest_vcpus
        if fork:
            names=["alpha-branch","beta-branch"]
            call=dict(operation_id="fork-counter-batch",request_digest=digest(b"counter-batch"),expected=ref,kind="fork_batch",parameters={"children":names})
            batch=http(endpoint,EXT+"/operations",call)
            assert batch["phase"]=="NEW" and len(batch["fork"]["children"])==2
            capture=batch["fork"]["capture_id"]
            latest={}
            def forked():
                nonlocal latest
                latest=http(endpoint,EXT+"/operations/"+call["operation_id"])
                progress=latest["fork"]
                if progress.get("error"):print("capture",progress["stage"],progress["error"],flush=True)
                assert progress["capture_id"]==capture and latest["phase"]!="ABORTED",latest
                return latest if latest["phase"]=="COMPLETED" else None
            try:finished=until(forked,150)
            except TimeoutError:raise AssertionError(latest)
            assert finished["fork"]["source_released"] and all(ch["phase"]=="COMPLETED" for ch in finished["fork"]["children"]),finished
            assert http(endpoint,EXT+"/operations",call)==finished
            source_ticks=[line.split() for line in guest_log().splitlines() if line.startswith("PARKED_BLOCK_TICK")]
            boundary=None
            machine_ids={source_ticks[0][4]}
            for child in finished["fork"]["children"]:
                file=logs/(child["incarnation_id"]+".log")
                def child_ticks():
                    if file.exists():
                        ticks=[line.split() for line in file.read_text(errors="replace").splitlines() if line.startswith("PARKED_BLOCK_TICK ")]
                        if len(ticks)>=2 and len(ticks[1])==7:return ticks[:2]
                first,fresh=until(child_ticks,20)
                marker=int(first[1])-1
                assert (int(first[5]),int(first[6]))==(marker,marker^0xbeef12349876),first
                boundary=boundary or first[1]
                assert first[1]==boundary,first
                # The held process can already have read its identity for the first tick.
                # The second iteration samples it again after the target gate opened.
                assert first[2]==fresh[2]==source_ticks[0][2] and int(fresh[1])==int(first[1])+1,(first,fresh)
                assert fresh[3]==child["name"] and fresh[4] not in machine_ids,fresh
                machine_ids.add(fresh[4])
            def fence_machine(vm_name):
                active=http(endpoint,f"{EXT}/machines/{vm_name}/execution")
                identity=http(endpoint,f"{EXT}/instances/{active['instance_id']}/inventory")["execution"]
                handle=os.pidfd_open(identity["pid"])
                try:
                    signal.pidfd_send_signal(handle,signal.SIGKILL)
                finally:
                    os.close(handle)
                until(lambda:http(endpoint,f"{EXT}/machines/{vm_name}/binding")["incarnation_id"] is None,20)
            def native(kind, source, key, parameters):
                request=dict(operation_id=key,request_digest=digest(key.encode()),expected=source,kind=kind,parameters=parameters)
                http(endpoint,EXT+"/operations",request)
                def observed():
                    result=http(endpoint,EXT+"/operations/"+key)
                    if result["phase"]=="ABORTED": raise AssertionError(result)
                    return result if result["phase"]=="COMPLETED" else None
                return until(observed,150)
            print("One held cut restored two distinct KVM children at the same RAM and two-writer boundary.",flush=True)
            fence_machine(name)
            assert http(endpoint,EXT+"/operations",call)==finished
            first_name,second_name=names
            first_ref=http(endpoint,f"{EXT}/machines/{first_name}/execution")
            native("standby",first_ref,"standby-branch-a",{"mode":"managed"})
            child_inv=f"{EXT}/instances/{first_ref['instance_id']}/inventory"
            assert http(endpoint,child_inv)["inventory"]["source_disposition"]=="STANDBY"
            descendant=native("independent_fork",first_ref,"fork-after-parent-exit",{"children":["grandchild"]})["fork"]
            assert descendant["original_source_disposition"]=="STANDBY" and descendant["source_released"]
            assert http(endpoint,child_inv)["inventory"]["source_disposition"]=="STANDBY"
            grandchild,=descendant["children"]
            assert grandchild["phase"]=="COMPLETED",grandchild
            logfile=logs/(grandchild["incarnation_id"]+".log")
            count=lambda:sum(line.startswith("PARKED_BLOCK_TICK ") for line in logfile.read_text(errors="replace").splitlines())
            until(lambda:logfile.exists() and count()>=1,20)
            fence_machine(first_name)
            fence_machine(second_name)
            prior=count()
            until(lambda:count()>prior+2,10)
            last=next(line for line in reversed(logfile.read_text(errors="replace").splitlines()) if line.startswith("PARKED_BLOCK_TICK ")).split()
            inherited=next(line for line in logfile.read_text(errors="replace").splitlines() if line.startswith("PARKED_BLOCK_TICK ")).split()
            inherited_marker=(int(inherited[1])-1)^(ord(first_name[0])<<48)
            assert (int(inherited[5]),int(inherited[6]))==(inherited_marker,inherited_marker^0xbeef12349876),inherited
            marker=(int(last[1])-1)^(ord("g")<<48)
            assert last[2]==source_ticks[0][2] and last[3]=="grandchild"
            assert (int(last[5]),int(last[6]))==(marker,marker^0xbeef12349876),last
            print("A parked child forked after its parent exited. The grandchild continued its captured process and both disks after fencing both ancestors and the sibling.",flush=True)
            if fork_faults or statepoint:
                grand_ref=http(endpoint,f"{EXT}/machines/grandchild/execution")
                if fork_faults:
                    partial_fork(endpoint,root,grand_ref)
                    if statepoint:fence_machine("partial-keep")
                if statepoint:durable_points(endpoint,grand_ref,"grandchild",logfile)
            return
        if lifecycle:
            import managed_lifecycle_checks
            managed_lifecycle_checks.verify(worker,bundle_id,endpoint,name,ref,rpc,http,EXT,until)
            return
        if statepoint:
            durable_points(endpoint,ref,name,logs/(ref["incarnation_id"]+".log"))
            return
        if not system_image:
            old=record["execution"]
            fd=os.pidfd_open(old["pid"])
            try:signal.pidfd_send_signal(fd,signal.SIGKILL)
            finally:os.close(fd)
            prior=until(lambda:(v if (v:=binding())["incarnation_id"] is None else None),20)
            assert prior["execution_epoch"]==1
            assert rpc(worker,"QueryWorkerBudget")["allocated"]==limits["allocated"]
            if product_volumes:
                stale = {**submit, "operation_id": "stale-cold-launch", "request_digest": digest(b"stale")}
                try:
                    http(endpoint, EXT + "/operations", stale)
                except RuntimeError as error:
                    assert "E_STALE_EXECUTION" in str(error), error
                else:
                    raise AssertionError("stale execution reopened the product writer")
            restarted={**submit,"operation_id":"restart-managed","request_digest":digest(b"restart"),
                       "expected":{k:prior[k] for k in ("instance_id","incarnation_id","execution_epoch")}}
            http(endpoint,EXT+"/operations",restarted)
            def second():
                value=http(endpoint,EXT+"/operations/restart-managed")
                assert value["phase"]!="ABORTED",value
                return value if value["phase"]=="COMPLETED" else None
            second_ref=until(second,55)["execution"]
            assert second_ref["execution_epoch"]==2 and second_ref["incarnation_id"]!=ref["incarnation_id"]
            new=http(endpoint,inventory_url)
            old_blocks=[d["block"]["managed_attachment"] for d in heads]
            new_blocks=[d["block"]["managed_attachment"] for d in new["inventory"]["devices"] if d.get("block")]
            for x,y in zip(old_blocks,new_blocks,strict=True):
                assert (x["volume_id"],x["writable_head_id"])==(y["volume_id"],y["writable_head_id"])
            if product_volumes:
                assert all(x["grant_id"] != y["grant_id"] for x, y in zip(old_blocks[1:], new_blocks[1:], strict=True))
                assert all(d["execution_epoch"] == 2 for d in new_blocks[1:])
                second_log = logs / (second_ref["incarnation_id"] + ".log")
                def persisted_write():
                    if not second_log.exists():
                        return False
                    for line in second_log.read_text(errors="replace").splitlines():
                        if "PARKED_BLOCK_TICK 1 " in line:
                            return all(int(x) != 0 for x in line.split()[-2:])
                    return False
                until(persisted_write, 20)
                print("Cold launch retained both real product heads and guest writes through the fenced restart. Wrong consumer, device slot and stale epoch were rejected.", flush=True)
            print("Fenced exit released the budget; a new epoch reopened the same independent writable heads.",flush=True)
        print(f"Managed launch {ref['incarnation_id']} on real KVM, UID {record['execution']['uid']}, three block attachments and two writers; private Serve restart and exact replay passed.", flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle",type=Path,required=True)
    parser.add_argument("--guest",type=Path,help="prebuilt static kvm-parked-block-guest test binary")
    parser.add_argument("--system-image",type=Path,help="managed Debian ext4 image containing the systemd Guest Agent service")
    parser.add_argument("--fork",action="store_true",help="fork a batch of two managed guests from one live capture")
    parser.add_argument("--product-volumes", action="store_true", help="open existing registered product disk heads")
    parser.add_argument("--lifecycle",action="store_true",help="verify Worker idle policy, leases, two-stage sleep and coalesced wake")
    parser.add_argument("--statepoint",action="store_true",help="checkpoint the guest and hibernate from managed standby")
    parser.add_argument("--fork-faults",action="store_true",help="kill one unpublished target and retry it from the original capture")
    args=parser.parse_args()
    if args.fork_faults: args.fork=True
    if os.geteuid()!=0:parser.error("requires root, KVM and systemd")
    if not os.environ.get("SMOLVM_MANAGED_TEST_ISOLATED"):
        args_for_child=["unshare","--mount","--propagation","private","--net","--",sys.executable,__file__,"--bundle",str(args.bundle.resolve())]
        for flag,path in (("--guest",args.guest),("--system-image",args.system_image)):
            if path:args_for_child.extend([flag,str(path.resolve())])
        for flag,enabled in (("--lifecycle",args.lifecycle),("--fork",args.fork),("--product-volumes",args.product_volumes),("--statepoint",args.statepoint),("--fork-faults",args.fork_faults)):
            if enabled:args_for_child.append(flag)
        os.execvpe("unshare",args_for_child,{**os.environ,"SMOLVM_MANAGED_TEST_ISOLATED":"1"})
    with tempfile.TemporaryDirectory(dir="/var/tmp",prefix="smm-") as tmp:
        root=Path(tmp)
        root.chmod(0o755)
        try: verify(args.bundle.resolve(),root,args.guest,args.system_image,args.fork,args.product_volumes,args.statepoint,args.fork_faults,args.lifecycle)
        except BaseException:
            for log in [root/"serve.log",root/"worker.log",*(root/"state/managed").glob("*.log")]:
                if log.exists():print(f"{log.name}\n{log.read_text(errors='replace')[-7000:]}",file=sys.stderr)
            raise


if __name__=="__main__":main()
