"""Exercise Worker lifecycle decisions against the counter KVM and all three collector scopes."""
import hashlib
import time


def verify(worker, bundle, endpoint, name, original, rpc, http, base, until):
    current = original.copy()
    serial = 0
    def call(method, body, expected=None, key=None):
        nonlocal serial
        serial += 1
        op = key or f"lifecycle-check-{serial}"
        return rpc(worker, method, body, route_id="deep", bundle_digest=bundle, expected=expected or current,
                   operation_id=op, request_digest="sha256:"+hashlib.sha256(op.encode()).hexdigest())

    def status():
        return call("GetLifecycleStatus", {})
    def binding():
        raw = http(endpoint, f"{base}/machines/{name}/binding")
        return {k:raw[k] for k in original}
    def protection(method, ident, principal="operator", **kwargs):
        return call(method,dict(protection_id=ident,principal=principal,**kwargs))
    def facts(collector, **counts):
        return call("ReportActivity",{"collector":collector,"seq":serial+1,"session":"first-"+collector,"valid_for_ms":5000,"counts":counts})

    policy={"auto_standby":True,"standby_after_seconds":4,"auto_hibernate":True,"hibernate_after_seconds":19,
            "min_running_after_wake_seconds":1,"retry_backoff_seconds":2}
    applied=call("ApplyLifecyclePolicy",{"effective_policy":policy,"expected_applied_revision":0,"new_revision":1})
    assert applied["applied_revision"]==1 and "unknown:guest" in status()["blockers"]
    token="lease-secret-which-is-not-copied-to-the-child"
    one=protection("AcquireRunningLease","legacy",semantics_version=1,ttl_seconds=1,token=token)
    two=protection("AcquireRunningLease","bounded",semantics_version=2,ttl_seconds=1,token=token)
    def read(key):return protection("QueryProtection",key)
    until(lambda:read("legacy")["state"]=="suspect" and read("bounded")["state"]=="released",8)
    one=read("legacy");protection("ReleaseRunningLease","legacy",expected_revision=one["revision"],token=token)
    blockers=status()["blockers"]
    assert any("unknown" in b for b in blockers),blockers
    h=protection("AcquireActivityHold","ssh",reason="open SSH session")
    until(lambda:any("SSH" in b for b in status()["blockers"]),3)
    protection("ReleaseActivityHold","ssh",expected_revision=h["revision"])
    print("Worker kept an expired v1 lease suspect, expired the v2 lease, and blocked sleep on unknown collectors and an open SSH hold.",flush=True)

    def host():
        facts("host",inbound=0,outbound=0)
        facts("platform",task=0,exec=0,stream=0)
    def busy():
        facts("guest",task=0,exec=0,inbound=0,outbound=1)
        host()
    end=time.monotonic()+6
    while time.monotonic()<end:
        busy()
        assert status()["power"]=="RUNNING"
        time.sleep(.5)
    last_guest=None
    last=None
    def hibernated():
        nonlocal last_guest,last
        ref=binding()
        if ref["incarnation_id"] is None:
            last=status()
            return last["power"]=="HIBERNATED"
        last=status()
        if last["power"]=="RUNNING":
            facts("guest",task=0,exec=0,inbound=0,outbound=0)
            last_guest=time.monotonic()
        if last["power"]=="STANDBY" and "operation_in_progress" not in last["blockers"]:
            assert last["controlled_suspended"],last
        host()
        return False
    try: until(hibernated,90)
    except TimeoutError: raise AssertionError(last)
    assert last_guest and time.monotonic()-last_guest>5,last
    print("A live outbound request protected the idle-CPU guest. Fresh zero activity led to native Standby, then Hibernate after guest reporting had stopped for longer than its TTL.",flush=True)
    current=binding()
    revision=status()["binding_revision"]
    for key in ("wake-a","wake-b"):
        protection("RequestWake",key,expected_binding_revision=revision,trigger="api_access",authorization_revision=1,endpoint_revision=1)
    current=until(lambda:(b if (b:=binding())["incarnation_id"] and b["execution_epoch"]>original["execution_epoch"] else None),90)
    data=until(lambda:(s if (s:=status())["power"]=="RUNNING" and (s.get("last_decision") or {}).get("stage")=="completed" else None),30)
    a,b=read("wake-a"),read("wake-b")
    assert a["wake_operation"]==b["wake_operation"] and a["wake_operation"]==data["last_decision"]["operation_id"],(a,b,data)
    result=protection("AuthorizeWakeActivation","wake-a",wake_operation=a["wake_operation"],authorized=True,expected_revision=a["revision"],authorization_revision=2,endpoint_revision=1)
    denied=protection("AuthorizeWakeActivation","wake-b",wake_operation=b["wake_operation"],authorized=False,expected_revision=b["revision"],authorization_revision=2,endpoint_revision=1)
    assert result["kind"]=="hold" and result["incarnation_id"]==current["incarnation_id"] and denied["state"]=="released"
    print("Two offline wake demands shared one exact restore. Reauthorization handed the accepted request to the new execution and dropped the revoked request.",flush=True)
