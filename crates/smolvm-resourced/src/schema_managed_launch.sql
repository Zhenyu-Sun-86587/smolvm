CREATE TABLE managed_launches (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    incarnation_id TEXT NOT NULL UNIQUE,
    serve_instance TEXT NOT NULL,
    machine_name TEXT NOT NULL,
    spec_json TEXT NOT NULL CHECK(json_valid(spec_json)),
    devices_json TEXT NOT NULL CHECK(json_valid(devices_json)),
    vcpus INTEGER NOT NULL CHECK(vcpus > 0),
    memory_mib INTEGER NOT NULL CHECK(memory_mib > 0),
    claim_boot TEXT,
    claim_pid INTEGER,
    claim_start INTEGER,
    disks_attached INTEGER NOT NULL DEFAULT 0 CHECK(disks_attached IN (0,1))
);
CREATE INDEX managed_launch_dispatch ON managed_launches(serve_instance, operation_id);

CREATE TABLE managed_budget_holds (
    instance_id TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    incarnation_id TEXT,
    vcpus INTEGER NOT NULL CHECK(vcpus>0),
    memory_mib INTEGER NOT NULL CHECK(memory_mib>0),
    storage_bytes INTEGER NOT NULL CHECK(storage_bytes>=0),
    state TEXT NOT NULL CHECK(state IN ('reserved','running','released')),
    PRIMARY KEY(operation_id,instance_id)
);
CREATE UNIQUE INDEX managed_budget_instance ON managed_budget_holds(instance_id)
    WHERE state!='released';
