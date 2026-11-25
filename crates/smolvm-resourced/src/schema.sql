CREATE TABLE worker_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    host_boot_id TEXT NOT NULL,
    broker_session_id TEXT NOT NULL,
    recovering INTEGER NOT NULL CHECK (recovering IN (0, 1))
);

CREATE TABLE runtime_bundles (
    bundle_digest TEXT PRIMARY KEY,
    executable_sha256 TEXT NOT NULL,
    protocol_major INTEGER NOT NULL CHECK (protocol_major = 1)
);

CREATE TABLE instance_bindings (
    route_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch >= 0),
    incarnation_id TEXT REFERENCES executions(incarnation_id),
    active_operation_id TEXT REFERENCES operations(operation_id),
    PRIMARY KEY (route_id, instance_id)
);

CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    route_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    expected_execution_epoch INTEGER NOT NULL CHECK (expected_execution_epoch >= 0),
    expected_incarnation_id TEXT,
    phase TEXT NOT NULL CHECK (phase IN ('NEW','COMPLETED','ABORTED')),
    decision TEXT NOT NULL CHECK (decision IN ('NONE','ABORT')),
    revision INTEGER NOT NULL CHECK (revision > 0)
);

CREATE TABLE executions (
    incarnation_id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch > 0),
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    host_boot_id TEXT NOT NULL,
    pid INTEGER NOT NULL CHECK (pid > 0),
    pid_start_time INTEGER NOT NULL CHECK (pid_start_time > 0),
    uid INTEGER NOT NULL CHECK (uid >= 0),
    phase TEXT NOT NULL CHECK (phase IN ('registered','unknown','exited')),
    last_operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    UNIQUE (route_id, instance_id, execution_epoch)
);

CREATE TABLE resources (
    resource_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('descriptor','block_head')),
    state TEXT NOT NULL CHECK (state IN ('available','lost','deleting','deleted')),
    durability TEXT NOT NULL CHECK (durability IN ('volatile','durable')),
    immutable INTEGER NOT NULL CHECK (immutable IN (0,1)),
    descriptor_json TEXT NOT NULL CHECK (json_valid(descriptor_json)),
    descriptor_digest TEXT NOT NULL,
    created_by_operation TEXT NOT NULL REFERENCES operations(operation_id),
    revision INTEGER NOT NULL CHECK (revision > 0)
);

CREATE TABLE resource_edges (
    owner_resource_id TEXT NOT NULL REFERENCES resources(resource_id),
    child_resource_id TEXT NOT NULL REFERENCES resources(resource_id),
    role TEXT NOT NULL,
    PRIMARY KEY (owner_resource_id, child_resource_id, role)
);
CREATE INDEX edges_by_child ON resource_edges(child_resource_id);

CREATE TABLE root_refs (
    owner_kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    resource_id TEXT NOT NULL REFERENCES resources(resource_id),
    state TEXT NOT NULL CHECK (state IN ('active','dropped')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_by_operation TEXT NOT NULL REFERENCES operations(operation_id),
    PRIMARY KEY (owner_kind, owner_id, resource_id)
);
CREATE INDEX roots_by_resource ON root_refs(resource_id, state);

CREATE TABLE volume_heads (
    volume_id TEXT PRIMARY KEY,
    head_resource_id TEXT NOT NULL REFERENCES resources(resource_id),
    backing_identity TEXT NOT NULL
);

-- A reservation holds broker-owned OFD locks. No VMM writer FD is issued by
-- this schema. Imported writer grants must use a separate catalog transition.
CREATE TABLE writer_sets (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    heads_json TEXT NOT NULL CHECK (json_valid(heads_json)),
    state TEXT NOT NULL CHECK (state IN ('reserved','released')),
    revision INTEGER NOT NULL CHECK (revision > 0)
);

CREATE TABLE writer_reservations (
    volume_id TEXT PRIMARY KEY REFERENCES volume_heads(volume_id),
    head_resource_id TEXT NOT NULL REFERENCES resources(resource_id),
    backing_identity TEXT NOT NULL UNIQUE,
    operation_id TEXT NOT NULL REFERENCES writer_sets(operation_id),
    incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch > 0)
);
CREATE INDEX writer_reservation_set ON writer_reservations(operation_id);
