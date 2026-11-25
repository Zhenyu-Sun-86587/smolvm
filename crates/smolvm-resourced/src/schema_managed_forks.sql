CREATE TABLE managed_fork_batches (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    source_incarnation TEXT NOT NULL REFERENCES executions(incarnation_id),
    serve_instance TEXT NOT NULL,
    capture_id TEXT UNIQUE NOT NULL,
    template TEXT NOT NULL CHECK(json_valid(template)),
    children TEXT NOT NULL CHECK(json_valid(children)),
    session INTEGER NOT NULL,
    token TEXT NOT NULL,
    anchor TEXT NOT NULL,
    network_gate INTEGER NOT NULL,
    original TEXT NOT NULL CHECK(original IN ('RUNNING','STANDBY')),
    stage TEXT NOT NULL,
    pivot_json TEXT CHECK(json_valid(pivot_json)),
    disk_json TEXT CHECK(json_valid(disk_json)),
    checkpoint BLOB,
    helper_digest TEXT,
    error TEXT,
    source_released INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    restore_capture_id TEXT
);
CREATE TABLE managed_fork_children (
    batch_id TEXT NOT NULL REFERENCES managed_fork_batches(operation_id),
    ordinal INTEGER NOT NULL,
    name TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    prior_epoch INTEGER NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0,
    cancelled INTEGER NOT NULL DEFAULT 0,
    frame_hex TEXT,
    PRIMARY KEY(batch_id,ordinal)
);
CREATE TABLE managed_fork_retries (
    batch_id TEXT NOT NULL REFERENCES managed_fork_batches(operation_id),
    prior_revision INTEGER NOT NULL,
    PRIMARY KEY(batch_id,prior_revision)
);
