CREATE TABLE IF NOT EXISTS statepoints (
    capture_id TEXT PRIMARY KEY,
    representation_id TEXT NOT NULL UNIQUE,
    volatile_id TEXT NOT NULL UNIQUE REFERENCES resources(resource_id),
    operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
    source_incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    export_json TEXT NOT NULL CHECK (json_valid(export_json)),
    point_json TEXT NOT NULL CHECK (json_valid(point_json)),
    phase TEXT NOT NULL CHECK (phase IN ('exporting','durable','stop_committed','hibernated','aborted')),
    manifest_digest TEXT,
    restore_capture_id TEXT REFERENCES statepoints(capture_id),
    error TEXT,
    revision INTEGER NOT NULL CHECK (revision > 0)
);

CREATE INDEX IF NOT EXISTS statepoint_pending_stop ON statepoints(phase,source_incarnation_id)
    WHERE phase='stop_committed';

CREATE TABLE IF NOT EXISTS statepoint_restore_leases (
    lease_id TEXT PRIMARY KEY REFERENCES fd_leases(lease_id),
    capture_id TEXT NOT NULL REFERENCES statepoints(capture_id),
    volume_policy TEXT NOT NULL CHECK (volume_policy IN ('exact','clone_conflicts'))
);
