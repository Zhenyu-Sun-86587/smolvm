CREATE TABLE native_resource_changes (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    intent_json TEXT NOT NULL CHECK (json_valid(intent_json)),
    stage TEXT NOT NULL CHECK (stage IN ('queued','waiting','restoring','completed','aborted')),
    observed_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(observed_json)),
    error_code TEXT,
    error TEXT,
    deadline_ms INTEGER NOT NULL,
    next_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX pending_native_resource_changes ON native_resource_changes(next_ms)
    WHERE stage IN ('queued','waiting','restoring');

CREATE TABLE native_pressure_balloon (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    host_boot_id TEXT NOT NULL,
    pressure_since_ms INTEGER NOT NULL,
    decision_id TEXT NOT NULL REFERENCES lifecycle_decisions(id),
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json))
);
