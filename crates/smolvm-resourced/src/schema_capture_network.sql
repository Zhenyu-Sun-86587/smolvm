CREATE TABLE capture_network_attestations (
    resource_id TEXT PRIMARY KEY REFERENCES resources(resource_id),
    source_incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    source_execution_epoch INTEGER NOT NULL CHECK(source_execution_epoch > 0),
    capture_digest TEXT NOT NULL,
    bound_tap_json TEXT CHECK(bound_tap_json IS NULL OR json_valid(bound_tap_json))
);
