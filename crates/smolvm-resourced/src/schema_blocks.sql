CREATE TABLE managed_blocks (
    resource_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    spec_json TEXT NOT NULL CHECK (json_valid(spec_json)),
    backing_identity TEXT UNIQUE
);

CREATE TABLE writer_grants (
    grant_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE REFERENCES writer_sets(operation_id),
    incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch > 0),
    state TEXT NOT NULL CHECK (state IN ('offered','attached','unknown','released')),
    revision INTEGER NOT NULL CHECK (revision > 0)
);
CREATE UNIQUE INDEX writer_grants_one_live_set ON writer_grants(incarnation_id) WHERE state!='released';
