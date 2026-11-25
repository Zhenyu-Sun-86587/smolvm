ALTER TABLE executions ADD COLUMN launch_permit_digest TEXT;
CREATE UNIQUE INDEX active_execution_process ON executions(host_boot_id,pid,pid_start_time) WHERE phase!='exited';

CREATE TABLE fd_transfers (
    transfer_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL UNIQUE,
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    descriptor_json TEXT NOT NULL CHECK (json_valid(descriptor_json)),
    descriptor_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('staging','committed','aborted','lost','missing','collected'))
);

CREATE TABLE fd_transfer_batches (
    transfer_id TEXT NOT NULL REFERENCES fd_transfers(transfer_id),
    batch_index INTEGER NOT NULL CHECK (batch_index >= 0),
    identities_json TEXT NOT NULL CHECK (json_valid(identities_json)),
    PRIMARY KEY (transfer_id, batch_index)
);

CREATE TABLE fd_leases (
    lease_id TEXT PRIMARY KEY,
    resource_id TEXT NOT NULL REFERENCES resources(resource_id),
    incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    state TEXT NOT NULL CHECK (state IN ('pending','attached','unknown','released')),
    delivered INTEGER NOT NULL CHECK (delivered >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0)
);
CREATE INDEX fd_leases_by_resource ON fd_leases(resource_id,state);
CREATE INDEX fd_leases_by_execution ON fd_leases(incarnation_id,state);
