CREATE TABLE network_tap_leases (
    lease_id TEXT PRIMARY KEY,
    attachment_id TEXT NOT NULL REFERENCES network_attachments(attachment_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    route_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    incarnation_id TEXT REFERENCES executions(incarnation_id),
    execution_epoch INTEGER,
    host_boot_id TEXT NOT NULL,
    broker_session_id TEXT NOT NULL,
    descriptor_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('quarantined','offered','attached','unknown','retired')),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    CHECK ((incarnation_id IS NULL) = (execution_epoch IS NULL)),
    CHECK (execution_epoch IS NULL OR execution_epoch > 0),
    CHECK (state IN ('quarantined','retired') OR incarnation_id IS NOT NULL)
);

CREATE UNIQUE INDEX one_owned_tap_lease
    ON network_tap_leases(attachment_id) WHERE state <> 'retired';
