CREATE TABLE private_packet_wake_rules (
    id TEXT PRIMARY KEY,
    source_attachment TEXT NOT NULL REFERENCES network_attachments,
    target_attachment TEXT NOT NULL REFERENCES network_attachments,
    transport TEXT NOT NULL CHECK (transport IN ('tcp','udp')),
    guest_port INTEGER NOT NULL CHECK (guest_port BETWEEN 1 AND 65535),
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    revision INTEGER NOT NULL CHECK (revision > 0),
    source_incarnation TEXT REFERENCES executions,
    source_epoch INTEGER,
    source_lease TEXT REFERENCES network_tap_leases,
    source_lease_revision INTEGER,
    enabled_since_ns INTEGER NOT NULL,
    mutation_id TEXT NOT NULL,
    mutation_digest TEXT NOT NULL,
    UNIQUE (source_attachment,target_attachment,transport,guest_port),
    CHECK (source_attachment<>target_attachment),
    CHECK (enabled=0 OR (source_incarnation IS NOT NULL AND source_epoch>0 AND source_lease IS NOT NULL AND source_lease_revision>0))
);
CREATE INDEX active_private_packet_wake_rules ON private_packet_wake_rules(source_attachment) WHERE enabled=1;

CREATE TABLE private_packet_wake_demands (
    instance_id TEXT PRIMARY KEY,
    protection_id TEXT NOT NULL,
    rule_id TEXT NOT NULL REFERENCES private_packet_wake_rules,
    rule_revision INTEGER NOT NULL,
    policy_revision INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (instance_id, protection_id) REFERENCES lifecycle_protections(instance_id,id) ON DELETE CASCADE
);

CREATE TABLE private_packet_wake_limits (
    instance_id TEXT PRIMARY KEY REFERENCES lifecycle_policies,
    next_request_at INTEGER NOT NULL
);

CREATE TABLE private_packet_wake_results (
    rule_id TEXT PRIMARY KEY REFERENCES private_packet_wake_rules,
    operation_id TEXT NOT NULL REFERENCES lifecycle_decisions,
    rule_revision INTEGER NOT NULL,
    target_epoch INTEGER NOT NULL,
    authorized INTEGER NOT NULL CHECK (authorized IN (0,1))
);
