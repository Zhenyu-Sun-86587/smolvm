CREATE TABLE IF NOT EXISTS network_memberships (
    instance_id TEXT PRIMARY KEY,
    policy_revision INTEGER NOT NULL CHECK (policy_revision >= 2),
    networks TEXT NOT NULL CHECK (json_valid(networks) AND json_type(networks) = 'array')
) STRICT;
