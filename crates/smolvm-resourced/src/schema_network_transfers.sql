CREATE TABLE IF NOT EXISTS network_transfers (
    migration_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE REFERENCES operations(operation_id),
    intent_json TEXT NOT NULL CHECK (json_valid(intent_json)),
    decision_json TEXT CHECK (decision_json IS NULL OR json_valid(decision_json)),
    phase TEXT NOT NULL CHECK (phase IN ('prepared','committed','aborted'))
) STRICT;

CREATE TABLE IF NOT EXISTS network_transfer_guards (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    attachment_id TEXT NOT NULL REFERENCES network_attachments(attachment_id),
    migration_id TEXT NOT NULL UNIQUE
) STRICT;
