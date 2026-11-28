CREATE TABLE IF NOT EXISTS disk_backup_attempts (
    attempt_id TEXT PRIMARY KEY,
    intent_digest TEXT NOT NULL,
    native_operation_id TEXT UNIQUE REFERENCES operations(operation_id),
    selection_json TEXT CHECK (selection_json IS NULL OR json_valid(selection_json)),
    receipt_json TEXT CHECK (receipt_json IS NULL OR json_valid(receipt_json))
);

CREATE TABLE IF NOT EXISTS disk_backups (
    backup_id TEXT PRIMARY KEY,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    instance_id TEXT NOT NULL,
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch > 0),
    owner_epoch INTEGER NOT NULL CHECK (owner_epoch > 0),
    binding_generation INTEGER NOT NULL CHECK (binding_generation > 0),
    disks_json TEXT NOT NULL CHECK (json_valid(disks_json)),
    deleted INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1))
);
