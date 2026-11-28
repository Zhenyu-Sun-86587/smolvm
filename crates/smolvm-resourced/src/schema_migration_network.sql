CREATE TABLE IF NOT EXISTS machine_migration_network_intents (
    migration_id TEXT PRIMARY KEY REFERENCES machine_migrations(migration_id),
    intent_json TEXT NOT NULL CHECK (json_valid(intent_json))
) STRICT;

CREATE TABLE IF NOT EXISTS machine_migration_source_taps (
    migration_id TEXT PRIMARY KEY REFERENCES machine_migrations(migration_id),
    lease_id TEXT NOT NULL REFERENCES network_tap_leases(lease_id),
    lease_revision INTEGER NOT NULL CHECK (lease_revision > 0),
    transfer_json TEXT NOT NULL CHECK (json_valid(transfer_json)),
    kernel_scope_json TEXT NOT NULL CHECK (json_valid(kernel_scope_json)),
    phase TEXT NOT NULL CHECK (phase IN ('closing','closed','reopening','reopened'))
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS active_migration_source_tap ON machine_migration_source_taps(lease_id)
WHERE phase <> 'reopened';
