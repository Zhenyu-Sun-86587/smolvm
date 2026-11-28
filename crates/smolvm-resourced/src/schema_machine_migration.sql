CREATE TABLE IF NOT EXISTS machine_migrations (
    migration_id TEXT PRIMARY KEY,
    ticket_digest TEXT NOT NULL,
    ticket_json TEXT NOT NULL CHECK(json_valid(ticket_json)),
    side TEXT NOT NULL CHECK(side IN ('source','target')),
    instance_id TEXT NOT NULL,
    native_operation_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    parked_at_unix_ms INTEGER,
    decision_json TEXT CHECK(decision_json IS NULL OR json_valid(decision_json)),
    import_json TEXT CHECK(import_json IS NULL OR json_valid(import_json))
);
CREATE UNIQUE INDEX IF NOT EXISTS active_machine_migration ON machine_migrations (instance_id)
WHERE state NOT IN ('aborted','resumed','complete');
CREATE TABLE IF NOT EXISTS machine_migration_receipts (
    migration_id TEXT NOT NULL REFERENCES machine_migrations(migration_id),
    step TEXT NOT NULL,
    result TEXT NOT NULL CHECK(json_valid(result)),
    PRIMARY KEY(migration_id,step)
);

CREATE TRIGGER IF NOT EXISTS machine_migration_parked_time
AFTER UPDATE OF stage ON managed_fork_batches
WHEN NEW.stage IN ('holding','pivoting','exporting')
BEGIN
    UPDATE machine_migrations
    SET parked_at_unix_ms=cast((julianday('now')-2440587.5)*86400000 AS INTEGER)
    WHERE side='source' AND native_operation_id=NEW.operation_id AND parked_at_unix_ms IS NULL;
END;
