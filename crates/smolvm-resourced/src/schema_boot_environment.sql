CREATE TABLE IF NOT EXISTS boot_environment_attempts (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id) ON DELETE CASCADE,
    catalog_revision INTEGER NOT NULL CHECK(catalog_revision >= 0),
    machine_revision INTEGER NOT NULL CHECK(machine_revision > 0),
    expires_ms INTEGER NOT NULL CHECK(expires_ms > 0),
    commitment TEXT NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0 CHECK(applied IN (0,1))
);
