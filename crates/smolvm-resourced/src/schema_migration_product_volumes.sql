CREATE TABLE IF NOT EXISTS migration_product_volumes (
    migration_id TEXT NOT NULL REFERENCES machine_migrations(migration_id),
    volume_id TEXT NOT NULL,
    metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
    PRIMARY KEY (migration_id,volume_id)
);
CREATE INDEX IF NOT EXISTS migration_product_volume_owner ON migration_product_volumes(volume_id,migration_id);
