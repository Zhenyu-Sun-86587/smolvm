CREATE TABLE verified_block_backings (
    resource_id TEXT PRIMARY KEY REFERENCES managed_blocks(resource_id) ON DELETE CASCADE,
    legacy_identity TEXT NOT NULL,
    durable_identity TEXT NOT NULL UNIQUE
);
