CREATE TABLE IF NOT EXISTS bucket_block_bases (
    resource_id TEXT NOT NULL REFERENCES managed_blocks(resource_id) ON DELETE CASCADE,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    closure_digest TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    member_digest TEXT NOT NULL,
    member_bytes INTEGER NOT NULL CHECK (member_bytes > 0),
    broker_socket TEXT NOT NULL,
    PRIMARY KEY (resource_id, bundle_digest)
) STRICT;
