CREATE TABLE IF NOT EXISTS bucket_machine_storage (
    instance_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    backend TEXT NOT NULL CHECK(backend IN ('file','bucket')),
    remote_commit TEXT CHECK(remote_commit IS NULL OR json_valid(remote_commit)),
    PRIMARY KEY(instance_id,bundle_digest)
);

CREATE TABLE IF NOT EXISTS bucket_storage_attempts (
    attempt_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    expected_json TEXT NOT NULL CHECK(json_valid(expected_json)),
    target TEXT NOT NULL CHECK(target IN ('file','bucket','sync','automatic')),
    phase TEXT NOT NULL CHECK(phase IN ('capture','upload','activate','ready','failed')),
    generation_ids TEXT CHECK(generation_ids IS NULL OR json_valid(generation_ids)),
    remote_commit TEXT CHECK(remote_commit IS NULL OR json_valid(remote_commit)),
    receipt TEXT CHECK(receipt IS NULL OR json_valid(receipt)),
    retry_at INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS bucket_explicit_attempt ON bucket_storage_attempts(instance_id,bundle_digest)
    WHERE target<>'automatic' AND phase NOT IN ('ready','failed');

CREATE TABLE IF NOT EXISTS bucket_online_bases (
    resource_id TEXT NOT NULL REFERENCES managed_blocks(resource_id) ON DELETE CASCADE,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    reference_json TEXT NOT NULL CHECK(json_valid(reference_json)),
    member_bytes INTEGER NOT NULL CHECK(member_bytes>0),
    PRIMARY KEY(resource_id,bundle_digest)
);
