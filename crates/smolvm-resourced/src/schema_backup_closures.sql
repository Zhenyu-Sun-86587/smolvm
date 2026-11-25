CREATE TABLE native_backup_exports (
    backup_id TEXT PRIMARY KEY,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    selection_json TEXT NOT NULL CHECK (json_valid(selection_json)),
    manifest_json TEXT NOT NULL CHECK (json_valid(manifest_json)),
    phase TEXT NOT NULL CHECK (phase IN ('pinned','released'))
);
