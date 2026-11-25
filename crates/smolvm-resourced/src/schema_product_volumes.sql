CREATE TABLE IF NOT EXISTS product_volumes (
    volume_id TEXT PRIMARY KEY,
    route_id TEXT NOT NULL,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles(bundle_digest),
    owner_id TEXT NOT NULL,
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('persistent','ephemeral')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    state TEXT NOT NULL CHECK (state IN ('available','deleted'))
);

CREATE TRIGGER IF NOT EXISTS product_volume_head_advance AFTER UPDATE OF head_resource_id ON volume_heads
WHEN OLD.head_resource_id<>NEW.head_resource_id
BEGIN
    UPDATE product_volumes SET revision=revision+1 WHERE volume_id=NEW.volume_id;
END;

CREATE TABLE IF NOT EXISTS product_volume_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    volume_id TEXT NOT NULL REFERENCES product_volumes(volume_id),
    generation_id TEXT NOT NULL REFERENCES resources(resource_id),
    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
    capacity_bytes INTEGER NOT NULL CHECK (capacity_bytes > 0),
    state TEXT NOT NULL CHECK (state IN ('available','deleted'))
);

CREATE TABLE IF NOT EXISTS product_volume_attachments (
    attachment_id TEXT PRIMARY KEY,
    volume_id TEXT NOT NULL REFERENCES product_volumes(volume_id),
    instance_id TEXT NOT NULL,
    device_key TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('rw','ro')),
    generation_id TEXT REFERENCES resources(resource_id),
    fork_policy TEXT NOT NULL CHECK (fork_policy IN ('clone','share_immutable','reject')),
    capture_policy TEXT NOT NULL CHECK (capture_policy IN ('include','external')),
    declared_epoch INTEGER NOT NULL CHECK (declared_epoch >= 0),
    state TEXT NOT NULL CHECK (state IN ('reserved','detached')),
    revision INTEGER NOT NULL CHECK (revision > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS product_volume_unique_rw ON product_volume_attachments(volume_id)
    WHERE state='reserved' AND mode='rw';
CREATE UNIQUE INDEX IF NOT EXISTS product_volume_unique_slot ON product_volume_attachments(instance_id,device_key)
    WHERE state='reserved';

CREATE TABLE IF NOT EXISTS product_volume_operations (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    volume_id TEXT NOT NULL,
    command_json TEXT NOT NULL CHECK (json_valid(command_json)),
    prior_head TEXT,
    prior_capacity INTEGER,
    result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json))
);
