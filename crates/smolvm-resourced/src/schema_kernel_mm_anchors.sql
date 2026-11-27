ALTER TABLE managed_fork_batches ADD COLUMN
    memory_fork_backend TEXT NOT NULL DEFAULT 'native'
    CHECK (memory_fork_backend IN ('native','kernel_cow','auto'));
ALTER TABLE managed_fork_batches ADD COLUMN
    selected_memory_fork_backend TEXT NOT NULL DEFAULT 'native'
    CHECK (selected_memory_fork_backend IN ('native','kernel_cow'));

-- The resource graph owns pins and collection. This journal owns the
-- process identity for the typed descriptor, including incomplete launches.
CREATE TABLE kernel_mm_anchors (
    capture_id TEXT PRIMARY KEY REFERENCES managed_fork_batches(capture_id),
    operation_id TEXT UNIQUE NOT NULL REFERENCES operations(operation_id),
    source_incarnation TEXT NOT NULL REFERENCES executions(incarnation_id),
    source_epoch INTEGER NOT NULL,
    source_session INTEGER NOT NULL,
    host_boot_id TEXT NOT NULL,
    regions_json TEXT NOT NULL CHECK (json_valid(regions_json)),
    layout_digest TEXT NOT NULL,
    helper_id TEXT UNIQUE NOT NULL,
    helper_pid INTEGER NOT NULL CHECK (helper_pid > 0),
    helper_start INTEGER NOT NULL CHECK (helper_start > 0),
    executable_dev INTEGER NOT NULL,
    executable_ino INTEGER NOT NULL,
    resource_id TEXT UNIQUE REFERENCES resources(resource_id),
    failure TEXT
);

-- An import receipt belongs to the final VMM and commits alongside its
-- registration after the privileged bootstrap has released the donor pidfd.
CREATE TABLE kernel_cow_imports (
    incarnation_id TEXT PRIMARY KEY REFERENCES executions(incarnation_id),
    capture_id TEXT NOT NULL REFERENCES kernel_mm_anchors(capture_id),
    proof_digest TEXT NOT NULL
);
