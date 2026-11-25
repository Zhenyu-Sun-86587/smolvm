ALTER TABLE managed_fork_batches ADD COLUMN admission_mode TEXT NOT NULL DEFAULT 'all_or_reject'
    CHECK (admission_mode IN ('all_or_reject','best_effort'));
ALTER TABLE managed_fork_children ADD COLUMN admission_error TEXT
    CHECK (admission_error IS NULL OR admission_error='E_RESOURCE_LIMIT');

CREATE TABLE native_provider_absence (
    resource_id TEXT NOT NULL REFERENCES resources(resource_id),
    incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    PRIMARY KEY(resource_id,incarnation_id)
);
