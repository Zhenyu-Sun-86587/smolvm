CREATE TABLE managed_cpu_limits (
    instance_id TEXT PRIMARY KEY,
    millicpus INTEGER NOT NULL CHECK (millicpus BETWEEN 1 AND 4294967295)
);

CREATE TABLE managed_cpu_limit_operations (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    millicpus INTEGER CHECK (millicpus BETWEEN 1 AND 4294967295),
    previous_quota_usec INTEGER CHECK (previous_quota_usec > 0),
    previous_period_usec INTEGER NOT NULL CHECK (previous_period_usec BETWEEN 1000 AND 1000000),
    quota_usec INTEGER CHECK (quota_usec > 0),
    period_usec INTEGER CHECK (period_usec BETWEEN 1000 AND 1000000),
    rejection TEXT CHECK (rejection IN ('execution_exited', 'controller_rejected')),
    CHECK ((quota_usec IS NULL) = (period_usec IS NULL)),
    CHECK (rejection IS NULL OR quota_usec IS NULL)
);
