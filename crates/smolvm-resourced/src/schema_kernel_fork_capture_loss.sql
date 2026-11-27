ALTER TABLE managed_fork_children ADD COLUMN capture_lost INTEGER NOT NULL DEFAULT 0
    CHECK (capture_lost IN (0, 1) AND (capture_lost=0 OR (cancelled=0 AND admission_error IS NULL)));
