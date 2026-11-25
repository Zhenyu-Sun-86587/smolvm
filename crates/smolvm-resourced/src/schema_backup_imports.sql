CREATE TABLE native_backup_imports (
    capture_id TEXT PRIMARY KEY REFERENCES statepoints(capture_id),
    backup_id TEXT NOT NULL,
    state_reader_id TEXT NOT NULL,
    hold_token_digest TEXT NOT NULL
);
