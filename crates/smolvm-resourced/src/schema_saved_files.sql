CREATE TABLE IF NOT EXISTS saved_file_mounts (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    mountinfo BLOB CHECK (length(mountinfo) <= 24576)
) STRICT;
