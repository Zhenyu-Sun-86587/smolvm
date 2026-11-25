CREATE TABLE managed_state_restores (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    capture_id TEXT NOT NULL REFERENCES statepoints(capture_id),
    rescue_capture_id TEXT REFERENCES statepoints(capture_id),
    mode TEXT NOT NULL CHECK (mode IN ('exact','clone_conflicts')),
    volume_map_json TEXT NOT NULL CHECK (json_valid(volume_map_json)),
    frame_hex TEXT,
    error_code TEXT,
    error_message TEXT
);
