CREATE TABLE native_endpoints (
    incarnation_id TEXT PRIMARY KEY REFERENCES executions(incarnation_id),
    control_socket TEXT NOT NULL,
    executable_dev INTEGER NOT NULL,
    executable_ino INTEGER NOT NULL
);

CREATE TABLE native_transitions (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    incarnation_id TEXT NOT NULL REFERENCES native_endpoints(incarnation_id),
    mode TEXT NOT NULL CHECK (mode IN ('raw','managed')),
    session INTEGER NOT NULL CHECK (session BETWEEN 1 AND 4294967295),
    token TEXT NOT NULL CHECK(length(token)=32),
    anchor TEXT NOT NULL CHECK(length(anchor)=32),
    network_gate INTEGER NOT NULL CHECK(network_gate IN (0,1)),
    stage TEXT NOT NULL CHECK(stage IN ('accepted','preparing','parking','entering','waking','aborting','complete','aborted')),
    disposition TEXT NOT NULL,
    last_error TEXT
);
CREATE INDEX native_pending ON native_transitions(stage);

-- Only a confirmed native standby can supply the challenge used for wake.
CREATE TABLE native_standby (
    incarnation_id TEXT PRIMARY KEY REFERENCES native_endpoints(incarnation_id),
    operation_id TEXT NOT NULL UNIQUE REFERENCES native_transitions(operation_id)
);
