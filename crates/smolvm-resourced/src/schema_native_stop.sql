-- An exact managed stop can exit the VMM only after its stop cut is durable.
CREATE TABLE native_stop_commits (
    operation_id TEXT PRIMARY KEY REFERENCES native_transitions(operation_id)
);
