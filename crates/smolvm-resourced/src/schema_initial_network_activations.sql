CREATE TABLE initial_network_activations (
    lease_id TEXT PRIMARY KEY REFERENCES network_tap_leases(lease_id),
    phase TEXT NOT NULL CHECK (phase IN ('opening','open','unknown'))
);
