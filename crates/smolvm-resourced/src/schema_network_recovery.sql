CREATE TABLE network_kernel_receipts (
    lease_id TEXT PRIMARY KEY REFERENCES network_tap_leases(lease_id),
    published_revision INTEGER NOT NULL CHECK(published_revision >= 1),
    router_dev INTEGER NOT NULL,
    router_ino INTEGER NOT NULL,
    evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json)),
    adopted_session_id TEXT
);

CREATE INDEX network_kernel_receipts_by_router ON network_kernel_receipts(router_dev,router_ino);
