CREATE TABLE IF NOT EXISTS network_overlay_source_fences (
    migration_id TEXT PRIMARY KEY,
    route_domain_id TEXT NOT NULL REFERENCES private_networks (route_domain_id),
    private_ipv4 INTEGER NOT NULL CHECK (private_ipv4 BETWEEN 0 AND 4294967295),
    source_incarnation_id TEXT NOT NULL,
    transfer_json TEXT NOT NULL CHECK (json_valid(transfer_json)),
    UNIQUE (route_domain_id, private_ipv4, source_incarnation_id)
) STRICT;

CREATE INDEX IF NOT EXISTS overlay_source_address_holds
    ON network_overlay_source_fences (route_domain_id, private_ipv4);

CREATE TABLE IF NOT EXISTS network_overlay_revisions (
    route_domain_id TEXT PRIMARY KEY REFERENCES private_networks (route_domain_id),
    revision INTEGER NOT NULL CHECK (revision > 0),
    digest TEXT NOT NULL CHECK (length(digest) = 64)
) STRICT;
