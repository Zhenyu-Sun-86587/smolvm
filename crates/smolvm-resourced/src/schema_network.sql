CREATE TABLE private_networks (
    network_id TEXT PRIMARY KEY,
    route_domain_id TEXT NOT NULL UNIQUE,
    cidr TEXT NOT NULL,
    gateway_ipv4 INTEGER NOT NULL,
    first_ipv4 INTEGER NOT NULL CHECK (first_ipv4 > gateway_ipv4),
    last_ipv4 INTEGER NOT NULL CHECK (last_ipv4 >= first_ipv4)
);

CREATE TABLE network_attachments (
    attachment_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL REFERENCES operations (operation_id),
    route_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    network_id TEXT NOT NULL REFERENCES private_networks (network_id),
    device_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('native', 'fixed_internal')),
    private_ipv4 INTEGER NOT NULL,
    guest_ipv4 INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('reserved', 'unknown', 'released')),
    revision INTEGER NOT NULL CHECK (revision >= 1)
);

CREATE UNIQUE INDEX network_private_address_owned
    ON network_attachments(network_id, private_ipv4) WHERE state <> 'released';
CREATE UNIQUE INDEX network_device_owned
    ON network_attachments(route_id, instance_id, device_id) WHERE state <> 'released';
