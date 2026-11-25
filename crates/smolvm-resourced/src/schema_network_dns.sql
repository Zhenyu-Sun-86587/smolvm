CREATE TABLE network_dns_names (
    attachment_id TEXT PRIMARY KEY REFERENCES network_attachments(attachment_id),
    network_id TEXT NOT NULL REFERENCES private_networks(network_id),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 3 AND 253),
    UNIQUE(network_id, name)
);

CREATE TRIGGER delete_dns_name_after_network_release
AFTER UPDATE OF state ON network_attachments WHEN NEW.state = 'released' AND OLD.state <> 'released'
BEGIN
    DELETE FROM network_dns_names WHERE attachment_id = NEW.attachment_id;
END;
