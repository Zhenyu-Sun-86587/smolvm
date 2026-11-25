ALTER TABLE private_packet_wake_results ADD COLUMN datagram TEXT
    CHECK (datagram IN ('forwarded', 'dropped', 'unknown'));
