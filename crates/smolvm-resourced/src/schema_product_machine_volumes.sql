CREATE TABLE product_machine_volumes (
    volume_id TEXT PRIMARY KEY REFERENCES product_volumes(volume_id),
    instance_id TEXT
);

CREATE INDEX product_machine_volume_owner ON product_machine_volumes(instance_id);
