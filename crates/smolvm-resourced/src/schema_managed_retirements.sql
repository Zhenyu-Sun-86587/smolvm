CREATE TABLE managed_retirements (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    stop_operation_id TEXT REFERENCES native_stop_commits(operation_id),
    private_heads_json TEXT NOT NULL CHECK(json_valid(private_heads_json))
);

CREATE UNIQUE INDEX retired_instance_scope ON operations(route_id, instance_id)
    WHERE kind='retire_instance' AND phase='COMPLETED';

CREATE TABLE retired_instance_blocks (
    resource_id TEXT PRIMARY KEY REFERENCES resources(resource_id),
    operation_id TEXT NOT NULL REFERENCES managed_retirements(operation_id)
);
