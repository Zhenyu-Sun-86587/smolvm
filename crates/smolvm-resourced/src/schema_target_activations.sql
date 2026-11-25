CREATE TABLE target_activations (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    bundle_digest TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    execution_epoch INTEGER NOT NULL CHECK(execution_epoch > 0),
    broker_session_id TEXT NOT NULL,
    host_boot_id TEXT NOT NULL,
    context_digest TEXT NOT NULL UNIQUE CHECK(length(context_digest)=64),
    challenge TEXT NOT NULL CHECK(length(challenge)=32),
    binding_json TEXT NOT NULL CHECK(json_valid(binding_json)),
    wire_digest TEXT,
    begin_revision INTEGER CHECK(begin_revision >= 1),
    commit_revision INTEGER CHECK(commit_revision >= 1),
    phase TEXT NOT NULL CHECK(phase IN
        ('authority_prepared','offered','applying','identity_ready','committing','policy_armed','released','failed_held','unknown')),
    decision TEXT NOT NULL CHECK(decision IN ('none','commit')),
    prior_revision INTEGER NOT NULL CHECK(prior_revision >= 0),
    revision INTEGER NOT NULL CHECK(revision >= 1)
);

CREATE UNIQUE INDEX one_live_target_activation
    ON target_activations(incarnation_id,execution_epoch)
    WHERE phase NOT IN ('released','failed_held');
