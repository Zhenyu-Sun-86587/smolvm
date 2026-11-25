CREATE TABLE lifecycle_policies (
    instance_id TEXT PRIMARY KEY,
    bundle_digest TEXT NOT NULL REFERENCES runtime_bundles,
    revision INTEGER NOT NULL,
    policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
    activity_seq INTEGER NOT NULL DEFAULT 0,
    idle_since INTEGER,
    grace_until INTEGER NOT NULL DEFAULT 0,
    freeze_seq INTEGER,
    last_incarnation TEXT,
    next_attempt INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE TABLE lifecycle_reports (
    instance_id TEXT NOT NULL REFERENCES lifecycle_policies,
    incarnation_id TEXT NOT NULL REFERENCES executions,
    collector TEXT NOT NULL CHECK(collector IN ('guest','host','platform')),
    session TEXT NOT NULL,
    seq INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    busy_json TEXT NOT NULL CHECK(json_valid(busy_json)),
    PRIMARY KEY(instance_id,collector)
);
CREATE TABLE lifecycle_sessions (
    instance_id TEXT NOT NULL, collector TEXT NOT NULL, session TEXT NOT NULL, PRIMARY KEY(instance_id,collector,session)
);
CREATE TABLE lifecycle_protections (
    instance_id TEXT NOT NULL REFERENCES lifecycle_policies,
    id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('hold','lease','wake')),
    principal TEXT NOT NULL,
    incarnation_id TEXT,
    epoch INTEGER NOT NULL,
    semantics INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','suspect','pending','released')),
    reason TEXT NOT NULL,
    expires_at INTEGER,
    wake_operation TEXT,
    authorization_revision INTEGER,
    endpoint_revision INTEGER,
    PRIMARY KEY(instance_id,id)
);
CREATE INDEX lifecycle_protection_state ON lifecycle_protections(instance_id,state);
CREATE TABLE lifecycle_requests (
    instance_id TEXT NOT NULL, request_id TEXT NOT NULL, digest TEXT NOT NULL, reply TEXT NOT NULL,
    PRIMARY KEY(instance_id,request_id)
);
CREATE TABLE lifecycle_decisions (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES lifecycle_policies,
    incarnation_id TEXT,
    epoch INTEGER NOT NULL,
    policy_revision INTEGER NOT NULL,
    activity_seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    origin TEXT NOT NULL,
    stage TEXT NOT NULL,
    disposition TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    finished_at INTEGER,
    error TEXT,
    start_memory INTEGER,
    end_memory INTEGER
);
CREATE UNIQUE INDEX lifecycle_pending_decision ON lifecycle_decisions(instance_id)
    WHERE stage IN ('queued','dispatching','running');
ALTER TABLE lifecycle_protections ADD COLUMN token_hash TEXT;
ALTER TABLE lifecycle_protections ADD COLUMN expires_boot TEXT;
CREATE TABLE lifecycle_pressure (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    throttled INTEGER NOT NULL,
    sample_json TEXT NOT NULL CHECK(json_valid(sample_json)),
    changed_at INTEGER NOT NULL,
    reclaimed_at INTEGER
);
ALTER TABLE lifecycle_policies ADD COLUMN freeze_session INTEGER;
CREATE TABLE lifecycle_events (
    seq INTEGER PRIMARY KEY, instance_id TEXT NOT NULL, decision_id TEXT NOT NULL,
    kind TEXT NOT NULL, origin TEXT NOT NULL, stage TEXT NOT NULL, occurred_at INTEGER NOT NULL, error TEXT
);
CREATE INDEX lifecycle_instance_events ON lifecycle_events(instance_id,seq);
CREATE TRIGGER record_lifecycle_decision AFTER INSERT ON lifecycle_decisions BEGIN
    INSERT INTO lifecycle_events(instance_id,decision_id,kind,origin,stage,occurred_at,error)
    VALUES(NEW.instance_id,NEW.id,NEW.kind,NEW.origin,NEW.stage,NEW.created_at,NEW.error);
END;
CREATE TRIGGER record_lifecycle_progress AFTER UPDATE OF stage ON lifecycle_decisions WHEN NEW.stage<>OLD.stage BEGIN
    INSERT INTO lifecycle_events(instance_id,decision_id,kind,origin,stage,occurred_at,error)
    VALUES(NEW.instance_id,NEW.id,NEW.kind,NEW.origin,NEW.stage,coalesce(NEW.finished_at,unixepoch()*1000),NEW.error);
END;
