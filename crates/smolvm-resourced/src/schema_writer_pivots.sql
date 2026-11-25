CREATE TABLE writer_pivots (
    operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
    incarnation_id TEXT NOT NULL REFERENCES executions(incarnation_id),
    execution_epoch INTEGER NOT NULL CHECK (execution_epoch > 0),
    previous_grant_id TEXT NOT NULL REFERENCES writer_grants(grant_id),
    next_grant_id TEXT NOT NULL UNIQUE,
    hold_token TEXT NOT NULL,
    plan_json TEXT NOT NULL CHECK (json_valid(plan_json)),
    state TEXT NOT NULL CHECK (state IN ('preparing','offered','commit','complete','aborted')),
    revision INTEGER NOT NULL CHECK (revision > 0)
);
CREATE UNIQUE INDEX writer_pivots_one_pending ON writer_pivots(incarnation_id)
    WHERE state NOT IN ('complete','aborted');
