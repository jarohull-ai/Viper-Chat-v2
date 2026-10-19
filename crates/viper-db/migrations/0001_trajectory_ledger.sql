CREATE TABLE trajectory_events (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 0),
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) > 0),
    trace_id TEXT NOT NULL CHECK (length(trace_id) > 0),
    schema_version TEXT NOT NULL CHECK (schema_version = 'viper.trajectory.v1'),
    event_type TEXT NOT NULL CHECK (length(event_type) > 0),
    occurred_at TEXT NOT NULL CHECK (length(occurred_at) > 0),
    detail_json TEXT NOT NULL CHECK (json_valid(detail_json)),
    previous_hash TEXT NOT NULL CHECK (length(previous_hash) = 64),
    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64)
) STRICT;

CREATE INDEX idx_trajectory_events_trace
    ON trajectory_events(trace_id, sequence);

CREATE TABLE trajectory_chain_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_sequence INTEGER NOT NULL CHECK (next_sequence >= 0),
    head_hash TEXT NOT NULL CHECK (length(head_hash) = 64)
) STRICT;

INSERT INTO trajectory_chain_state(singleton, next_sequence, head_hash)
VALUES (1, 0, '0000000000000000000000000000000000000000000000000000000000000000');
