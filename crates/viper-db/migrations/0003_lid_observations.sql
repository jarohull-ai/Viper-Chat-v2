CREATE TABLE lid_observations (
    observation_id TEXT PRIMARY KEY CHECK (length(observation_id) BETWEEN 1 AND 128),
    event_id TEXT NOT NULL REFERENCES trajectory_events(event_id) ON DELETE RESTRICT,
    audit_event_id TEXT NOT NULL UNIQUE REFERENCES trajectory_events(event_id) ON DELETE RESTRICT,
    observed_at TEXT NOT NULL CHECK (length(observed_at) BETWEEN 1 AND 64),
    lid REAL NOT NULL CHECK (lid > 0.0 AND lid <= 1000000000000.0),
    neighbors_used INTEGER NOT NULL CHECK (neighbors_used BETWEEN 2 AND 256),
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 128),
    model_bundle_sha256 TEXT NOT NULL CHECK (
        length(model_bundle_sha256) = 64 AND model_bundle_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    corpus_version TEXT NOT NULL CHECK (length(corpus_version) BETWEEN 1 AND 64),
    corpus_manifest_sha256 TEXT NOT NULL CHECK (
        length(corpus_manifest_sha256) = 64 AND corpus_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status = 'uncalibrated')
) STRICT;

CREATE INDEX idx_lid_observations_event ON lid_observations(event_id);
CREATE INDEX idx_lid_observations_audit_event ON lid_observations(audit_event_id);
CREATE INDEX idx_lid_observations_model_corpus
    ON lid_observations(model_bundle_sha256, corpus_manifest_sha256);
