CREATE TABLE policy_versions (
    policy_id TEXT NOT NULL CHECK (length(policy_id) > 0),
    version TEXT NOT NULL CHECK (length(version) > 0),
    schema_version TEXT NOT NULL CHECK (length(schema_version) > 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    activated_at TEXT NOT NULL CHECK (length(activated_at) > 0),
    lifecycle_status TEXT NOT NULL CHECK (
        lifecycle_status IN ('active', 'retiring', 'revoked')
    ),
    PRIMARY KEY (policy_id, version)
) STRICT;

CREATE UNIQUE INDEX idx_policy_versions_one_active
    ON policy_versions(policy_id)
    WHERE lifecycle_status = 'active';
