CREATE TABLE IF NOT EXISTS census_schema_migrations (
    version BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS workforce_records (
    subject TEXT PRIMARY KEY,
    employment_status TEXT NOT NULL CHECK (
        employment_status IN ('prehire', 'active', 'leave', 'suspended', 'terminated')
    ),
    manager_subject TEXT,
    org_unit_id TEXT NOT NULL,
    department TEXT NOT NULL,
    effective_at BIGINT NOT NULL CHECK (effective_at >= 0),
    source TEXT NOT NULL,
    source_version BIGINT NOT NULL CONSTRAINT ck_workforce_records_source_version_positive
        CHECK (source_version > 0),
    observed_at BIGINT NOT NULL CHECK (observed_at >= 0),
    provenance JSONB NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS workforce_changes (
    cursor BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    dedupe_key TEXT NOT NULL,
    source TEXT NOT NULL,
    source_version BIGINT NOT NULL CONSTRAINT ck_workforce_changes_source_version_positive
        CHECK (source_version > 0),
    kind TEXT NOT NULL CHECK (kind IN ('joiner', 'mover', 'leaver')),
    subject TEXT NOT NULL,
    effective_at BIGINT NOT NULL CHECK (effective_at >= 0),
    old_state JSONB,
    new_state JSONB NOT NULL,
    correlation_id TEXT NOT NULL,
    provenance JSONB NOT NULL,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    recorded_at BIGINT NOT NULL,
    UNIQUE (source, dedupe_key)
);

CREATE INDEX IF NOT EXISTS idx_workforce_changes_subject_cursor
    ON workforce_changes (subject, cursor);
CREATE INDEX IF NOT EXISTS idx_workforce_changes_source_cursor
    ON workforce_changes (source, cursor);
CREATE INDEX IF NOT EXISTS idx_workforce_changes_kind_cursor
    ON workforce_changes (kind, cursor);

INSERT INTO census_schema_migrations (version, name, applied_at)
VALUES (1, 'workforce_jml', EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT)
ON CONFLICT (version) DO NOTHING;
