DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM census_schema_migrations WHERE version = 2
    ) THEN
        IF EXISTS (SELECT 1 FROM workforce_records WHERE source_version <= 0)
           OR EXISTS (SELECT 1 FROM workforce_changes WHERE source_version <= 0) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'workforce source_version remediation is required before schema v2';
        END IF;

        ALTER TABLE workforce_records
            DROP CONSTRAINT IF EXISTS workforce_records_source_version_check;
        ALTER TABLE workforce_records
            DROP CONSTRAINT IF EXISTS ck_workforce_records_source_version_positive;
        ALTER TABLE workforce_records
            ADD CONSTRAINT ck_workforce_records_source_version_positive
            CHECK (source_version > 0);

        ALTER TABLE workforce_changes
            DROP CONSTRAINT IF EXISTS workforce_changes_source_version_check;
        ALTER TABLE workforce_changes
            DROP CONSTRAINT IF EXISTS ck_workforce_changes_source_version_positive;
        ALTER TABLE workforce_changes
            ADD CONSTRAINT ck_workforce_changes_source_version_positive
            CHECK (source_version > 0);

        INSERT INTO census_schema_migrations (version, name, applied_at)
        VALUES (2, 'positive_source_version', EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT);
    END IF;
END
$$;
