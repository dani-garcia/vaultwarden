-- Record whether 2026-07-16 is about to run in this migration sequence. The durable marker lets a
-- retry distinguish its deterministic group-derived 0/1/1 backfill from older, ambiguous data.
CREATE TABLE IF NOT EXISTS __vw_custom_role_same_run_0716 (
    marker INTEGER NOT NULL PRIMARY KEY
);
INSERT IGNORE INTO __vw_custom_role_same_run_0716 (marker)
SELECT 1
FROM DUAL
WHERE NOT EXISTS (
    SELECT 1
    FROM __diesel_schema_migrations
    WHERE version = '20260716120000'
);
