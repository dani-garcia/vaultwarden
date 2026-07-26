-- Forward migration marker. Its down migration intentionally blocks an automatic lossy downgrade
-- before any granular permission column is removed.
SELECT 1;
