-- SQLite forbids non-constant defaults in ALTER TABLE ... ADD COLUMN, so add
-- the column with a constant placeholder and backfill separately.
ALTER TABLE org_policies
ADD COLUMN revision_date DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';

UPDATE org_policies SET revision_date = CURRENT_TIMESTAMP;
