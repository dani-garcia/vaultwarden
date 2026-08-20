-- DATETIME (not TIMESTAMP) to match this repo's convention for revision_date
-- columns elsewhere, and to avoid MySQL's implicit session-timezone
-- conversion and 2038 range limit on TIMESTAMP.
ALTER TABLE org_policies
ADD COLUMN revision_date DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';

UPDATE org_policies SET revision_date = UTC_TIMESTAMP();
