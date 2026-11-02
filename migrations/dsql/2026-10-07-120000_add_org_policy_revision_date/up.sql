-- DSQL cannot add a column with constraints. Separate migrations set a default and backfill it.
ALTER TABLE org_policies ADD COLUMN revision_date TIMESTAMP WITHOUT TIME ZONE;
