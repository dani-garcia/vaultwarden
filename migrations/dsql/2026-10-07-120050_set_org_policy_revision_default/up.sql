-- Older instances omit this column during rolling updates and rollbacks.
ALTER TABLE org_policies ALTER COLUMN revision_date SET DEFAULT TIMESTAMP '1970-01-01 00:00:00';
