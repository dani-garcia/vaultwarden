-- Backfill via `now() AT TIME ZONE 'utc'` rather than a DEFAULT of now():
-- assigning timestamptz now() into a naive TIMESTAMP column casts through
-- the server's TimeZone GUC, so a DEFAULT now() would store local wall-clock
-- instead of UTC on non-UTC servers, unlike every other naive-UTC timestamp
-- column in this schema.
ALTER TABLE org_policies
ADD COLUMN revision_date TIMESTAMP NOT NULL DEFAULT '1970-01-01 00:00:00';

UPDATE org_policies SET revision_date = (now() AT TIME ZONE 'utc');
