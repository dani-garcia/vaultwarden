-- Keep DDL and DML separate, and store UTC regardless of the session time zone.
UPDATE org_policies SET revision_date = (now() AT TIME ZONE 'utc') WHERE revision_date IS NULL;
