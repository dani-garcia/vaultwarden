ALTER TABLE users_organizations ADD COLUMN manage_users BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN manage_groups BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN manage_policies BOOLEAN NOT NULL DEFAULT FALSE;
-- Previously the server stored members created with the Custom role as Manager (3) and
-- masqueraded them as Custom (4) in all API responses. Now that Custom is a real, persisted
-- type, convert those members so clients (which no longer know the Manager role) keep
-- seeing exactly what they saw before. access_all is preserved; the new flags stay FALSE,
-- which matches the capabilities these members had.
UPDATE users_organizations SET atype = 4 WHERE atype = 3;
