ALTER TABLE users_organizations ADD COLUMN manage_users BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN manage_groups BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN manage_policies BOOLEAN NOT NULL DEFAULT FALSE;
-- Record which memberships were legacy Managers *before* anything converts them.
--
-- This is the only moment at which that is knowable. `atype = 3` means Manager here and Custom
-- afterwards -- the conversion below reuses the value -- so once it has run, a genuine legacy
-- Manager and a Custom member created later are byte-identical. Every later step that has to reason
-- about legacy authority (2026-07-23, 2026-08-09 and tools/custom_role_rollback/) reads this table
-- instead of guessing, which is what stops them from handing legacy privileges to modern members.
--
-- Deliberately not a Diesel model and not in schema.rs: no runtime code reads it. It is
-- migration/rollback bookkeeping, and it carries no foreign key so that 2026-07-24-120000's table
-- rebuild does not have to care about it.
CREATE TABLE IF NOT EXISTS __vw_custom_role_legacy_manager (
    users_organizations_uuid CHAR(36) NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_legacy_manager (users_organizations_uuid)
SELECT uuid FROM users_organizations WHERE atype = 3
ON CONFLICT DO NOTHING;

-- Separately, mark that this database's Custom-role history is accounted for -- it was produced by
-- the migrations that ship today. Nothing else creates this table, which is what lets the startup
-- preflight treat its absence as proof that an earlier revision of this chain ran instead.
--
-- Deliberately not the record table above: that one holds data an operator has to be able to write
-- during recovery, so its existence cannot also stand for "the history behind this data was
-- reviewed" -- creating it empty to silence an error would otherwise pass as the audit it asks for.
CREATE TABLE IF NOT EXISTS __vw_custom_role_history_verified (
    verified INTEGER NOT NULL PRIMARY KEY
);

-- Previously the server stored members created with the Custom role as Manager (3) and
-- masqueraded them as Custom (4) in all API responses. Now that Custom is a real, persisted
-- type, convert those members so clients (which no longer know the Manager role) keep
-- seeing exactly what they saw before. access_all is preserved; the new flags stay FALSE,
-- which matches the capabilities these members had.
UPDATE users_organizations SET atype = 4 WHERE atype = 3;
