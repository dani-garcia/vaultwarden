-- Lossy revert: this removes the three independent Custom collection permissions, which the legacy
-- role/access_all schema cannot represent -- it only knows all three together. The revert therefore
-- requires the same acknowledgement as 2026-07-24-140000/down.sql -- which only announces the loss,
-- it does not authorize it. Create the marker table while every Vaultwarden instance is stopped:
--
--     CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
-- The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
INSERT INTO __vw_custom_role_downgrade_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = '__vw_allow_custom_role_downgrade'
);
-- `DROP TEMPORARY TABLE`, not `DROP TABLE`: the latter is one more statement that commits
-- implicitly on MySQL/MariaDB, and it would happily drop a permanent table of the same name.
DROP TEMPORARY TABLE __vw_custom_role_downgrade_guard;

-- The previous schema exposes access_all as the three collection permissions together. Avoid
-- turning Edit-only memberships into Create/Edit/Delete grants when rolling back.
UPDATE users_organizations
SET access_all = create_new_collections AND edit_any_collection AND delete_any_collection
WHERE atype = 4;

-- One ALTER, not three. Each `ALTER TABLE` commits implicitly on MySQL/MariaDB, so three statements
-- mean two intermediate states that survive a failure while Diesel still considers the migration
-- unapplied; one statement is the closest this backend gets to all-or-nothing.
ALTER TABLE users_organizations
  DROP COLUMN create_new_collections,
  DROP COLUMN edit_any_collection,
  DROP COLUMN delete_any_collection;
