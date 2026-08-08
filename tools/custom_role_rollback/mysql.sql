-- Roll a MySQL/MariaDB database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- NOTE: MySQL/MariaDB commit every DDL statement implicitly, so this script cannot be wrapped in a
-- transaction. Take a backup before running it; if it is interrupted, restore and start over.

ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;

-- The legacy flag is recomputed with the same mapping the down migrations use: everyone who
-- reached every collection keeps that reach, and a Custom member has to hold all three collection
-- permissions -- Edit-only must not silently turn into the legacy "manage all collections"
-- authority, which in that older schema also carried collection deletion.
UPDATE users_organizations SET access_all = TRUE WHERE atype IN (0, 1);
UPDATE users_organizations
SET access_all = TRUE
WHERE atype = 4
  AND create_new_collections = TRUE
  AND edit_any_collection = TRUE
  AND delete_any_collection = TRUE;

-- The old server cannot load type 4; Custom members were stored as Manager back then.
UPDATE users_organizations SET atype = 3 WHERE atype = 4;

ALTER TABLE users_organizations DROP COLUMN manage_users;
ALTER TABLE users_organizations DROP COLUMN manage_groups;
ALTER TABLE users_organizations DROP COLUMN manage_policies;
ALTER TABLE users_organizations DROP COLUMN create_new_collections;
ALTER TABLE users_organizations DROP COLUMN edit_any_collection;
ALTER TABLE users_organizations DROP COLUMN delete_any_collection;
ALTER TABLE users_organizations DROP COLUMN access_event_logs;
ALTER TABLE users_organizations DROP COLUMN access_import_export;
ALTER TABLE users_organizations DROP COLUMN access_reports;

-- Bookkeeping tables this feature may have left behind.
DROP TABLE IF EXISTS __vw_custom_role_same_run_0716;
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;

-- Finally forget the seven migrations, so the older binary does not see a ledger from the future
-- and a later upgrade applies them again from a clean state.
DELETE FROM __diesel_schema_migrations
WHERE version IN (
  '20260630120000',
  '20260715120000',
  '20260716120000',
  '20260723120000',
  '20260724120000',
  '20260724130000',
  '20260724140000'
);
