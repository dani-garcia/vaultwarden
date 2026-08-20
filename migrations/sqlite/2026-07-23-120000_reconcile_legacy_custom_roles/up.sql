-- Repair the legacy role/permission state while membership `access_all` still exists.
--
-- A plain User carrying the historical membership-level `access_all` bit is deliberately not
-- converted: that state grants dynamic reach over every collection *without* management authority,
-- and the new model has no equivalent. It is refused instead -- and refused *here*, not only in Rust:
-- Vaultwarden's startup preflight already stops such a database before any migration runs and prints
-- the two explicit choices (`RefuseLegacyUserAccessAll` in `src/db/mod.rs`), but a migration run
-- outside that wrapper -- `diesel migration run`, a bare `MigrationHarness`, any other SQL runner
-- -- would not consult it, and 2026-07-24-120000 removes the only source of that reach a few
-- statements later. Repeating the check before this file's first mutation is what makes the silent
-- loss impossible rather than unlikely.
--
-- The duplicate key aborts the migration. It is only inserted when such a membership exists.
CREATE TEMPORARY TABLE __vw_legacy_user_access_all_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_user_access_all_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_user_access_all_guard (blocked)
SELECT 1
FROM users_organizations
WHERE atype = 2
  AND access_all = TRUE
LIMIT 1;
DROP TABLE __vw_legacy_user_access_all_guard;

-- The legacy-Manager record has to exist already: 2026-06-30-120000 writes it, and the startup
-- preflight refuses a database whose ledger carries that version without it. Creating it here would
-- manufacture an empty, apparently valid history for precisely the databases that need an operator
-- to look at them, so refuse instead -- this guard exists for a bare migration runner that never
-- consulted the preflight.
--
-- The duplicate key aborts the migration. It is only inserted while the record table is absent.
CREATE TEMPORARY TABLE __vw_legacy_manager_record_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_manager_record_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_manager_record_guard (blocked)
SELECT 1
WHERE NOT EXISTS (
    SELECT 1 FROM sqlite_master
    WHERE type = 'table' AND name = '__vw_custom_role_legacy_manager'
);
DROP TABLE __vw_legacy_manager_record_guard;

-- A database that reaches this file with memberships still at `atype = 3` never ran the rewritten
-- 2026-06-30-120000 -- for instance because a runner applied the files out of order. Those rows are
-- unambiguously legacy Managers *right now*, so record them before the conversion at the end of this
-- file makes them indistinguishable from modern Custom members. Idempotent, and a no-op on the
-- normal path where 2026-06-30-120000 already recorded them.
INSERT OR IGNORE INTO __vw_custom_role_legacy_manager (users_organizations_uuid)
SELECT uuid FROM users_organizations WHERE atype = 3;

-- Step 1: a legacy Manager who managed every collection through an organization-local group with
-- `access_all` keeps that authority, materialized into the permission columns it now lives in.
--
-- Restricted to memberships recorded as legacy Managers. Matching on role and group membership
-- alone -- which an earlier revision did -- also matches every *modern* flagless Custom member who
-- happens to sit in an ordinary `access_all` group, because the two states are the same shape, and
-- would hand them organization-wide collection edit and delete.
--
-- Earlier revisions derived this authority live from the group at request time instead, which was
-- unsound for exactly that reason. Materializing it makes it visible to an owner in the member's
-- permission list and revocable by clearing a checkbox. It is deliberately a one-time snapshot: the
-- permission no longer lapses when the source group does. See tools/custom_role_rollback/README.md.
--
-- Deliberately not `create_new_collections`: creating collections historically required
-- membership-level `access_all`, and it is an independent permission now.
UPDATE users_organizations
SET edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype IN (3, 4)
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = users_organizations.uuid
      AND g.organizations_uuid = users_organizations.org_uuid
      AND g.access_all = TRUE
  );

-- Step 2: membership `access_all` on a legacy Manager represented all three collection capabilities.
-- Set only TRUE values so this repair never removes independently configured permissions, and again
-- only for recorded legacy Managers -- an intermediate revision of this feature branch could leave a
-- modern Custom member carrying the old column as well.
UPDATE users_organizations
SET create_new_collections = TRUE,
    edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype IN (3, 4)
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
  AND access_all = TRUE;

-- Convert only after the legacy bit has been copied.
UPDATE users_organizations SET atype = 4 WHERE atype = 3;

-- Clear the same-run marker only after every permission update succeeds.
DELETE FROM __vw_custom_role_same_run_0716 WHERE marker = 1;
