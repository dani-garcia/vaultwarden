-- Lossy revert: this removes the three Custom management permissions and the Custom role itself,
-- which the legacy role/access_all schema cannot represent. The revert therefore
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

-- Convert Custom members back to a role the older server can load -- it cannot represent type 4 and
-- masquerades Manager as Custom in API responses. Which role each one gets is a decision about its
-- authority *now*, and it is not symmetric with the upgrade.
--
-- Deliberately not driven by `__vw_custom_role_legacy_manager`. That records who held the Manager
-- role before the *first* upgrade and is never updated afterwards, so a member whose Manager powers
-- an owner has since reduced -- or who was demoted to User and later re-created as a limited Custom
-- member -- would be handed the whole legacy role back. Historical provenance is evidence, not
-- authorization. Use a list written for this downgrade instead.
--
-- Absent, or empty, means "nobody", and everything below becomes a plain User. That is the safe
-- direction: the legacy Manager role is not a subset of what a Custom member holds -- it manages, and
-- deletes, every collection reachable through `users_collections.manage`,
-- `collections_groups.manage` or `groups.access_all`, and reads member and collection ACL details
-- through `ManagerHeadersLoose`, none of which needs a permission flag in the old schema. To keep the
-- historical mapping, copy it over deliberately before reverting:
--
--     CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid CHAR(36) NOT NULL PRIMARY KEY);
--     INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid)
--     SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager;
CREATE TABLE IF NOT EXISTS __vw_rollback_manager_allowlist (
    users_organizations_uuid CHAR(36) NOT NULL PRIMARY KEY
);

UPDATE users_organizations SET atype = 3
WHERE atype = 4
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist);

-- Everything still on the Custom role becomes a plain User, and `access_all` has to be cleared with
-- it. 2026-07-16-120000/down.sql sets that flag for every Custom member holding all three collection
-- permissions, on the assumption they are about to become a Manager; left behind on a User it
-- produces `User + access_all`, the one legacy state the upgrade refuses outright -- which would
-- leave the database unable to move forward again. `users_collections` and `collections_groups` are
-- untouched, so these members keep every per-collection grant and lose only the organization-wide
-- powers the old schema cannot express.
UPDATE users_organizations SET atype = 2, access_all = FALSE WHERE atype = 4;

-- One ALTER, not three. Each `ALTER TABLE` commits implicitly on MySQL/MariaDB, so three statements
-- mean two intermediate states that survive a failure while Diesel still considers the migration
-- unapplied; one statement is the closest this backend gets to all-or-nothing.
ALTER TABLE users_organizations
  DROP COLUMN manage_users,
  DROP COLUMN manage_groups,
  DROP COLUMN manage_policies;

-- Oldest lossy step of the chain: nothing below this can lose Custom-role data any more, so the
-- acknowledgement is consumed here. It authorized *this* downgrade, not every future one. The
-- Custom-role bookkeeping goes with it -- the roles it describes are back, and a later re-upgrade
-- rebuilds all of it from the restored `atype = 3` rows.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_allow_unresumable_mysql_downgrade;
DROP TABLE IF EXISTS __vw_rollback_manager_allowlist;
DROP TABLE IF EXISTS __vw_custom_role_legacy_manager;
DROP TABLE IF EXISTS __vw_custom_role_history_verified;
