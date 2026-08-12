-- The legacy-Manager record has to exist before anything below runs: 2026-06-30-120000 writes it,
-- and the group-derived step at the end of this file reads it. Checked *before* the ALTER TABLE so a
-- refusal leaves no half-added column group behind -- every ALTER commits implicitly here, and a
-- partial group is what the startup preflight then has to recover from.
--
-- `CREATE TEMPORARY TABLE` / `DROP TEMPORARY TABLE` do not commit implicitly, so this whole check is
-- free of durable side effects.
--
-- Creating the record here instead would manufacture an empty, apparently valid history for exactly
-- the databases that need an operator to look at them; see 2026-07-23-120000 for the full reasoning.
-- This guard exists for a bare migration runner that never consulted the startup preflight.
--
-- The duplicate key aborts the migration. It is only inserted while the record table is absent.
CREATE TEMPORARY TABLE __vw_legacy_manager_record_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_manager_record_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_manager_record_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = '__vw_custom_role_legacy_manager'
);
DROP TEMPORARY TABLE __vw_legacy_manager_record_guard;

ALTER TABLE users_organizations ADD COLUMN create_new_collections BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE;

-- Before these permissions were persisted independently, access_all represented the legacy
-- "Manage all collections" checkbox. Preserve that capability for existing Custom members.
--
-- Driven by the stored value rather than by the membership's shape, so it needs no provenance: a
-- member carrying access_all held exactly this capability, whenever the row was created.
UPDATE users_organizations
SET create_new_collections = access_all,
    edit_any_collection = access_all,
    delete_any_collection = access_all
WHERE atype = 4;

-- A legacy Manager also managed every collection when one of their groups had access_all, even if
-- the membership itself did not. Preserve that existing edit/delete capability without granting
-- collection creation, which historically still required membership access_all.
--
-- Restricted to memberships recorded as legacy Managers, exactly like 2026-07-23-120000 and
-- 2026-08-09-120000. Role and group membership alone are *not* evidence of legacy authority:
-- "Custom, member of an access_all group" is also the shape of every modern Custom member who was
-- simply put into an ordinary access_all group, and granting on that shape hands them
-- organization-wide collection edit and delete -- which, through edit_any_collection, also satisfies
-- has_full_access() and therefore reaches every cipher in the organization.
--
-- On the normal upgrade path this changes nothing: 2026-06-30-120000 runs first and records every
-- `atype = 3` row, which at this point is every Custom member there is.
UPDATE users_organizations
SET edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype = 4
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
  AND EXISTS (
    SELECT 1
    FROM groups_users
    -- `groups` is a reserved word in MySQL 8 and must be quoted, matching the existing
    -- `2022-07-27-110000_add_group_support` migration. (PostgreSQL/SQLite do not reserve it.)
    INNER JOIN `groups` ON `groups`.uuid = groups_users.groups_uuid
    WHERE groups_users.users_organizations_uuid = users_organizations.uuid
      AND `groups`.organizations_uuid = users_organizations.org_uuid
      AND `groups`.access_all = TRUE
  );
