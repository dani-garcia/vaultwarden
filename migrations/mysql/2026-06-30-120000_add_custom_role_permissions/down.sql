-- Lossy revert: the legacy role/`access_all` schema cannot represent the nine Custom permissions or
-- the Custom role. Two explicit operator decisions are required before anything is touched, and both
-- are consumed at the end, so one decision covers one downgrade. Operators who only need the older
-- binary to start again can use the self-contained script per backend in tools/custom_role_rollback/.
--
-- Both guards use temporary tables on purpose: on MySQL/MariaDB temporary-table DDL is the only DDL
-- that does not commit implicitly, so a refusal here cannot leave a half-reverted schema behind.

-- 1) Acknowledge the loss. Create this table with every Vaultwarden instance stopped:
--
--        CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
--
--    The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
INSERT INTO __vw_custom_role_downgrade_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = '__vw_allow_custom_role_downgrade'
);
DROP TEMPORARY TABLE __vw_custom_role_downgrade_guard;

-- 2) Decide which Custom memberships come back as Manager. The legacy role is not a subset of what a
--    Custom member holds, so handing it out automatically would *grant* authority during a
--    downgrade; it takes a current, deliberate list. An empty list is a valid answer and maps every
--    Custom member to plain User. See README.md in tools/custom_role_rollback/.
--
--        CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid CHAR(36) NOT NULL PRIMARY KEY);
--        INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid) VALUES ('<MEMBERSHIP_UUID>');
--
--    The duplicate key aborts the revert. It is only inserted while the list is absent.
CREATE TEMPORARY TABLE __vw_rollback_allowlist_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_rollback_allowlist_guard (blocked) VALUES (1);
INSERT INTO __vw_rollback_allowlist_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = '__vw_rollback_manager_allowlist'
);
DROP TEMPORARY TABLE __vw_rollback_allowlist_guard;

ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;

-- Roles and `access_all` are recomputed together, because in the old schema they are not
-- independent:
--
--   * Owners and Admins always carried the bit and it grants them nothing extra;
--   * an allowlisted Custom member becomes a Manager, and keeps the bit only if it holds all three
--     collection permissions -- in the old schema `access_all` also carried collection deletion, so
--     an Edit-only member must not silently gain it;
--   * everything else becomes a plain User without the bit. `User + access_all` is the one legacy
--     state the upgrade refuses, so leaving it set would make the database unable to move forward
--     again.
--
-- Group-derived Manager authority is not restored here and does not need to be: `groups.access_all`
-- was never modified, so the older binary derives it again by itself for whoever comes back as
-- Manager.
UPDATE users_organizations
SET access_all = CASE
        WHEN atype IN (0, 1) THEN TRUE
        WHEN atype = 4
         AND uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist)
         AND create_new_collections = TRUE
         AND edit_any_collection = TRUE
         AND delete_any_collection = TRUE THEN TRUE
        ELSE FALSE
    END,
    atype = CASE
        WHEN atype = 4
         AND uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist) THEN 3
        WHEN atype = 4 THEN 2
        ELSE atype
    END;

ALTER TABLE users_organizations
    DROP COLUMN manage_users,
    DROP COLUMN manage_groups,
    DROP COLUMN manage_policies,
    DROP COLUMN create_new_collections,
    DROP COLUMN edit_any_collection,
    DROP COLUMN delete_any_collection,
    DROP COLUMN access_event_logs,
    DROP COLUMN access_import_export,
    DROP COLUMN access_reports;

-- Both decisions authorized *this* downgrade, not the next one.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_rollback_manager_allowlist;
