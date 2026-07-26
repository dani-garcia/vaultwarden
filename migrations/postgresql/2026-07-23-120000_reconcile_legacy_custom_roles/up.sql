-- A normal User with the historical membership-level access_all bit cannot be mapped to the
-- Custom role without adding collection-management authority. Stop before dropping the source bit.
CREATE TEMPORARY TABLE __vw_legacy_user_access_all_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_user_access_all_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_user_access_all_guard (blocked)
SELECT 1
FROM users_organizations
WHERE atype = 2 AND access_all = TRUE
LIMIT 1;
DROP TABLE __vw_legacy_user_access_all_guard;

-- The current 2026-07-16 migration copied a legacy full-access group's dynamic authority to the
-- exact direct 0/1/1 pattern. While the same organization-local source group is still present,
-- remove that deterministic copy so later group removal also revokes the authority.
UPDATE users_organizations
SET edit_any_collection = FALSE,
    delete_any_collection = FALSE
WHERE atype IN (3, 4)
  AND access_all = FALSE
  AND create_new_collections = FALSE
  AND edit_any_collection = TRUE
  AND delete_any_collection = TRUE
  AND EXISTS (SELECT 1 FROM __vw_custom_role_same_run_0716 WHERE marker = 1)
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = users_organizations.uuid
      AND g.organizations_uuid = users_organizations.org_uuid
      AND g.access_all = TRUE
  );

-- A remaining 0/1/1 pattern may be either an intentional direct grant or an older derived grant
-- whose source group has already been removed. Do not guess which one it is.
CREATE TEMPORARY TABLE __vw_legacy_group_access_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_group_access_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_group_access_guard (blocked)
SELECT 1
FROM users_organizations
WHERE atype IN (3, 4)
  AND access_all = FALSE
  AND create_new_collections = FALSE
  AND edit_any_collection = TRUE
  AND delete_any_collection = TRUE
LIMIT 1;
DROP TABLE __vw_legacy_group_access_guard;

-- Membership access_all on a legacy Manager/Custom represented all three collection capabilities.
-- Set only TRUE values so this repair never removes independently configured permissions.
UPDATE users_organizations
SET create_new_collections = TRUE,
    edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype IN (3, 4)
  AND access_all = TRUE;

-- Convert only after the legacy bit has been copied.
UPDATE users_organizations SET atype = 4 WHERE atype = 3;

-- Clear the same-run marker only after every guard and permission update succeeds.
DELETE FROM __vw_custom_role_same_run_0716 WHERE marker = 1;
