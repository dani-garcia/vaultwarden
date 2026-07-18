ALTER TABLE users_organizations ADD COLUMN create_new_collections BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE;

-- Before these permissions were persisted independently, access_all represented the legacy
-- "Manage all collections" checkbox. Preserve that capability for existing Custom members.
UPDATE users_organizations
SET create_new_collections = access_all,
    edit_any_collection = access_all,
    delete_any_collection = access_all
WHERE atype = 4;

-- A legacy Manager also managed every collection when one of their groups had access_all,
-- even if the membership itself did not. Preserve that existing edit/delete capability without
-- granting collection creation, which historically still required membership access_all.
UPDATE users_organizations
SET edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype = 4
  AND EXISTS (
    SELECT 1
    FROM groups_users
    INNER JOIN groups ON groups.uuid = groups_users.groups_uuid
    WHERE groups_users.users_organizations_uuid = users_organizations.uuid
      AND groups.organizations_uuid = users_organizations.org_uuid
      AND groups.access_all = TRUE
  );
