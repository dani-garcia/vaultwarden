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
