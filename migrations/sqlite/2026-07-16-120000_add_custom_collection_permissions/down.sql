-- The previous schema exposes access_all as the three collection permissions together. Avoid
-- turning Edit-only memberships into Create/Edit/Delete grants when rolling back.
UPDATE users_organizations
SET access_all = create_new_collections AND edit_any_collection AND delete_any_collection
WHERE atype = 4;

ALTER TABLE users_organizations DROP COLUMN create_new_collections;
ALTER TABLE users_organizations DROP COLUMN edit_any_collection;
ALTER TABLE users_organizations DROP COLUMN delete_any_collection;
