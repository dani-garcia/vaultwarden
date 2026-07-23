-- Recreate the column and repopulate it from the role/permission model that replaced it, restoring
-- the invariant older server versions rely on: access_all == access to every collection. That is
-- exactly Owners/Admins, plus Custom members holding `edit_any_collection`.
ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE users_organizations SET access_all = TRUE WHERE atype IN (0, 1);
UPDATE users_organizations SET access_all = TRUE WHERE atype = 4 AND edit_any_collection = TRUE;
