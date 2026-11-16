-- The memberships and groups keep the explicit assignments the upgrade gave them. Owners and Admins get the access to
-- all collections back that they always had before, which the older versions need to show them every collection. The
-- Managers stay Users who manage their collections.
ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE `groups` ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE users_organizations SET access_all = TRUE WHERE atype IN (0, 1);
