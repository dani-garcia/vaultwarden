-- Three additional Bitwarden Custom-role permissions. They are only meaningful for Custom members
-- (gated on the role in code); Owners/Admins hold every permission implicitly.
ALTER TABLE users_organizations ADD COLUMN access_event_logs BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN access_import_export BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN access_reports BOOLEAN NOT NULL DEFAULT FALSE;
