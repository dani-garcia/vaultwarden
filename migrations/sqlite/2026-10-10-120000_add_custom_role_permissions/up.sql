-- The granular permissions of the Custom member role. They only take effect on a Custom membership
-- (atype 4) while EXPERIMENTAL_CUSTOM_ROLES is enabled, and every existing membership starts without any.
ALTER TABLE users_organizations ADD COLUMN manage_users BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN manage_groups BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN manage_policies BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN create_new_collections BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN edit_any_collection BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN delete_any_collection BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN access_event_logs BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN access_import_export BOOLEAN NOT NULL DEFAULT 0; -- FALSE
ALTER TABLE users_organizations ADD COLUMN access_reports BOOLEAN NOT NULL DEFAULT 0; -- FALSE
