-- The Manage account recovery permission of the Custom member role. Like the other permissions it only takes
-- effect on a Custom membership (atype 4) while EXPERIMENTAL_CUSTOM_ROLES is enabled, and nobody starts with it.
ALTER TABLE users_organizations ADD COLUMN manage_reset_password BOOLEAN NOT NULL DEFAULT FALSE;
