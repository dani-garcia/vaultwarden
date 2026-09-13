-- Downgrade is lossy because the legacy role model cannot represent arbitrary Custom permissions.
-- Custom memberships are mapped to User to avoid granting additional privileges. Restore a
-- pre-upgrade database backup if exact state preservation is required.
ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users_organizations
SET access_all = CASE WHEN atype IN (0, 1) THEN TRUE ELSE FALSE END;

UPDATE users_organizations SET atype = 2 WHERE atype = 4;

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
