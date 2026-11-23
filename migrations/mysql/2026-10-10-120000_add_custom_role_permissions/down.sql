-- Dropping the permissions would silently take them away from the Custom members, who would also keep a role (4) the
-- versions before this one don't know. So while there are any, this fails on the duplicate key below, before anything
-- is dropped: change their role first, or restore the backup taken before the upgrade.
-- A failed attempt leaves the temporary table on this connection. Clear it before retrying.
DROP TEMPORARY TABLE IF EXISTS custom_role_downgrade;
CREATE TEMPORARY TABLE custom_role_downgrade (blocked_by VARCHAR(255) NOT NULL PRIMARY KEY);
INSERT INTO custom_role_downgrade VALUES ('Custom members: change their role first, or restore the backup taken before the upgrade');
INSERT INTO custom_role_downgrade
    SELECT 'Custom members: change their role first, or restore the backup taken before the upgrade'
    FROM users_organizations WHERE atype = 4 LIMIT 1;
DROP TEMPORARY TABLE custom_role_downgrade;

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
