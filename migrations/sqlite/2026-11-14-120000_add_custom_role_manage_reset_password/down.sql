-- Dropping the permission would silently take it away from the Custom members holding it. So while there are any,
-- this fails on the duplicate key below: take it away first, or restore the backup taken before the upgrade.
-- It needs to run in one transaction, as Diesel does.
CREATE TEMPORARY TABLE custom_role_downgrade (blocked_by VARCHAR(255) NOT NULL PRIMARY KEY);
INSERT INTO custom_role_downgrade VALUES ('Manage account recovery: take it away first, or restore the backup taken before the upgrade');
INSERT INTO custom_role_downgrade
    SELECT 'Manage account recovery: take it away first, or restore the backup taken before the upgrade'
    FROM users_organizations WHERE manage_reset_password LIMIT 1;
DROP TABLE custom_role_downgrade;

ALTER TABLE users_organizations DROP COLUMN manage_reset_password;
