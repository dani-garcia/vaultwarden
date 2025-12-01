-- Dynamically create DROP FOREIGN KEY
-- Some versions of MySQL or MariaDB might fail if the key doesn't exists
-- This checks if the key exists, and if so, will drop it.
SET @drop_sso_fk = IF((SELECT true FROM information_schema.TABLE_CONSTRAINTS WHERE
    CONSTRAINT_SCHEMA = DATABASE() AND
    TABLE_NAME = 'sso_users' AND
    CONSTRAINT_NAME = 'sso_users_ibfk_1' AND
    CONSTRAINT_TYPE = 'FOREIGN KEY') = true,
    'ALTER TABLE sso_users DROP FOREIGN KEY sso_users_ibfk_1',
    'SELECT 1');
PREPARE stmt FROM @drop_sso_fk;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

ALTER TABLE sso_users ADD FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON UPDATE CASCADE ON DELETE CASCADE;
