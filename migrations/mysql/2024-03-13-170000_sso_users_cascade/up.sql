SELECT if (
    EXISTS(
        SELECT CONSTRAINT_NAME FROM information_schema.table_constraints
            WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'sso_users'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
                AND CONSTRAINT_NAME = 'sso_users_ibfk_1'
    )
    ,'ALTER TABLE sso_users DROP FOREIGN KEY `sso_users_ibfk_1`'
    ,'SELECT "info: FK sso_users_ibfk_1 does not exist."'
) INTO @drop_stmt;
PREPARE drop_stmt FROM @drop_stmt;
EXECUTE drop_stmt;

SELECT if (
    EXISTS(
        SELECT CONSTRAINT_NAME FROM information_schema.table_constraints
            WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'sso_users'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
                AND CONSTRAINT_NAME = '1'
    )
    ,'ALTER TABLE sso_users DROP FOREIGN KEY `1`'
    ,'SELECT "info: FK sso_users 1 does not exist."'
) INTO @drop_stmt;
PREPARE drop_stmt FROM @drop_stmt;
EXECUTE drop_stmt;

DEALLOCATE PREPARE drop_stmt;

ALTER TABLE sso_users ADD FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON UPDATE CASCADE ON DELETE CASCADE;
