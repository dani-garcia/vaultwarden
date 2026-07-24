ALTER TABLE sends ADD COLUMN emails TEXT;

CREATE TABLE sends_otp (
    send_uuid       CHAR(36) NOT NULL REFERENCES sends(uuid) ON DELETE CASCADE ON UPDATE CASCADE,
    email           VARCHAR(255) NOT NULL,
    code            TEXT NOT NULL,

    creation_date     DATETIME NOT NULL,
    revision_date     DATETIME NOT NULL,
    expiration_date   DATETIME NOT NULL,

    PRIMARY KEY(send_uuid, email)
);


DELETE FROM sends where user_uuid IS NULL;
UPDATE sends SET hide_email = false WHERE hide_email IS NULL;

SELECT if (
    EXISTS(
        SELECT CONSTRAINT_NAME FROM information_schema.table_constraints
            WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'sends'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
                AND CONSTRAINT_NAME = 'sends_ibfk_2'
    )
    ,'ALTER TABLE sends DROP FOREIGN KEY `sends_ibfk_2`'
    ,'SELECT "info: FK sends_ibfk_2 does not exist."'
) INTO @drop_stmt;
PREPARE drop_stmt FROM @drop_stmt;
EXECUTE drop_stmt;

SELECT if (
    EXISTS(
        SELECT CONSTRAINT_NAME FROM information_schema.table_constraints
            WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'sends'
                AND CONSTRAINT_TYPE = 'FOREIGN KEY'
                AND CONSTRAINT_NAME = '2'
    )
    ,'ALTER TABLE sends DROP FOREIGN KEY `2`'
    ,'SELECT "info: FK sends 2 does not exist."'
) INTO @drop_stmt;
PREPARE drop_stmt FROM @drop_stmt;
EXECUTE drop_stmt;

DEALLOCATE PREPARE drop_stmt;

ALTER TABLE sends DROP COLUMN organization_uuid;
ALTER TABLE sends MODIFY user_uuid CHAR(36) NOT NULL;
ALTER TABLE sends MODIFY hide_email BOOLEAN NOT NULL;
