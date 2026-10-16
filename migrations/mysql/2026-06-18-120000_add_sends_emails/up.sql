ALTER TABLE sends ADD COLUMN emails TEXT;

CREATE TABLE sends_otp (
    send_uuid       CHAR(36) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    code            TEXT NOT NULL,

    creation_date     DATETIME NOT NULL,
    revision_date     DATETIME NOT NULL,
    expiration_date   DATETIME NOT NULL,

    PRIMARY KEY(send_uuid, email)
);

ALTER TABLE sends_otp ADD CONSTRAINT fk_send_uuid FOREIGN KEY (send_uuid) REFERENCES sends(uuid) ON DELETE CASCADE ON UPDATE CASCADE;

DELETE FROM sends where user_uuid IS NULL;
UPDATE sends SET hide_email = false WHERE hide_email IS NULL;

SELECT CONCAT('ALTER TABLE sends DROP FOREIGN KEY `', constraint_name, '`') INTO @drop_stmt
    FROM information_schema.key_column_usage
        WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'sends'
            AND COLUMN_NAME = 'organization_uuid';
PREPARE drop_stmt FROM @drop_stmt;
EXECUTE drop_stmt;
DEALLOCATE PREPARE drop_stmt;

ALTER TABLE sends DROP COLUMN organization_uuid;
ALTER TABLE sends MODIFY user_uuid CHAR(36) NOT NULL;
ALTER TABLE sends MODIFY hide_email BOOLEAN NOT NULL;
