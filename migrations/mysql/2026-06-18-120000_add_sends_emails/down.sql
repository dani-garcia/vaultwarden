DROP TABLE sends_otp;

ALTER TABLE sends DROP COLUMN auth_type;
ALTER TABLE sends DROP COLUMN emails;

ALTER TABLE sends MODIFY user_uuid CHAR(36) NULL;
ALTER TABLE sends MODIFY hide_email BOOLEAN NULL;

ALTER TABLE sends ADD COLUMN organization_uuid CHAR(36);
ALTER TABLE sends ADD FOREIGN KEY (organization_uuid) REFERENCES organizations(uuid);
