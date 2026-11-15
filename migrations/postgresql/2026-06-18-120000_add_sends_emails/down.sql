DROP TABLE sends_otp;

ALTER TABLE sends DROP COLUMN auth_type;
ALTER TABLE sends DROP COLUMN emails;

ALTER TABLE sends ALTER COLUMN user_uuid DROP NOT NULL;
ALTER TABLE sends ALTER COLUMN hide_email DROP NOT NULL;

ALTER TABLE sends ADD COLUMN organization_uuid TEXT REFERENCES organizations(uuid);
