DROP INDEX auth_requests_creation_date;
DROP INDEX auth_requests_organization_type;

ALTER TABLE auth_requests DROP COLUMN atype;

ALTER TABLE devices DROP COLUMN encrypted_private_key;
ALTER TABLE devices DROP COLUMN encrypted_public_key;
ALTER TABLE devices DROP COLUMN encrypted_user_key;
