ALTER TABLE attachments RENAME COLUMN akey TO key;
ALTER TABLE ciphers RENAME COLUMN atype TO type;
ALTER TABLE devices RENAME COLUMN atype TO type;
ALTER TABLE twofactor RENAME COLUMN atype TO type;
ALTER TABLE users RENAME COLUMN akey TO key;
ALTER TABLE users_organizations RENAME COLUMN akey TO key;
ALTER TABLE users_organizations RENAME COLUMN atype TO type;