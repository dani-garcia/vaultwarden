ALTER TABLE attachments RENAME COLUMN key TO akey;
ALTER TABLE ciphers RENAME COLUMN type TO atype;
ALTER TABLE devices RENAME COLUMN type TO atype;
ALTER TABLE twofactor RENAME COLUMN type TO atype;
ALTER TABLE users RENAME COLUMN key TO akey;
ALTER TABLE users_organizations RENAME COLUMN key TO akey;
ALTER TABLE users_organizations RENAME COLUMN type TO atype;