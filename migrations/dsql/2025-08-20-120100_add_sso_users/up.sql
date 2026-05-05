CREATE TABLE sso_users (
    user_uuid character(36) NOT NULL PRIMARY KEY,
    identifier text NOT NULL UNIQUE
);
