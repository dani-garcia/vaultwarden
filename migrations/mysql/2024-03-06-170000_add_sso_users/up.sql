CREATE TABLE sso_users (
  user_uuid           CHAR(36) NOT NULL PRIMARY KEY,
  identifier          VARCHAR(768) NOT NULL UNIQUE,
  created_at          TIMESTAMP NOT NULL DEFAULT now(),

  FOREIGN KEY(user_uuid) REFERENCES users(uuid)
);
