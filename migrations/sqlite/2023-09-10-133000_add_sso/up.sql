CREATE TABLE sso_nonce (
  nonce               CHAR(36) NOT NULL PRIMARY KEY,
  created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
