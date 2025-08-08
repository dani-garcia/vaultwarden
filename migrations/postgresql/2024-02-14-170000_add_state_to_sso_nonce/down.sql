DROP TABLE sso_nonce;

CREATE TABLE sso_nonce (
  nonce               CHAR(36) NOT NULL PRIMARY KEY,
  created_at          TIMESTAMP NOT NULL DEFAULT now()
);
