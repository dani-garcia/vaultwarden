DROP TABLE IF EXISTS sso_nonce;

CREATE TABLE sso_nonce (
  state               TEXT NOT NULL PRIMARY KEY,
  nonce               TEXT NOT NULL,
  verifier            TEXT,
  redirect_uri        TEXT NOT NULL,
  created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
