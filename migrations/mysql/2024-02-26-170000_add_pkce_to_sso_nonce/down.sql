DROP TABLE IF EXISTS sso_nonce;

CREATE TABLE sso_nonce (
    state               VARCHAR(512) NOT NULL PRIMARY KEY,
    nonce               TEXT NOT NULL,
    redirect_uri        TEXT NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);
