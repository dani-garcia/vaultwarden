DROP TABLE IF EXISTS sso_nonce;

CREATE TABLE sso_auth (
    state               VARCHAR(512) NOT NULL PRIMARY KEY,
    client_challenge    TEXT NOT NULL,
    nonce               TEXT NOT NULL,
    verifier            TEXT,
    redirect_uri        TEXT NOT NULL,
    code_response       JSON,
    auth_response       JSON,
    created_at          TIMESTAMP NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP NOT NULL DEFAULT now()
);
