CREATE TABLE sso_auth (
    state text NOT NULL PRIMARY KEY,
    client_challenge text NOT NULL,
    nonce text NOT NULL,
    redirect_uri text NOT NULL,
    code_response text,
    auth_response text,
    created_at timestamp without time zone NOT NULL DEFAULT now(),
    updated_at timestamp without time zone NOT NULL DEFAULT now()
);
