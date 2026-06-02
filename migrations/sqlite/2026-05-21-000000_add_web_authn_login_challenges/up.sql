CREATE TABLE web_authn_login_challenges (
    id          TEXT      NOT NULL PRIMARY KEY,
    challenge   TEXT      NOT NULL,
    created_at  DATETIME  NOT NULL
);

CREATE INDEX idx_web_authn_login_challenges_created_at ON web_authn_login_challenges (created_at);
