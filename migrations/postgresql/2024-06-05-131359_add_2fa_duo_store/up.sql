CREATE TABLE twofactor_duo_ctx (
    state      VARCHAR(1024) NOT NULL,
    user_email VARCHAR(255)  NOT NULL,
    nonce      VARCHAR(1024) NOT NULL,
    exp        BIGINT        NOT NULL,

    PRIMARY KEY (state)
);