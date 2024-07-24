CREATE TABLE twofactor_duo_ctx (
    state      VARCHAR(64)  NOT NULL,
    user_email VARCHAR(255) NOT NULL,
    nonce      VARCHAR(64)  NOT NULL,
    exp        BIGINT       NOT NULL,

    PRIMARY KEY (state)
);