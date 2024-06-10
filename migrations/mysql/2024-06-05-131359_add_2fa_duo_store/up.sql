CREATE TABLE twofactor_duo_ctx (
    -- For mysql, the character set on state is overridden to ascii because the utf8mb4 database charset recommended in
    -- the Vaultwarden docs causes 1 character to consume 4 bytes, exceeding innodb's 3072 max key size if we want to
    -- accommodate the largest supported state size. This isn't a problem for nonce since it's not a key for the table.
    state      VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
    user_email VARCHAR(255)  NOT NULL,
    nonce      VARCHAR(1024) NOT NULL,
    exp        BIGINT        NOT NULL,

    PRIMARY KEY (state)
);