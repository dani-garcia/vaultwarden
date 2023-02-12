ALTER TABLE users
    ADD COLUMN
    client_kdf_memory INTEGER DEFAULT NULL;

ALTER TABLE users
    ADD COLUMN
    client_kdf_parallelism INTEGER DEFAULT NULL;
