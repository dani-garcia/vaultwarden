ALTER TABLE users
    ADD COLUMN
    client_kdf_memory INT4 DEFAULT NULL;

ALTER TABLE users
    ADD COLUMN
    client_kdf_parallelism INT4 DEFAULT NULL;
