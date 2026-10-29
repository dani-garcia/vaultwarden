SELECT if (
    NOT EXISTS(
        SELECT DISTINCT index_name FROM information_schema.statistics
            WHERE table_schema = DATABASE()
                AND table_name = 'devices'
                AND column_name = 'encrypted_private_key'
    )
    ,'ALTER TABLE devices ADD COLUMN encrypted_private_key TEXT NULL, ADD COLUMN encrypted_public_key TEXT NULL, ADD COLUMN encrypted_user_key TEXT NULL'
    ,'SELECT "info: column exist."'
) INTO @add_col_stmt;
PREPARE add_col_stmt FROM @add_col_stmt;
EXECUTE add_col_stmt;
DEALLOCATE PREPARE add_col_stmt;
