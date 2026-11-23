-- A blob-encrypted cipher keeps all of its content in `data`, up to 500,000 characters, so the
-- 64 KiB of TEXT is too small. Like upstream, which uses LONGTEXT.
ALTER TABLE ciphers MODIFY data LONGTEXT NOT NULL;
