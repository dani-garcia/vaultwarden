ALTER TABLE ciphers
ADD COLUMN favorite BOOLEAN NOT NULL DEFAULT FALSE;

-- Transfer favorite status for user-owned ciphers.
UPDATE ciphers
SET favorite = TRUE
WHERE EXISTS (
  SELECT * FROM favorites
  WHERE favorites.user_uuid = ciphers.user_uuid
    AND favorites.cipher_uuid = ciphers.uuid
);

DROP TABLE favorites;
