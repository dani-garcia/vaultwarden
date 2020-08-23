ALTER TABLE ciphers
ADD COLUMN favorite BOOLEAN NOT NULL DEFAULT 0; -- FALSE

-- Transfer favorite status for user-owned ciphers.
UPDATE ciphers
SET favorite = 1
WHERE EXISTS (
  SELECT * FROM favorites
  WHERE favorites.user_uuid = ciphers.user_uuid
    AND favorites.cipher_uuid = ciphers.uuid
);

DROP TABLE favorites;
