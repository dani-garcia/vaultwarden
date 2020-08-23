CREATE TABLE favorites (
  user_uuid   CHAR(36) NOT NULL REFERENCES users(uuid),
  cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers(uuid),

  PRIMARY KEY (user_uuid, cipher_uuid)
);

-- Transfer favorite status for user-owned ciphers.
INSERT INTO favorites(user_uuid, cipher_uuid)
SELECT user_uuid, uuid
FROM ciphers
WHERE favorite = TRUE
  AND user_uuid IS NOT NULL;

ALTER TABLE ciphers
DROP COLUMN favorite;
