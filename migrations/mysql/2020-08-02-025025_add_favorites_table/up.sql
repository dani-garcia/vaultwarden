CREATE TABLE favorites (
  user_uuid   CHAR(36) NOT NULL REFERENCES users(uuid),
  cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers(uuid),

  PRIMARY KEY (user_uuid, cipher_uuid)
);

ALTER TABLE ciphers
DROP COLUMN favorite;
