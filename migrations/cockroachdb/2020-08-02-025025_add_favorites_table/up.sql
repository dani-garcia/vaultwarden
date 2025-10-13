CREATE TABLE favorites (
  user_uuid   VARCHAR(40) NOT NULL REFERENCES users(uuid),
  cipher_uuid VARCHAR(40) NOT NULL REFERENCES ciphers(uuid),

  PRIMARY KEY (user_uuid, cipher_uuid)
);
