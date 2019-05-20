CREATE TABLE ciphers_collections (
  cipher_uuid       VARCHAR(40) NOT NULL REFERENCES ciphers (uuid),
  collection_uuid VARCHAR(40) NOT NULL REFERENCES collections (uuid),
  PRIMARY KEY (cipher_uuid, collection_uuid)
);
