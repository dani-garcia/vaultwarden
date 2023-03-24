ALTER TABLE attachments RENAME TO oldAttachments;

CREATE TABLE attachments (
  id          TEXT    NOT NULL PRIMARY KEY,
  cipher_uuid TEXT    NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT    NOT NULL,
  file_size   INTEGER NOT NULL

);

INSERT INTO attachments (id, cipher_uuid, file_name, file_size) 
SELECT id, cipher_uuid, file_name, file_size FROM oldAttachments;

DROP TABLE oldAttachments;
