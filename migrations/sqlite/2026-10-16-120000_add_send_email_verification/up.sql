ALTER TABLE sends ADD COLUMN auth_type INTEGER NOT NULL DEFAULT 2;
UPDATE sends SET auth_type = 1 WHERE password_hash IS NOT NULL;
ALTER TABLE sends ADD COLUMN emails TEXT;

CREATE TABLE send_access_otps (
  send_uuid       TEXT     NOT NULL,
  email           TEXT     NOT NULL,
  code            TEXT     NOT NULL,
  attempts        INTEGER  NOT NULL DEFAULT 0,
  creation_date   DATETIME NOT NULL,
  expiration_date DATETIME NOT NULL,

  PRIMARY KEY (send_uuid, email),
  FOREIGN KEY (send_uuid) REFERENCES sends (uuid) ON DELETE CASCADE
);
