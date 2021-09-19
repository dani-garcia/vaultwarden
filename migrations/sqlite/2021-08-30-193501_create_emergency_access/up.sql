CREATE TABLE emergency_access (
  uuid                      TEXT     NOT NULL PRIMARY KEY,
  grantor_uuid              TEXT     REFERENCES users (uuid),
  grantee_uuid              TEXT     REFERENCES users (uuid),
  email                     TEXT,
  key_encrypted             TEXT,
  atype                     INTEGER  NOT NULL,
  status                    INTEGER  NOT NULL,
  wait_time_days            INTEGER  NOT NULL,
  recovery_initiated_at     DATETIME,
  last_notification_at      DATETIME,
  updated_at                DATETIME NOT NULL,
  created_at                DATETIME NOT NULL
);
