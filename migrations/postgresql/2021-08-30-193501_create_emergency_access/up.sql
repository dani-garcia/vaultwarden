CREATE TABLE emergency_access (
  uuid                      CHAR(36)     NOT NULL PRIMARY KEY,
  grantor_uuid              CHAR(36)     REFERENCES users (uuid),
  grantee_uuid              CHAR(36)     REFERENCES users (uuid),
  email                     VARCHAR(255),
  key_encrypted             TEXT,
  atype                     INTEGER  NOT NULL,
  status                    INTEGER  NOT NULL,
  wait_time_days            INTEGER  NOT NULL,
  recovery_initiated_at     TIMESTAMP,
  last_notification_at      TIMESTAMP,
  updated_at                TIMESTAMP NOT NULL,
  created_at                TIMESTAMP NOT NULL
);
