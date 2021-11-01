CREATE TABLE twofactor_incomplete (
  user_uuid   VARCHAR(40) NOT NULL REFERENCES users(uuid),
  device_uuid VARCHAR(40) NOT NULL,
  device_name TEXT        NOT NULL,
  login_time  TIMESTAMP   NOT NULL,
  ip_address  TEXT        NOT NULL,

  PRIMARY KEY (user_uuid, device_uuid)
);
