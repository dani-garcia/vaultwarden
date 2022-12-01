CREATE TABLE event (
  uuid               TEXT        NOT NULL PRIMARY KEY,
  event_type         INTEGER     NOT NULL,
  user_uuid          TEXT,
  org_uuid           TEXT,
  cipher_uuid        TEXT,
  collection_uuid    TEXT,
  group_uuid         TEXT,
  org_user_uuid      TEXT,
  act_user_uuid      TEXT,
  device_type        INTEGER,
  ip_address         TEXT,
  event_date         DATETIME    NOT NULL,
  policy_uuid        TEXT,
  provider_uuid      TEXT,
  provider_user_uuid TEXT,
  provider_org_uuid  TEXT,
  UNIQUE (uuid)
);
