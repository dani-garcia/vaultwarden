-- Roll a SQLite database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- `ALTER TABLE ... DROP COLUMN` is avoided on purpose: it only exists since SQLite 3.35, and this
-- script has to work on the same older system SQLite the forward migrations support. Rebuilding the
-- table also recreates `access_all` and drops all nine permission columns in one step.

PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE users_organizations_rollback (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),
  access_all BOOLEAN NOT NULL DEFAULT 0,
  akey       TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype      INTEGER NOT NULL,
  reset_password_key TEXT,
  external_id TEXT,
  invited_by_email TEXT DEFAULT NULL,

  UNIQUE (user_uuid, org_uuid)
);

-- The legacy flag is recomputed with the same mapping the down migrations use: everyone who
-- reached every collection keeps that reach, and a Custom member has to hold all three collection
-- permissions -- Edit-only must not silently turn into the legacy "manage all collections"
-- authority, which in that older schema also carried collection deletion.
INSERT INTO users_organizations_rollback (
  uuid, user_uuid, org_uuid, access_all, akey, status, atype,
  reset_password_key, external_id, invited_by_email
)
SELECT
  uuid, user_uuid, org_uuid,
  CASE
    WHEN atype IN (0, 1) THEN 1
    WHEN atype = 4
         AND create_new_collections = 1
         AND edit_any_collection = 1
         AND delete_any_collection = 1 THEN 1
    ELSE 0
  END,
  akey, status,
  -- The old server cannot load type 4; Custom members were stored as Manager back then.
  CASE WHEN atype = 4 THEN 3 ELSE atype END,
  reset_password_key, external_id, invited_by_email
FROM users_organizations;

DROP TABLE users_organizations;

ALTER TABLE users_organizations_rollback RENAME TO users_organizations;

-- Bookkeeping tables this feature may have left behind.
DROP TABLE IF EXISTS __vw_custom_role_same_run_0716;
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;

-- Finally forget the seven migrations, so the older binary does not see a ledger from the future
-- and a later upgrade applies them again from a clean state.
DELETE FROM __diesel_schema_migrations
WHERE version IN (
  '20260630120000',
  '20260715120000',
  '20260716120000',
  '20260723120000',
  '20260724120000',
  '20260724130000',
  '20260724140000'
);

COMMIT;
