CREATE TABLE favorites (
  user_uuid   TEXT NOT NULL REFERENCES users(uuid),
  cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid),

  PRIMARY KEY (user_uuid, cipher_uuid)
);

-- Transfer favorite status for user-owned ciphers.
INSERT INTO favorites(user_uuid, cipher_uuid)
SELECT user_uuid, uuid
FROM ciphers
WHERE favorite = 1
  AND user_uuid IS NOT NULL;

-- Drop the `favorite` column from the `ciphers` table, using the 12-step
-- procedure from <https://www.sqlite.org/lang_altertable.html#altertabrename>.
-- Note that some steps aren't applicable and are omitted.

-- 1. If foreign key constraints are enabled, disable them using PRAGMA foreign_keys=OFF.
--
-- Diesel runs each migration in its own transaction. `PRAGMA foreign_keys`
-- is a no-op within a transaction, so this step must be done outside of this
-- file, before starting the Diesel migrations.

-- 2. Start a transaction.
--
-- Diesel already runs each migration in its own transaction.

-- 4. Use CREATE TABLE to construct a new table "new_X" that is in the
--    desired revised format of table X. Make sure that the name "new_X" does
--    not collide with any existing table name, of course.

CREATE TABLE new_ciphers(
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     REFERENCES users(uuid),
  organization_uuid TEXT     REFERENCES organizations(uuid),
  atype             INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  password_history  TEXT,
  deleted_at        DATETIME
);

-- 5. Transfer content from X into new_X using a statement like:
--    INSERT INTO new_X SELECT ... FROM X.

INSERT INTO new_ciphers(uuid, created_at, updated_at, user_uuid, organization_uuid, atype,
                        name, notes, fields, data, password_history, deleted_at)
SELECT uuid, created_at, updated_at, user_uuid, organization_uuid, atype,
       name, notes, fields, data, password_history, deleted_at
FROM ciphers;

-- 6. Drop the old table X: DROP TABLE X.

DROP TABLE ciphers;

-- 7. Change the name of new_X to X using: ALTER TABLE new_X RENAME TO X.

ALTER TABLE new_ciphers RENAME TO ciphers;

-- 11. Commit the transaction started in step 2.

-- 12. If foreign keys constraints were originally enabled, reenable them now.
--
-- `PRAGMA foreign_keys` is scoped to a database connection, and Diesel
-- migrations are run in a separate database connection that is closed once
-- the migrations finish.
