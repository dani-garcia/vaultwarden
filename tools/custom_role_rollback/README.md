# Rolling back the Custom-role change

The Custom-role change removes the membership `access_all` column and adds nine permission columns.
A Vaultwarden version from before that change cannot start against the new schema, because its
`schema.rs` still expects `access_all` to exist.

Vaultwarden only ever applies *pending* migrations — it never reverts one on its own — so putting
the old image back is not enough. Run the script for your backend once and the old version starts
again.

## What is lost

The old schema has nowhere to store the nine permissions, so they are dropped:

| Before the rollback | After |
|---|---|
| Owner / Admin | Owner / Admin with `access_all = TRUE` |
| Custom with **all three** collection permissions | Manager with `access_all = TRUE` |
| Custom with only some collection permissions | Manager with `access_all = FALSE` |
| Custom with `manageUsers` / `manageGroups` / `managePolicies` | Manager — those permissions are gone |
| Custom with `accessEventLogs` / `accessImportExport` / `accessReports` | Manager — those permissions are gone |
| plain User | plain User with `access_all = FALSE` |

Per-collection assignments (`users_collections`, `collections_groups`) and `groups.access_all` are
untouched. Only `users_organizations` changes.

Two of those rows do not come back byte-identical to what the database held before the *upgrade*,
because the information no longer exists to reconstruct them:

- **Owner/Admin always come back with `access_all = TRUE`**, even if the flag was `FALSE` for them
  before. The upgrade dropped the column precisely because Owners and Admins reach every collection
  through their role, so the original value is unknown afterwards. It grants them nothing they did
  not already have as Owner/Admin; the visible difference is that unassigned collections show up in
  their personal vault view again.
- **A plain User that carried `access_all` comes back with `access_all = FALSE`.** The upgrade wrote
  that member's reach out as explicit per-collection assignments before dropping the bit, and those
  rows are left untouched here — so the member keeps access to the collections that existed at
  upgrade time, just not automatically to ones created afterwards.

Edit-any-collection deliberately does **not** become `access_all` on its own: in the old schema that
flag also carried the legacy "manage all collections" authority including deletion, so a member who
only held Edit must not come back with delete rights.

## How to run it

Stop every Vaultwarden instance and take a backup first. Then:

```bash
# SQLite
sqlite3 /path/to/data/db.sqlite3 < tools/custom_role_rollback/sqlite.sql

# MySQL / MariaDB
mysql -u <user> -p <database> < tools/custom_role_rollback/mysql.sql

# PostgreSQL
psql -U <user> -d <database> -v ON_ERROR_STOP=1 -f tools/custom_role_rollback/postgresql.sql
```

Run it exactly once — a second run fails because the permission columns are already gone. On
MySQL/MariaDB the statements cannot be wrapped in a transaction (DDL commits implicitly there); if
the script is interrupted, restore the backup and start over. SQLite and PostgreSQL apply the whole
script atomically.

Afterwards start the older Vaultwarden version. Upgrading again later re-applies the seven
migrations from a clean state.

## Reverting with the Diesel CLI instead

For development checkouts the down migrations do the same thing step by step. The newest one refuses
by default so an accidental revert cannot silently destroy the permission data; acknowledge it
explicitly first:

```sql
CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
```

Then `diesel migration revert` works as usual. The rollback scripts above drop that table again.
