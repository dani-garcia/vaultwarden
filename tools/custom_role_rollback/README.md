# Rolling back the Custom-role change

The Custom-role change removes the membership `access_all` column and adds nine permission columns.
A Vaultwarden version from before that change cannot start against the new schema, because its
`schema.rs` still expects `access_all` to exist.

Vaultwarden only ever applies *pending* migrations — it never reverts one on its own — so putting the
old image back is not enough. Run the script for your backend once and the old version starts
again.

## Choosing which members come back as Manager

The old and new role models are not ordered, so this is a decision, not a conversion. The legacy
Manager role is **not** a subset of what a Custom member holds: it manages — and deletes — every
collection reachable through `users_collections.manage`, `collections_groups.manage` or
`groups.access_all`, and it reads member and collection ACL details through `ManagerHeadersLoose`.
None of that needs a permission flag in the old schema. Mapping every Custom member to Manager would
therefore *grant* authority during a downgrade: a member with `deleteAnyCollection = false` but a
direct or group-based manage grant would come back able to delete those collections, and a member
with no permissions at all would come back able to read the organization's member list.

So the scripts map to Manager only what you list, and everything else to plain User. Create the list
with every Vaultwarden instance stopped, right before running the rollback:

```sql
CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid TEXT NOT NULL PRIMARY KEY);
```

Use `CHAR(36)` instead of `TEXT` on MySQL/MariaDB and PostgreSQL. An empty list is a valid answer and
maps every Custom member to plain User. To add members, list the candidates and pick from them:

```sql
SELECT uuid, user_uuid, org_uuid, status,
       manage_users, manage_groups, manage_policies,
       create_new_collections, edit_any_collection, delete_any_collection,
       access_event_logs, access_import_export, access_reports
FROM users_organizations WHERE atype = 4;

INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid) VALUES ('<MEMBERSHIP_UUID>');
```

The decision is deliberately taken **now**, from what each membership holds today, rather than from
any record of who was a Manager before the upgrade. Such a record would describe the state at the
time of the *first* upgrade and would never be updated afterwards, so a member whose Manager powers
an owner has since reduced — or who was demoted to User and later re-created as a limited Custom
member — would be handed the whole legacy role back. Historical provenance is evidence, not
authorization, and the upgrade therefore keeps none.

## What is lost

The old schema has nowhere to store the nine permissions, so they are dropped:

| Before the rollback | After |
|---|---|
| Owner / Admin | Owner / Admin with `access_all = TRUE` |
| Custom **on the allowlist**, with all three collection permissions | Manager with `access_all = TRUE` |
| Custom **on the allowlist**, with only some collection permissions | Manager with `access_all = FALSE` |
| Custom not on the allowlist | plain User with `access_all = FALSE` |
| plain User | plain User with `access_all = FALSE` |

Per-collection assignments (`users_collections`, `collections_groups`) and `groups.access_all` are
untouched. Only `users_organizations` changes, so a member mapped to plain User keeps every grant
those tables carry and loses only the organization-wide powers the old schema cannot express. A
member who comes back as Manager and is still in an organization-local `accessAll` group gets the
group-derived collection authority back automatically — the old binary derives it live from
`groups.access_all`, which the upgrade never touched.

One row does not come back byte-identical to what the database held before the *upgrade*, because
the information no longer exists to reconstruct it:

- **Owner/Admin always come back with `access_all = TRUE`**, even if the flag was `FALSE` for them
  before. The upgrade dropped the column precisely because Owners and Admins reach every collection
  through their role, so the original value is unknown afterwards. It grants them nothing they did
  not already have as Owner/Admin; the visible difference is that unassigned collections show up in
  their personal vault view again.

A plain User carrying `access_all` cannot reach this point at all: the upgrade refuses to start on
such a database and asks an owner to resolve it first, precisely so that no rollback has to guess
what the bit meant. For the same reason a Custom member mapped to plain User never keeps `access_all`
— that combination is the one legacy state the upgrade refuses, and leaving it behind would make the
database unable to move forward again.

Edit-any-collection deliberately does **not** become `access_all` on its own: in the old schema that
flag also carried the legacy "manage all collections" authority including deletion, so a member who
only held Edit must not come back with delete rights.

## How group-derived Manager authority is migrated

Before the Custom role, a Manager could reach every collection of an organization in two ways: the
membership's own `access_all` bit, or membership of an organization-local group with `accessAll`.
The upgrade preserves both, deterministically and without asking:

| Legacy Manager has | After the upgrade |
|---|---|
| membership `access_all = TRUE` | `createNewCollections` + `editAnyCollection` + `deleteAnyCollection` |
| only an organization-local `accessAll` group | `editAnyCollection` + `deleteAnyCollection` |
| neither | no collection permission |

Collection *creation* is deliberately not granted in the second row: it always required the
membership bit, never the group.

The second row is a policy choice worth knowing about. The group-derived capability used to be
dynamic — it ended when the group was deleted, when its `accessAll` was cleared, when the member left
it, and it was inert whenever `ORG_GROUPS_ENABLED` was false. Nothing in the new model is bound to a
group like that, so it becomes a membership permission and therefore:

- it no longer lapses when the last qualifying group disappears, or when `accessAll` is cleared;
- it applies even with the groups feature switched off;
- `editAnyCollection` additionally satisfies `has_full_access()`, so the member reaches every
  collection directly rather than through the group.

That is accepted on purpose. The alternatives are worse: silently dropping the permission would
revoke access these members have today, and refusing to migrate would block an ordinary upgrade from
an official Vaultwarden database. After the upgrade the permission is visible in the member's
permission list and an owner can clear it with a checkbox — which is more than the old model offered,
where the same authority was invisible on the membership.

`groups.access_all` and every `groups_users` row are left exactly as they are, so the group keeps
granting collection *access* to its members as before. A `groups_users` row pointing at another
organization's `accessAll` group conveys nothing, exactly as it conveys nothing today.

Status is not part of the rule: an invited, accepted or revoked membership is converted like a
confirmed one. None of them holds authority in that state, and the permission is what the membership
would come back with if it is ever restored — which is exactly what `access_all` would have done.

The only state the upgrade refuses outright is a plain **User** carrying membership `access_all`; see
above. That refusal can also be resolved without any SQL, once for the whole instance, by setting
`LEGACY_USER_ACCESS_ALL_MIGRATION` to `drop` (clear the flag; each member keeps the collections they
are explicitly assigned to) or `materialize` (write the reach out as explicit assignments first,
confirmed memberships only, then clear it). The setting is read only while that migration is pending.

## How to run it

Stop every Vaultwarden instance and take a backup first. Create the allowlist as described above.
Then:

```bash
# SQLite
sqlite3 -bail /path/to/data/db.sqlite3 < tools/custom_role_rollback/sqlite.sql

# MySQL / MariaDB
mysql -u <user> -p <database> < tools/custom_role_rollback/mysql.sql

# PostgreSQL
psql -U <user> -d <database> -v ON_ERROR_STOP=1 -f tools/custom_role_rollback/postgresql.sql
```

Every script begins with a **read-only precondition** that inspects the schema and the migration
ledger before it touches anything, and refuses unless all of these hold:

- membership `access_all` is gone (so the upgrade did run, and this script has not),
- all nine permission columns exist,
- the Custom-role migration `20260630120000` is recorded in `__diesel_schema_migrations`,
- **no migration newer than `20260630120000` is recorded** — this script does not know what a later
  migration changed, and removing only the Custom-role version would leave the ledger claiming a
  migration whose schema objects may have been undone,
- **`__vw_rollback_manager_allowlist` exists**, and on MySQL/MariaDB has exactly one non-nullable,
  uniquely indexed `users_organizations_uuid` column — a table of the right name but the wrong shape
  would otherwise pass every check and then fail on the first read, *after* the first `ALTER TABLE`
  has already committed implicitly,
- SQLite only: **`users_organizations` has exactly the eighteen expected columns, two indexes and no
  triggers.** The SQLite script rebuilds the table from a fixed column list, so anything it does not
  know about would be dropped along with its data. The column check uses `pragma_table_xinfo`, which
  unlike `table_info` also reports generated columns, and the index check counts `pragma_index_list`
  rather than `sqlite_master`, because the index behind a `UNIQUE` constraint has no SQL text and
  would otherwise be invisible.

A second run, or a half-finished upgrade, is therefore refused with a message that names the reason
and leaves the database exactly as it was. This matters most on MySQL/MariaDB, where nothing can be
rolled back: without the check, a database whose `access_all` was already dropped but whose
permission columns were never added would get through the first `ADD COLUMN` and the value rewrites
before failing on the `DROP COLUMN` — ending up less consistent than before.

The PostgreSQL script resolves `users_organizations`, `__diesel_schema_migrations` and
`__vw_rollback_manager_allowlist` once each, requires all of them to live in the **same** schema, and
addresses that schema explicitly from then on. An unqualified name is otherwise resolved per
statement through `search_path`, so a session with `search_path = decoy, real` could have the table
rewrite land in one schema and the ledger delete in another.

The MySQL/MariaDB script ends with an explicit `COMMIT`. Everything before it is DDL and commits
implicitly, but the final ledger `DELETE` is plain DML: under `autocommit = 0` it would be rolled
back on disconnect, leaving the schema old while the migration still counts as applied — and a later
upgrade would then skip it and start new code against the old schema.

**Do not drop the `-bail` / `ON_ERROR_STOP=1` flags, do not pass `--force` to `mysql`, and do not run
these through a client that keeps going after a failed statement.** The sqlite3 shell continues after
errors by default; the script sets `.bail on` itself, but that is a shell command a different runner
will ignore. A runner that carries on past a failing statement would reach the `DROP TABLE` and commit
an empty `users_organizations`.

SQLite and PostgreSQL apply the script in a single transaction, so an aborted run leaves the
database untouched. On MySQL/MariaDB the statements cannot be wrapped in a transaction (DDL commits
implicitly there); the precondition is what keeps a mismatch from being mutated at all, but if the
script is interrupted *after* it passed, restore the backup and start over.

The SQLite script rebuilds `users_organizations` instead of using `ALTER TABLE ... DROP COLUMN`, which
only exists since SQLite 3.35 — the same reason the forward migration rebuilds the table. It therefore
also works against the older system SQLite that `sqlite_system` builds link.

Afterwards start the older Vaultwarden version. Upgrading again later re-applies the migration from a
clean state: it reads the restored `atype = 3` rows directly and converts them deterministically,
so the round trip converges.

## Reverting with the Diesel CLI instead

For a development checkout, `2026-06-30-120000/down.sql` does the same thing. It refuses by default
and needs the same two decisions the scripts above take, in the same order:

```sql
CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid TEXT NOT NULL PRIMARY KEY);
```

Then `diesel migration revert` works as usual. Both tables are dropped by the revert they authorize,
so one decision covers one downgrade, and `2026-06-30-120000/up.sql` clears a leftover
acknowledgement as well, so consent never carries over into a later, unrelated revert.

Unlike the standalone scripts, the down migration has no precondition beyond those two guards: it is
a development path, and Diesel already knows the migration is recorded.

On MySQL/MariaDB the revert **cannot be resumed**: every `ALTER TABLE` commits on its own, while
Diesel deletes the ledger row in a separate statement afterwards. A crash in between leaves the
columns gone and the migration still recorded as applied; re-running it then fails with
`Unknown column` (1091) and the only way out is the backup. The down migration adds and drops its
columns in one `ALTER TABLE` each rather than one per column, which is the closest this backend gets
to all-or-nothing, and temporary guard tables are removed with `DROP TEMPORARY TABLE`, which is one
implicit commit fewer and cannot hit a permanent table of the same name by accident. Use `mysql.sql`
above for anything you care about.
