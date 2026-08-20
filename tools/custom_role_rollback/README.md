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

The upgrade records which memberships held the Manager role beforehand, in
`__vw_custom_role_legacy_manager`. That is useful evidence, and copying it over is a reasonable
starting point:

```sql
INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid)
SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager;
```

But it is deliberately **not** used automatically. It records who was a Manager before the *first*
upgrade and is never updated afterwards, so a member whose Manager powers an owner has since reduced
— or who was demoted to User and later re-created as a limited Custom member — would be handed the
whole legacy role back. Historical provenance is evidence, not authorization.

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
those tables carry and loses only the organization-wide powers the old schema cannot express.

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

## The upgrade asks one question of its own

Migration `2026-08-10-120000` stops the *upgrade* — not the rollback — when a Custom member holds
`editAnyCollection` or `deleteAnyCollection` and belongs to an organization-local group with
`accessAll`. It grants nothing and revokes nothing; it exists because that combination is the one
place where the new model cannot reproduce the old semantics.

Before the Custom role, a Manager who reached every collection through such a group held that
authority *while* the group relationship lasted: it ended when the group was deleted, when its
`accessAll` was cleared, when the member left it, and it was inert whenever `ORG_GROUPS_ENABLED` was
false. Nothing in the new model expresses a permission bound to a group like that — the permissions
live on the membership. The earlier migrations in the chain therefore write the authority onto the
membership, and the result is deliberately not identical to what it replaces:

- it no longer lapses when the last qualifying group disappears, or when `accessAll` is cleared;
- it applies even with the groups feature switched off;
- `editAnyCollection` additionally satisfies `has_full_access()`, so the member reaches every
  collection directly rather than through the group.

Doing that silently would be a migration granting durable organization-wide collection edit and
delete on its own authority; dropping it silently would take a capability away. Neither is the
migration's call, so it hands the decision to an owner. On a database with no Custom membership that
both has edit/delete authority and belongs to an organization-local `accessAll` group, there is
nothing to decide and it is a no-op.

**Start Vaultwarden once to get the question.** The startup preflight looks ahead for the same
condition, from the legacy schema as well as the migrated one, and refuses with the review query, the
three differences above and the acknowledgement statement
(`RefuseUnconfirmedPermanentCollectionAuthority` in `src/db/mod.rs`). The migration keeps its own
guard as the backstop for a bare `diesel migration run`, but Diesel reports only the driver error
there, so on that path the question arrives as nothing but a duplicate-key violation on
`__vw_permanent_authority_guard`.

Every matching membership is asked about, including a recorded legacy Manager with
`createNewCollections` set. That flag is an independent permission an owner can change after an
earlier revision materialized group-derived edit/delete, so its current value is not reliable
historical provenance. This deliberately prefers a conservative extra question over silently making
group-derived authority permanent. A membership whose own legacy `access_all` supplied all three
permissions may therefore be listed even though nothing changes meaning for it. An invited or revoked
membership is asked about too: it holds no authority today, but the permission is what it would come
back with if it is ever restored.

Answering the question is a different statement depending on when you are asked, because the
preflight looks ahead from both schemas. Before the upgrade has run there is nothing to clear — the
permission columns do not exist yet — so declining means ending the group relationship the authority
comes from, either for one membership (`DELETE FROM groups_users …`) or for the whole group
(`UPDATE groups SET access_all = FALSE …`). Once the columns exist, clear them directly. Doing that
after the upgrade is equally safe: Vaultwarden does not start until the acknowledgement is recorded,
so nothing is ever live in between. The refusal prints both statements.

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
- all nine Custom-role migrations are recorded in `__diesel_schema_migrations`,
- **no migration newer than `20260810120000` is recorded** — this script does not know what a later
  migration changed, and removing only the Custom-role versions would leave the ledger claiming a
  migration whose schema objects may have been undone,
- **`__vw_custom_role_history_verified` exists**, i.e. this database's Custom-role history was
  produced by the migrations that ship today (see the next section),
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
access-permission columns were never added would get through the first `ADD COLUMN`, the value
rewrites, the type change and six `DROP COLUMN`s before failing on the seventh — ending up less
consistent than before.

The PostgreSQL script resolves `users_organizations`, `__diesel_schema_migrations`,
`__vw_rollback_manager_allowlist` and `__vw_custom_role_history_verified` once each, requires all of
them to live in the **same** schema, and addresses that schema explicitly from then on. An
unqualified name is otherwise resolved per statement through `search_path`, so a session with
`search_path = decoy, real` could have the table rewrite land in one schema and the ledger delete in
another.

The MySQL/MariaDB script ends with an explicit `COMMIT`. Everything before it is DDL and commits
implicitly, but the final ledger `DELETE` is plain DML: under `autocommit = 0` it would be rolled
back on disconnect, leaving the schema old while all nine migrations still count as applied — and a
later upgrade would then skip them and start new code against the old schema.

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

Afterwards start the older Vaultwarden version. Upgrading again later re-applies the nine
migrations from a clean state, and rebuilds `__vw_custom_role_legacy_manager` from the very
`atype = 3` rows the rollback restored — so the round trip converges.

## Databases upgraded before the history marker existed

`__vw_custom_role_history_verified` is created by `2026-06-30-120000`, and nothing else creates it.
A database upgraded by an earlier revision of this feature branch carries that migration's version in
its ledger without the table, and Diesel never re-runs a recorded version — so Vaultwarden refuses to
start and the rollback scripts refuse to run, rather than acting on migrations whose effects were
different.

Start Vaultwarden once: it prints the full recovery, which depends on how far the earlier revision
got and covers up to three things — recording which memberships were legacy Managers, reviewing
permissions an earlier `20260809120000` granted in bulk to Custom members of `accessAll` groups, and
reviewing the direct collection assignments an earlier `20260723120000` wrote for a plain User that
carried membership `access_all`. If you still have the backup from before the first upgrade,
restoring it and upgrading again is simpler and needs no decision at all.

The marker is created as a separate statement from the legacy-Manager record on purpose. That record
is data an operator has to be able to write during recovery, so its existence must not double as
evidence that the history behind it was reviewed — otherwise creating it empty to make the error
message go away would silently pass as the audit it is asking for.

## Reverting with the Diesel CLI instead

For development checkouts the down migrations do the same thing step by step. **Every one of them that
loses permission data refuses by default** — `2026-07-24-130000`, `2026-07-16-120000` and
`2026-06-30-120000` — and so does `2026-07-24-140000`, which loses nothing itself and exists to stop
the chain before the first destructive step. `2026-08-10-120000` and `2026-08-09-120000` are reverted
first and are no-ops. Acknowledge the downgrade once:

```sql
CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
```

Then `diesel migration revert` works as usual for the whole chain. The acknowledgement is deliberately
*not* consumed by the first guard it satisfies: it is dropped by the oldest lossy migration
(`2026-06-30-120000`), so one decision covers one downgrade and a revert that stops halfway is still
guarded when it resumes. Re-upgrading clears a leftover acknowledgement
(`2026-07-24-140000/up.sql`), so consent never carries over into a later, unrelated revert. The
rollback scripts above drop the table as well.

The down migrations use the same allowlist as the scripts above. Unlike the scripts they do not
refuse when `__vw_rollback_manager_allowlist` is missing — they create it empty, which means "nobody"
and maps every Custom member to plain User. Populate it first if that is not what you want.

On SQLite the down migrations do use `ALTER TABLE ... DROP COLUMN` and therefore need SQLite 3.35 or
newer. That is fine for a development checkout with a bundled SQLite; operators on an older system
SQLite should use `sqlite.sql` above, which rebuilds the table instead.

### MySQL/MariaDB: supported for development checkouts only

On MySQL/MariaDB the Diesel revert chain **cannot be resumed**, and `2026-07-24-140000/down.sql`
requires a second, separate acknowledgement that says so:

```sql
CREATE TABLE __vw_allow_unresumable_mysql_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
```

Every `ALTER TABLE` there commits on its own, while Diesel deletes the ledger row in a separate
statement afterwards. A crash in between leaves the columns gone and the migration still recorded as
applied; re-running it then fails forever with `Unknown column` (1091), the startup preflight refuses
the database — correctly — and the only way out is the backup. Making it resumable would need
conditional DDL, i.e. a stored procedure created before the checks have run. Each down migration
removes its three permission columns in a single `ALTER TABLE` rather than three, which is the
closest this backend gets to all-or-nothing, and temporary guard tables are removed with
`DROP TEMPORARY TABLE`, which is one implicit commit fewer and cannot hit a permanent table of the
same name by accident. Use `mysql.sql` above for anything you care about.
