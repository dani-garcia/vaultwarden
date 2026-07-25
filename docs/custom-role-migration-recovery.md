# Custom-role migration recovery

Vaultwarden deliberately stops the Custom-role migration when the old database state cannot be
translated without either removing access or adding new management authority. A failed preflight
does not authorize Vaultwarden to choose between those outcomes.

## Before doing anything

1. Stop every Vaultwarden instance that uses the database. Do not perform this migration during a
   rolling deployment.
2. Take and verify a full database backup.
3. Keep the complete startup error. It identifies the state that needs review.
4. Do not add or delete rows in `__diesel_schema_migrations` merely to bypass the preflight.

The relevant versions are:

| Version | Purpose |
|---|---|
| `2026-07-15-120000` | Mark that `2026-07-16` is pending in the same migration sequence |
| `2026-07-16-120000` | Add the three collection-permission columns |
| `2026-07-23-120000` | Reconcile legacy Manager/Custom membership permissions |
| `2026-07-24-120000` | Drop membership-level `access_all` |
| `2026-07-24-130000` | Add the three Custom Access permissions |
| `2026-07-24-140000` | Refuse a lossy Custom-role downgrade |

Diesel stores these directory versions without punctuation in `__diesel_schema_migrations` (for
example, `2026-07-16-120000` is stored as `20260716120000`).
The immutable `2026-06-30-120000` migration is an earlier prerequisite; this table focuses on the
new marker/repair/drop/downgrade safety sequence.

## Legacy User with membership `access_all`

Find the affected memberships before the source column is dropped:

```sql
SELECT uuid, user_uuid, org_uuid, status
FROM users_organizations
WHERE atype = 2 AND access_all = TRUE;
```

This state was accepted by older Vaultwarden versions. It has no exact representation in the new
nine-bit Custom-role model:

- clearing `access_all` keeps the User role but removes organization-wide vault access;
- changing the member to Custom with all three collection permissions preserves broad vault access,
  but also grants collection-management capabilities the old User role did not have.

An organization owner must decide the intended role and permissions for each result. Make that
change on the backed-up pre-drop database and record the decision:

- to keep the member a normal User, set that membership's `access_all` to false;
- to intentionally promote the member to Custom with Create/Edit/Delete-any authority, set that
  membership's `atype` to the legacy Manager value `3` and keep `access_all` true. The repair copies
  the bit to all three collection permissions before converting `atype` to `4`.

Apply either change by exact membership UUID while all Vaultwarden instances are stopped. Do not
bulk-promote these records automatically.

## Group-derived legacy collection management

An organization-local `groups.access_all` relationship is safe when the membership has no direct
collection permissions. During a normal upgrade, the older `2026-07-16` migration temporarily
copies that relationship to the exact direct `create/edit/delete = 0/1/1` pattern. The new repair
recognizes the still-present, organization-bound source and deterministically resets the direct
Edit/Delete bits to false **only** when the durable `2026-07-15` marker proves that `2026-07-16` was
pending in the same migration sequence. Vault access remains group-derived, so removing the member
from the group also removes that access.

The marker survives a process failure between `2026-07-16` and `2026-07-23`, allowing the next
startup to finish the deterministic repair. `2026-07-23` transactionally clears the marker row only
after all guards and data updates succeed. The empty internal bookkeeping table is intentionally
retained so MySQL does not introduce a DDL commit boundary. Do not create, remove, or populate
`__vw_custom_role_same_run_0716` manually.

The preflight stops only when the three columns already exist and it finds a `0/1/1` pattern. At
that point the values may be either an intentional direct Edit+Delete grant or an older group
backfill whose source group was removed; the database has no provenance bit that can distinguish
them.

For each stopped `0/1/1` membership, the owner must choose one of these executable outcomes:

- **Group-derived or obsolete:** set `edit_any_collection` and `delete_any_collection` to false for
  that exact membership. Leave the intended group relationship in place if access should remain
  group-derived. The next preflight can then proceed.
- **Intentionally direct Edit+Delete:** while every server is stopped, temporarily set
  `create_new_collections` to true for that exact membership. The unambiguous `1/1/1` state passes
  the repair and is not treated as a group backfill. Run the migration in a maintenance instance
  that is not reachable by clients, stop it as soon as all six recovery-sequence versions listed
  above are recorded, then set `create_new_collections` back to false before normal service resumes.
  This restores the explicitly reviewed direct `0/1/1` state after the repair marker exists.

The organization boundary used to identify a current group source is:

```sql
SELECT DISTINCT uo.uuid, uo.org_uuid, g.uuid AS group_uuid
FROM users_organizations AS uo
INNER JOIN groups_users AS gu ON gu.users_organizations_uuid = uo.uuid
INNER JOIN groups AS g ON g.uuid = gu.groups_uuid
WHERE uo.atype IN (3, 4)
  AND uo.access_all = FALSE
  AND g.organizations_uuid = uo.org_uuid
  AND g.access_all = TRUE;
```

On MySQL, quote the table as `` `groups` ``. Review direct `0/1/1` records separately:

```sql
SELECT uuid, user_uuid, org_uuid
FROM users_organizations
WHERE atype IN (3, 4)
  AND access_all = FALSE
  AND create_new_collections = FALSE
  AND edit_any_collection = TRUE
  AND delete_any_collection = TRUE;
```

Because an explicit Edit+Delete assignment has the same stored values as the historical derived
state, Vaultwarden cannot classify those records automatically. Never use the temporary Create bit
while a server is accepting client traffic.

## The `access_all` column was already dropped

If `2026-07-24-120000` is recorded but `2026-07-23-120000` is not, restore a backup from before the
drop and migrate again after resolving the cases above. The old membership bit is no longer present,
so a later migration cannot prove which members had it.

If no such backup exists, perform a membership-by-membership authorization review using
administrative records before changing roles or flags. Only after the final state has been reviewed
may an operator mark the repair version as resolved. Vaultwarden intentionally provides no automatic
command for this irreversible case.

## Historical MySQL partial `2026-07-16` migration

An older branch revision could fail on the unquoted `groups` identifier after MySQL had already
committed all three `ADD COLUMN` statements. The migration version was not recorded, so a normal
retry then failed on duplicate columns.

Vaultwarden automatically completes this state only when all of the following are true:

- `2026-07-16-120000` is absent from the ledger;
- all three expected columns exist, are non-null booleans, and default to false;
- `access_all` still exists and `2026-07-24-120000` has not run;
- the stored values are either the untouched false defaults, the values produced by the canonical
  membership-`access_all` copy, or exact `0/1/1` values accompanied by both the durable same-run
  marker and a current same-organization `groups.access_all` source; and
- neither a legacy User/access-all case nor ambiguous group provenance exists.

It then reapplies the canonical membership data copy and inserts the ledger row in one transaction.
For the narrowly accepted same-run `0/1/1` crash state, that copy first reconstructs `0/0/0`; the
pending canonical group backfill and `2026-07-23` repair then run normally. A missing group source,
any other partial column set, changed definition, or unexpected value stops startup. Preserve that
database and repair it manually from the verified backup; do not drop columns that may contain
independently changed permissions.

## Verification after recovery

After a successful start, verify:

```sql
SELECT version
FROM __diesel_schema_migrations
WHERE version IN (
    '20260715120000',
    '20260716120000',
    '20260723120000',
    '20260724120000',
    '20260724130000',
    '20260724140000'
)
ORDER BY version;

SELECT COUNT(*) AS invalid_manager_types
FROM users_organizations
WHERE atype = 3;
```

All six versions must be present and `invalid_manager_types` must be zero. Then test a fresh login,
sync, collection read/edit/delete, and group removal for every membership that was reviewed.

## Downgrade guard

The old schema cannot encode nine independent permissions in its single membership `access_all`
bit. Even a state that currently happens to use only `0/0/0` or `1/1/1` could be changed after a
one-step guard was reverted and before a later incremental downgrade. A conditional guard would
therefore create false confidence.

The newest migration always stops an automatic downgrade with a duplicate-key error in the
`__vw_custom_role_downgrade_guard` temporary table, before any production permission column or
migration-ledger row is removed. This mechanism is enforced by primary keys on SQLite, PostgreSQL,
MySQL 5.7+, and MariaDB; it does not rely on historically ignored MySQL `CHECK` constraints. This is
intentional.

Rollback requires either:

- restoring a verified database backup taken before the Custom-role upgrade; or
- an explicit offline transformation plan that exports all permissions, defines the accepted
  semantic loss or role changes membership by membership, and is tested against a disposable copy
  on the same database backend.

Do not delete the `20260724140000` ledger row merely to bypass this protection.
