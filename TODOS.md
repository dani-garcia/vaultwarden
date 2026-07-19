# TODOS

## SCIM

### Config-gated denial tests (SCIM_ENABLED=false, ORG_GROUPS_ENABLED=false)

**What:** Test the two config master switches from the denied side: a valid token
against `SCIM_ENABLED=false` must get the uniform 401, and any Groups route with
`ORG_GROUPS_ENABLED=false` must get the SCIM-enveloped 501.

**Why:** These are the primary kill switches for the whole surface and the one
authz-matrix case the build plan promised that is still missing.

**Context:** `CONFIG` is a process-global `LazyLock` pinned by the `test-support`
`#[ctor]` before main, so the disabled states cannot be tested in the same
process as the enabled suite. Needs either a second test binary with its own
ctor env, or an injectable check in `guard.rs` / `groups.rs`. See the
`plan-delivery-gap-scim-disabled-authz-case` learning.

**Effort:** M
**Priority:** P1
**Depends on:** None

### Live Entra ID tenant validation

**What:** Run the full lifecycle against a throwaway Entra tenant: Test
Connection, assign user, create/update/deprovision/restore, group sync, token
rotation. Follow docs/scim/README.md as written and fix any doc drift found.

**Why:** Everything is verified against RFC 7643/7644 and observed Entra
behaviour, but no real Entra sync has run against this build yet.

**Context:** User-driven (needs a tenant). Never production. The rate limiter
keys on `IP_HEADER` (`X-Real-IP`) - the deployment in front must set it.

**Effort:** M
**Priority:** P1
**Depends on:** Branch pushed and deployed somewhere TLS-fronted

### Mail-enabled invite failure path, end to end

**What:** An integration test that runs `post_user` with mail enabled and a
failing SMTP target, asserting the 500 plus the rollback outcome.

**Why:** The rollback decision logic is unit-tested
(`provisioning_rollback_spares_preexisting_users`), but the branch that calls it
(send_invite failure inside `post_user`) still never executes under test.

**Context:** Needs mail enabled in `CONFIG` (same process-global constraint as
above) plus a fast-failing SMTP endpoint; naive versions are slow or flaky.
Consider folding into the same second test binary as the config-gated tests.

**Effort:** M
**Priority:** P2
**Depends on:** Config-gated denial tests (shared harness)

### Coverage: error-envelope edges and manage HTTP surface

**What:** Tests for the remaining actionable gaps from the ship coverage audit
(82%): malformed-body 400 / oversized-body 413 envelopes, HTTP-level 429
envelope, POST /Users missing/invalid email 400s, policy-blocked restore 400,
GroupPatch path-less object form (Entra sends this shape), externalId HTTP
filters, POST /Groups blank-name 400 and dup-externalId 409, and the manage
endpoints driven over HTTP with AdminHeaders.

**Why:** These are the branches where a regression would surface to Entra as a
wrong status code or envelope, currently proven only by adjacent coverage.

**Context:** All testable in the existing Rocket-local harness except the
manage endpoints, which need an AdminHeaders fixture. Coverage map in the
2026-07-19 ship PR body has the full gap list.

**Effort:** M
**Priority:** P2
**Depends on:** None

### Performance backlog for large orgs

**What:** SQL-side pagination for /Users and /Groups lists, batched group
member writes (resolve via `eq_any`, diff instead of delete-all+reinsert on
PUT), and secondary indexes on `users_organizations(org_uuid, external_id)` and
`groups(organizations_uuid, external_id)`.

**Why:** Current implementation loads full member/group sets per list request
and issues ~4N queries for an N-member group write. Fine at self-host scale
(hundreds of members); wasteful for thousands.

**Context:** Indexes diverge from upstream's no-secondary-index convention -
decide deliberately. Review findings from 2026-07-19 have the details.

**Effort:** L
**Priority:** P3
**Depends on:** None

### Harden SCIM write edges surfaced by adversarial review

**What:** Three lower-severity robustness gaps from the 2026-07-19 adversarial
pass: (1) externalId uniqueness is check-then-set with no backing DB unique
index, so concurrent writes could duplicate the correlation key; (2) a Group
displayName > 100 chars or externalId > 300 chars from Entra hits the MySQL
column limit and returns a 500 instead of a 400 invalidValue; (3) `scim_status`
returns key metadata behind only an AdminHeaders session with no password/OTP
re-auth, unlike generate/delete.

**Why:** None are exploitable today (single Entra sync engine; strict-mode MySQL
only; admin session required), but each is an unenforced invariant or an
inconsistent guard that a future change could turn into a real bug.

**Why not now:** (1) wants a migration adding a partial unique index across three
dialects - real schema work, deferrable; (2) wants length validation in the
Group handlers; (3) is a one-line guard tightening. Bundle them.

**Effort:** M
**Priority:** P2
**Depends on:** None

## Upstream hygiene

### ip_constant clippy lints in http_client.rs tests

**What:** 9 pre-existing `clippy::ip_constant` errors in upstream
`src/http_client.rs` test code under `--all-targets` with the 1.96 toolchain.

**Why:** Blocks running `cargo clippy --all-targets` clean locally; will bite
if CI ever lints test targets.

**Context:** Upstream code, untouched per branch discipline. Fix as a separate
commit or PR upstream (`Ipv4Addr::LOCALHOST` instead of hand-coded addresses).

**Effort:** S
**Priority:** P3
**Depends on:** None

## Completed
