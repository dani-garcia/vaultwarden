# SCIM v2 design

Architecture and security model for the SCIM implementation in this fork.
Operator instructions live in [README.md](README.md).

## Provision and deprovision flows

```mermaid
sequenceDiagram
    autonumber
    participant Entra as Entra ID
    participant Guard as ScimToken guard
    participant H as SCIM handlers
    participant DB as Database
    participant Mail as SMTP

    Note over Entra,Mail: Provision (assign user in Entra)
    Entra->>Guard: GET /Users?filter=userName eq "a@x.com" (Bearer scim_v1...)
    Guard->>DB: verify org key digest (ct_eq)
    Guard-->>H: ScimToken{org}
    H->>DB: find user + membership
    H-->>Entra: 200 ListResponse (totalResults 0)
    Entra->>Guard: POST /Users {userName, externalId, active}
    Guard-->>H: ScimToken{org}
    H->>DB: create shell User (if new), Membership status=Invited(0)
    H->>Mail: send invite (rollback membership on failure)
    H->>DB: log event (SCIM actor)
    H-->>Entra: 201 Created {id = membership uuid}

    Note over Entra,Mail: Deprovision (unassign / soft delete)
    Entra->>Guard: PATCH /Users/{id} {op replace, active false}
    Guard-->>H: ScimToken{org}
    H->>DB: last-confirmed-owner check
    H->>DB: status -= 128 (revoke, akey kept)
    H->>DB: log event (SCIM actor)
    H-->>Entra: 200 {active: false}
```

## Membership state machine

The revocation encoding is the one non-obvious invariant in the whole
integration: revoked is a stored **offset** (`status - 128`), and the enum
value `Revoked = -1` never reaches the database. Every active/inactive
decision in the SCIM code funnels through one helper that tests
`status <= -1`.

```mermaid
stateDiagram-v2
    direction LR
    [*] --> Invited0: SCIM POST /Users
    Invited0: Invited (0)
    Accepted1: Accepted (1)
    Confirmed2: Confirmed (2)
    RevokedI: Revoked Invited (-128)
    RevokedA: Revoked Accepted (-127)
    RevokedC: Revoked Confirmed (-126)

    Invited0 --> Accepted1: user accepts invite (own session)
    Accepted1 --> Confirmed2: admin confirms (client wraps org key)

    Invited0 --> RevokedI: SCIM active false / DELETE
    Accepted1 --> RevokedA: SCIM active false / DELETE
    Confirmed2 --> RevokedC: SCIM active false / DELETE
    RevokedI --> Invited0: SCIM active true (restore, +128)
    RevokedA --> Accepted1: SCIM active true
    RevokedC --> Confirmed2: SCIM active true (akey intact, no re-confirm)

    note right of Confirmed2
        Vault access exists only here.
        The wrap happens in the admin's
        client. No server-side path can
        produce Membership.akey.
    end note
```

Why confirm cannot be automated server-side, verified against source:

- `Organization.private_key` is stored encrypted under the org symmetric key;
  the server cannot decrypt it.
- `confirm_invite_impl` only stores an opaque client-computed blob into
  `Membership.akey`.
- Account Recovery cannot substitute: enrollment is self-service and needs
  the user's master password, and `recover_account` requires the member to
  already be Confirmed. It is gated behind the state it would need to reach.

A future companion *confirm-worker* (a headless client holding an admin
account, wrapping keys client-side and posting `bulk_confirm_invite`) could
automate step three without weakening zero-knowledge. It is deliberately not
part of the server.

## Authentication

The credential is a per-organization static bearer token,
`scim_v1.<org_uuid>.<secret>`, because Entra's provisioning client sends a
fixed Secret Token and cannot run an OAuth flow (which rules out reusing the
one-hour organization api-key JWT that `/api/public` uses).

- The secret is 32 random bytes (256 bits). At rest it exists only as a
  sha256 hex digest in the `scim_api_key` table.
- sha256 instead of argon2 is deliberate: argon2's cost is protection for
  low-entropy human passwords. This secret is machine-generated at full
  entropy, so digest inversion is infeasible, while per-request argon2 on an
  unauthenticated endpoint would be a denial-of-service amplifier during
  Entra's sync bursts.
- Verification uses a constant-time compare, with a dummy compare when no
  key row exists. The dominant timing signal is still the database lookup;
  the dummy compare is hygiene, not a timing-proof guarantee.
- An active `scim_api_key` row is also the per-org enable switch; the global
  `SCIM_ENABLED` config is the master gate. Both must hold.
- Generation and rotation require an interactive org admin session plus
  master-password or OTP re-authentication. Rotation replaces the row, so
  the previous token dies instantly. The plaintext is returned exactly once
  and never logged.

```mermaid
flowchart TD
    A[Request to /scim/v2/org_id/...] --> B{Rate limit by client IP}
    B -- exceeded --> R429[429 SCIM error]
    B --> C{SCIM_ENABLED}
    C -- no --> R401
    C --> D{Bearer parses as scim_v1.org.secret}
    D -- no --> R401
    D --> E{token org == path org}
    E -- no --> R401
    E --> F{active scim_api_key row for org}
    F -- "no (dummy ct_eq burned)" --> R401
    F --> G{ct_eq sha256 of secret vs stored digest}
    G -- no --> R401
    G --> H[ScimToken org_uuid to handler]
    H --> I[Handler scopes every query to token org]

    R401[Uniform 401 SCIM error body]

    style R401 fill:#7a1f1f,color:#fff
    style R429 fill:#7a5a1f,color:#fff
    style H fill:#1f5c2e,color:#fff
```

Every 401 leaving the mount is byte-identical regardless of which check
failed (asserted by test); causes are logged server-side only. Misses on
filters return empty lists and unknown ids return the same 404 as another
org's ids, so the surface does not confirm what exists.

## Module layout

```mermaid
flowchart LR
    subgraph scim [src/api/scim]
        guard[guard.rs\nScimToken]
        errm[error.rs\nSCIM envelope + catchers]
        filter[filter.rs\neq filter parser]
        patchm[patch.rs\nPatchOp user/group]
        modelsm[models.rs\nserde requests]
        usersm[users.rs\n/Users handlers]
        groupsm[groups.rs\n/Groups handlers]
        disc[discovery.rs\nSPConfig/ResourceTypes/Schemas]
        manage[manage.rs\ntoken mgmt under /api]
    end

    subgraph core [existing Vaultwarden]
        ratelimit[ratelimit.rs]
        cryptom[crypto.rs ct_eq/sha256]
        events[core/events.rs log_event]
        models[db/models Membership/Group/ScimApiKey]
    end

    guard --> ratelimit
    guard --> cryptom
    guard --> models
    usersm --> patchm
    usersm --> filter
    usersm --> modelsm
    groupsm --> patchm
    groupsm --> filter
    usersm --> events
    groupsm --> events
    usersm --> models
    groupsm --> models
    manage --> models
    usersm --> errm
    groupsm --> errm
    disc --> guard
```

The `/scim` mount carries its own catchers so every error, including ones
Rocket generates before a handler runs, is a SCIM `Error` envelope. Token
management deliberately lives under `/api` with `AdminHeaders`: the SCIM
surface itself can never mint or rotate its own credential.

## Semantics that differ from a naive SCIM reading

| Topic | Choice | Reason |
|---|---|---|
| DELETE /Users | revoke, not delete | preserves `akey`; restore is lossless; compromised token cannot destroy state |
| Roles | not synced (always User) | `Custom` collapses to Manager in `MembershipType::from_str`; no honest round-trip |
| userName/displayName updates | accepted, ignored | email is login identity; `user.name` is global to the person; erroring would fail every directory rename sync |
| Group DELETE | real delete | groups carry no E2EE state |
| Group members | diff add/remove; replace only on PUT/replace | Entra PATCHes diffs, including `members[value eq "..."]` removal paths |
| Groups when disabled | loud 501 | `ldap_import` silently skips; silence hides misconfiguration in the IdP |
| Filter misses | empty 200 list | Entra Test Connection probes a random user; distinguishable misses enable enumeration |

## Test strategy

All tests are inline (bin-only crate). The integration harness runs the real
Rocket router with a temporary sqlite database. A `#[ctor]` constructor in
the `test-support` workspace crate rewrites the process environment before
`main`, because `CONFIG` is a process-global that reads `.env` at first
touch: without this, tests would inherit the developer's live configuration.
The main crate forbids `unsafe`, so the `set_var` calls live in
`test-support`. Integration tests serialize on a mutex and share one
never-dropped pool (sqlite WAL locking).

Covered end to end: the full provision / deprovision / restore lifecycle at
every status offset (`-126`, `-127`, `-128`), duplicate and last-owner
conflicts, uniform-401 byte-equality, enumeration shape, Entra PATCH quirks
(op casing, string booleans, path-less values, filter-path member removal),
pagination edges, and the rate limiter.
