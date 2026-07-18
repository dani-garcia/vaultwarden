# SCIM v2 provisioning

This fork adds a SCIM v2 provisioning server (RFC 7643 / RFC 7644) so
organization membership can be driven from an identity provider. Microsoft
Entra ID is the tested IdP. Design details and diagrams: [design.md](design.md).

## What it does, honestly

- **Automated invite**: assigning a user in the IdP creates the Vaultwarden
  account (if needed) and org membership, and sends the invite email.
- **Automated deprovision**: removing a user (or setting `active: false`)
  revokes org access immediately. Restore is lossless.
- **Group sync**: group existence and membership, when `ORG_GROUPS_ENABLED=true`.
- **Not automated**: the final *Confirm* step. End-to-end encryption means the
  org key must be wrapped for each member by an admin's client; no server can
  do it. Provisioned users wait in *Invited* / *Accepted* until an admin
  confirms them in the web vault. See design.md for why this is a property of
  the encryption model, not a missing feature.

## Server setup

1. Enable SCIM in the server config (default is off):

   ```ini
   SCIM_ENABLED=true
   # optional tuning
   SCIM_RATELIMIT_SECONDS=1
   SCIM_RATELIMIT_MAX_BURST=60
   ```

2. Generate the per-organization SCIM token (requires an org admin session;
   re-authenticates with your master password like API key rotation):

   ```bash
   curl -s -X POST "$DOMAIN/api/organizations/$ORG_ID/scim/api-key" \
     -H "Authorization: Bearer $ADMIN_SESSION_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"masterPasswordHash": "..."}'
   ```

   The response contains the token (`scim_v1.<org>.<secret>`) and the tenant
   URL. **The token is shown exactly once**; only its sha256 digest is stored.
   POST again to rotate (the old token stops working immediately), DELETE the
   same path to disable SCIM for the org, GET `/scim/status` to inspect.

3. TLS is required in front of the server (Entra refuses plain http). If a
   reverse proxy sets client IPs, make sure it overwrites the `IP_HEADER`
   header (default `X-Real-IP`); the SCIM rate limiter keys on that value.

## Entra ID setup

1. Entra admin center: **Enterprise applications > New application > Create
   your own application** (non-gallery).
2. **Provisioning > Automatic**:
   - Tenant URL: `https://<your-domain>/scim/v2/<org_id>`
   - Secret Token: the `scim_v1...` value from step 2 above.
   - Test Connection, then Save.
3. **Attribute mappings** (Users):

   | Entra attribute | SCIM attribute | Vaultwarden |
   |---|---|---|
   | userPrincipalName (or mail) | `userName` | account email (lowercased) |
   | objectId | `externalId` | membership external id |
   | Switch([IsSoftDeleted], , "False", "True", "True", "False") | `active` | revoke / restore |
   | displayName | `displayName` | account name (set at creation only) |

   Map `userName` from **mail** rather than userPrincipalName if your UPNs
   are not routable mailboxes: the value must be a deliverable email address,
   because it becomes the Vaultwarden login and receives the invite.

   Recommended: delete the default mappings this server does not sync
   (`roles`, `preferredLanguage`, `title`, addresses, phones). They are
   accepted and ignored, but trimming them keeps the Entra sync log clean.

4. Groups: map `displayName` and `objectId` to `externalId`. Members sync as
   diffs. Assign users before (or together with) their groups; a group member
   who is not yet provisioned as a user is rejected until the user sync runs.
5. Assign users/groups to the app and start provisioning. Entra's initial
   cycle lists existing users first (`userName eq` filters), then creates.

## Behaviour notes and deviations

- **DELETE = revoke.** Both Entra soft delete (`active: false`) and hard
  DELETE revoke the membership. The row and its keys survive, so restoring a
  returning user needs no re-confirmation. No destructive operation is
  exposed to the IdP at all. This is a deliberate deviation from RFC 7644.
- **Roles are not synced.** Everyone provisions as the User role;
  promote people in the web vault. Vaultwarden's Custom role cannot round-trip
  through SCIM.
- **userName / displayName changes are not synced after creation.** The email
  is the login identity; the display name belongs to the person globally, not
  to one org's directory. Renames in Entra succeed (accepted and ignored)
  rather than erroring the sync.
- **SCIM user id** is the org membership id, not the account id. The same
  person in two orgs has two SCIM ids: SCIM is org-scoped by construction.
- Every SCIM change is written to the org event log (admin-visible) with the
  synthetic actor `vaultwarden-scim-...` when `ORG_EVENTS_ENABLED=true`.

## Operational lifecycle

1. Entra assigns user, SCIM creates membership at *Invited*, invite mail sent.
2. User clicks the invite, creates or logs into their account (*Accepted*).
3. An org admin confirms the member in the web vault (*Confirmed*). This is
   the manual step; the admin's client wraps the org key for the member.
4. Entra unassigns or soft deletes, SCIM revokes immediately. Vault access
   stops on the member's next sync.
5. Re-assignment restores the membership exactly as it was, including the
   confirmed state, with no new invite or confirmation needed.
