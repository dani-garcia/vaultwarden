# Vaultwarden threat model

To report a security issue, see [SECURITY.md](SECURITY.md).

## Overview

Vaultwarden is an unofficial, self-hosted server for the Bitwarden clients, written in Rust. It stores encrypted vaults and handles login, two-factor authentication, organizations, file and text sharing through Send, emergency access, and an admin panel for the operator. It is not affiliated with Bitwarden. The browser, desktop, mobile and CLI clients come from Bitwarden. Our container images include a web vault built from Bitwarden's web client with our own patches.

## Security expectations

### Deployment

We expect a TLS-terminating reverse proxy in front of the server, `DOMAIN` set to its public origin, and an operator who keeps the host secure. This model covers Vaultwarden itself. Third-party software that consumes its output or sits in front of it, such as log parsers and reverse proxies, is the operator's to configure and secure.

### Encryption

Clients encrypt vault contents end to end. The server stores and serves ciphertext it cannot decrypt, and it never sees the master password. The server enforces access to data and actions itself, without relying on a client to behave. A few settings rely on the client for part of their effect, such as `hide_passwords`, where the client still receives the password, and some organization policies.

A member receives the organization key when they are confirmed. Invited and accepted members do not have it. A revoked member who was once confirmed may still have it. Every confirmed member holds the same key for the whole organization, so only the server separates collections.

The server can read everything that is not end-to-end encrypted, such as email addresses, names, organization names, who owns what, item types and timestamps, attachment sizes, password hints, the stored master password hash and KDF settings, the TOTP and other 2FA secrets that protect login to the account, API keys, refresh tokens, security stamps, the JWT signing key, and SMTP and push credentials. TOTP secrets that users store in vault items are end-to-end encrypted with the rest of the item.

### Trust

Registration is open by default (`SIGNUPS_ALLOWED=true`), but many personal and small-team instances turn it off, so holding an account usually implies a minimal level of trust. Account holders are still never trusted with anyone else's data. Members of an organization have some trust in each other.

| Actor | Can reach | Must not reach |
|---|---|---|
| Anonymous internet | Login, prelogin, registration, public Send access, icons, the anonymous notifications hub, static files | Any vault, Send, organization or member data; the admin panel; the internal network through outbound requests |
| Registered user | Their own vault, Sends, devices and settings; organizations they belong to | Another user's data; any other organization; raising their own role or status |
| Invited or accepted member | Accepting the invitation, enrolling in account recovery, and the organization's name, public key and policies | Items, collections, the member list, the organization key, any other privileged action before confirmation |
| Revoked member | Nothing in that organization | Any organization data from the server, even data they could once read |
| Organization User | Items in assigned collections, with `read_only` and `manage` enforced by the server | Other collections, write access to read-only collections, Admin-level metadata |
| Organization Manager (shown as Custom in clients) | The above, plus managing collections where they have `manage`. With "manage all collections" (`access_all`), every collection and full member and group details | Without `access_all`: managing other collections, full member and group details. Always: changing policies, role changes |
| Organization Admin | All data in that organization, members below Owner (some actions on Managers and Admins are limited to Owners), policies, events, account recovery for enrolled members below Owner | Owners, other organizations, the personal vault of a member who is not enrolled in recovery, the organization API key |
| Organization Owner | The whole organization, including account recovery for enrolled members | Other organizations; the personal vault of a member who is not enrolled in recovery |
| Organization API key holder (Owner-issued) | Directory import into its own organization | Other organizations, item content, Owners |
| Send recipient | One Send, within its limits | Other Sends, access beyond the configured limits, the owner's vault |
| Emergency access grantee | After approval or the wait time: the access the grantor configured, which can be full takeover by design | Anything before that |
| Admin panel (`ADMIN_TOKEN`) | All users, organizations and settings. We expect the holder to also have admin access to the machine | No limit once authenticated |
| Host operator, database and data folder access | Everything | No limit |
| Configured SSO provider, SMTP server, push relay | What they need for their function | Vault contents |

### Configuration

Optional features that operators turn on carry the same expectations as the defaults: SSO, groups, organization events, anything needing SMTP (email 2FA, invitations), push, S3 storage, the admin panel, and the MySQL and PostgreSQL backends.

Some settings remove a protection on purpose, and using them is the operator's choice: `DISABLE_ADMIN_TOKEN`, `IP_HEADER_TRUSTED_PROXIES=all` on a directly exposed instance, turning off `HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS`, and `SSO_DEBUG_TOKENS`.

### Upstream Bitwarden

Where this document does not cover a behaviour, we follow upstream Bitwarden by default.

## Security issues

A security issue is a bug in Vaultwarden that breaks these expectations. Examples:

- someone reading, adding, changing or deleting data that the table above says they must not reach;
- an organization member reaching collections they are not assigned to, or a revoked or unconfirmed member reaching organization items or collections;
- someone gaining a role or permission they should not have;
- getting past an organization policy the server enforces;
- a login session or refresh token surviving a password change or security stamp rotation, or a remembered device still skipping 2FA after a 2FA method is removed;
- getting past authentication, 2FA or login brute-force protection;
- logging in as someone else through SSO;
- reading a Send that is disabled or expired, or exceeding its limits;
- reaching an emergency access outcome early or out of order;
- reaching the admin panel without the token, or acting through an admin's session with script or a cross-site request;
- outbound requests reaching the internal network;
- attacker-controlled script or HTML served from the vault origin, where the web vault runs and holds decrypted keys;
- code execution on the server, or exposure of keys or other server-held secrets, including in logs;
- denial of service or resource exhaustion that still applies with a reverse proxy in front.

## Not security issues

These are intended behaviour or outside this model. Several match upstream Bitwarden.

- What the admin panel or host operator can do once authenticated, including an admin token holder running code on the server. We expect them to have admin access to the machine.
- Organization Owners and Admins reading all organization data, and account recovery of enrolled members. Both are by design.
- Organization Managers listing basic member details, such as names and emails. Upstream allows this for all members.
- `hide_passwords` ("except passwords"). It helps avoid accidental leaks and copy-pastes, but the client still holds the password.
- Bugs in Bitwarden's client code, including that code in the web vault we bundle, such as CSV formula injection (exports are built in the browser) or a client failing on a malformed stored value. The advisory and CVE for those belong to Bitwarden. When the bundled web vault is affected, we ship a security release that references theirs. Bugs that our own web vault patches add are ours.
- The server not decrypting or authenticating ciphertext. It holds no key.
- `/identity/accounts/prelogin` returning KDF settings for any email, with deterministic fake settings for unknown ones.
- Login timing not being equalized.
- Download link replay: an attachment token or Send access token being reusable by its holder until it expires (1 and 2 minutes), and object storage presigned URLs that we cannot count or revoke. The holder already has the content.
- Organization API tokens staying valid until they expire (1 hour) after the key is rotated.
- The personal API key working after a password change until the user rotates it. It is a separate credential.
- A revoked or removed member's login session staying valid. It belongs to their own account, and the server checks membership on every request.
- A revoked or removed member keeping what their client already synced, and the organization key not being rotated when a member leaves.
- The notifications WebSocket accepting a login token until it expires, and keeping open connections, after a password change. It carries change notifications and login requests, not vault data.
- Anonymous `clear-token` on `/devices/identifier/<id>/clear-token`. The impact is delayed push delivery.
- No server-side cleanup of attachments that were reserved but never uploaded.
- The number of items a user can store. There is no limit, by design.
- Log injection. Changing log lines has no effect on Vaultwarden and only matters to third-party software parsing them, such as Fail2Ban, including filters from our community wiki.
- Reverse proxy misconfiguration, such as a proxy not sending `X-Forwarded-Proto`, which decides the admin cookie's `Secure` flag.
- Attacks that need another component to break its own specification.
- Outbound requests to the SSO provider, Yubico server or S3 endpoint the operator configures, which skip the outbound filter and can be on the internal network.
- Weak KDF settings a user chooses for their own account.
- File permissions in the data folder. Host security belongs to the operator.
- The WebSocket `access_token` query parameter. Clients send it that way, and our hardening guide covers log redaction.
- Dependency and base image CVEs without a path reachable through Vaultwarden.
- Missing best practices with no demonstrated impact, such as headers, `style-src 'unsafe-inline'` (the web vault needs it) and version disclosure.
- Outdated versions.

## Severity

We rate issues by what the attacker holds at the end (plaintext, ciphertext they have the key for, ciphertext they have no key for, or the power to write or delete, which needs no key) and by the access they needed first. An attack that needs no account usually rates higher than one that does. This applies to new issues. Older advisories may be rated differently.

Denial of service and resource exhaustion only count if they still apply with a reverse proxy in front. We do not consider them a serious problem in practice, so they are never High and Medium should be rare.

Secrets written to logs are rated by what the secret gives someone who reads the logs and how long it stays valid. Reading logs does not assume host access.

### Critical

Anything that lets someone read another account's data decrypted is Critical by default, whether or not they have an account of their own. That covers:

- attacker-controlled script running on the vault origin for other users during normal use, caused by how Vaultwarden stores or serves content;
- code execution on the server by anyone other than an admin token holder, because it can change the web vault the server serves;
- exposing key material that lets someone else decrypt an account's data;
- anyone other than the named grantee reaching an emergency access outcome.

Forging login or admin tokens, reading the JWT signing key, reaching the admin panel without the token, and taking over arbitrary accounts with no action by the victim are also Critical when no account is needed.

### High

- Decrypted reads within the same organization, including a member reaching collections they are not assigned to, or a revoked member who kept the key. Members share one key and have some trust in each other, and the scope is limited to that organization.
- Changing or deleting another user's or organization's existing data.
- Reading another user's server-held secrets, such as their account's 2FA secrets or API keys.
- Reading another user's stored master password hash or encrypted user key, which allow offline guessing of the master password.
- SSRF that returns the response to the attacker.
- Escalating within an organization with real effect on data or members.
- Account takeover through SSO, unless it meets the Critical conditions above.
- The named emergency access grantee reaching the outcome early. The grantor chose them and the scope is one account.
- Script or a cross-site request acting through an admin's session without them noticing. This includes script that only runs in the admin panel. It is Critical if it reaches code execution or the files the server serves.
- Attacker-controlled script on the vault origin that needs unusual victim interaction.

### Medium

- Ciphertext read by someone with no key.
- Defeating login brute-force protection. The attacker still has to guess the password, and get past 2FA if the victim has it.
- 2FA bypass that needs the password, and a login session or refresh token surviving a password change or security stamp rotation.
- Getting past an organization policy the server enforces, such as required 2FA or single organization.
- Adding data to another user's or organization's space without permission, such as a read-only member adding items.
- Data loss for another user that the attacker cannot reliably trigger or aim.
- SSRF where the response is filtered or blind.
- Reading a Send that is disabled or expired.
- Denial of service or resource exhaustion from one request with no account needed, in the default configuration, where the denial stays after the attacker stops until someone has to act, such as by restarting the server or repairing data.

### Low

These may be handled as ordinary hardening in some cases.

- Behaviour that differs from upstream Bitwarden with low impact.
- Bypassing a non-default limit (`USER_ATTACHMENT_LIMIT`, `ORG_ATTACHMENT_LIMIT`, `USER_SEND_LIMIT`).
- Vaultwarden mishandling the headers of a correctly configured proxy (`IP_HEADER`, `IP_HEADER_TRUSTED_PROXIES`), even if that weakens rate limits.
- Metadata across a boundary, such as who is assigned to which collection.
- Exceeding a Send's access limits when the attacker already holds the link.
- A missing rate limit outside login, with no other effect.
- Forging organization audit events, as long as existing events cannot be modified.
- Other ways to tell whether an email has an account, apart from the prelogin and login timing cases under "Not security issues".
- Denial of service or resource exhaustion from one operation that needs an account or a non-default setting, where the denial stays after the attacker stops until someone has to act.
- Denial of service or resource exhaustion that lasts only while the attacker keeps going, or that recovers by itself, such as a crash the container restarts from or a panic that yields a 500 with no lasting effect. We handle these as hardening.

### CVSS

Our ratings can differ from CVSS 3.1, because its scoring parameters don't translate well to an end-to-end encrypted system.
