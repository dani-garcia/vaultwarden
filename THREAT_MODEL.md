# Vaultwarden threat model

To report a security issue, see [SECURITY.md](SECURITY.md).

## Overview

Vaultwarden is an unofficial, self-hosted server for the Bitwarden clients, written in Rust. It stores encrypted vaults, handles login, two-factor authentication, organizations, file and text sharing through Send, and emergency access, and provides an admin panel for the operator. It is not affiliated with Bitwarden. The browser, desktop, mobile and CLI clients come from Bitwarden. Our container images include a web vault built from Bitwarden's web client with our own patches.

## Security expectations

### Deployment

We expect a TLS-terminating reverse proxy in front of the server, `DOMAIN` set to its public URL, and an operator who keeps the host secure. This model covers Vaultwarden itself. Third-party software that consumes its output or sits in front of it, such as log parsers and reverse proxies, is the operator's to configure and secure.

### Encryption

Clients encrypt vault contents end to end. The server stores and serves ciphertext it cannot decrypt, and it never sees the master password. The server enforces access to data and actions itself, without relying on a client to behave. A few settings rely on the client for part of their effect, listed under [Out of scope](#out-of-scope).

A member receives the organization key when they are confirmed. Invited and accepted members do not have it. A revoked member who was once confirmed may still have it. Every confirmed member holds the same key for the whole organization, so only the server separates collections.

The server can read everything that is not end-to-end encrypted, such as user, group, device and organization names, email addresses, who owns what, item types and timestamps, attachment sizes, password hints, the stored master password hash and KDF settings, the TOTP and other 2FA secrets that protect login to the account, API keys, refresh tokens, security stamps, the JWT signing key, and SMTP and push credentials. TOTP secrets that users store in vault items are end-to-end encrypted with the rest of the item.

Someone who controls the server can also serve a modified web vault, so end-to-end encryption does not protect web vault users from them.

### Trust

Registration is open by default (`SIGNUPS_ALLOWED=true`), but many personal and small-team instances turn it off, so holding an account usually implies a minimal level of trust. Account holders are still never trusted with anyone else's data. Members of an organization have some trust in each other.

| Actor | Can reach | Must not reach |
|---|---|---|
| Anonymous internet | Login, prelogin, registration, public Send access, icons, the anonymous notifications hub, static files | Any vault, organization or member data; Sends they have no link to; the admin panel; the internal network through outbound requests |
| Websites and icon sources | The icon fetcher, through any response, redirect or DNS answer; the server, through cross-site requests from a visitor's browser | The internal network through outbound requests; script on the vault origin; acting through a visitor's session |
| Registered user | Their own vault, Sends, devices and settings; organizations they belong to | Another user's data; any other organization; raising their own role or status |
| Invited or accepted member | Accepting the invitation, enrolling in account recovery, and the organization's name, public key and policies | Items, collections, the member list, the organization key, any other privileged action before confirmation |
| Revoked member | Nothing in that organization | Any organization data from the server, even data they could once read |
| Organization User | Items in assigned collections, with `read_only` and `manage` enforced by the server | Other collections, write access to read-only collections, Admin-level metadata |
| Organization Manager (a legacy role, shown as Custom in clients) | The above, plus managing collections where they have `manage`. With "Manage all collections" (`access_all`), every collection and full member and group details | Without `access_all`: managing other collections, full member and group details. Always: changing policies or roles |
| Organization Admin | All data in that organization, members below Owner (some actions on Managers and Admins are limited to Owners), policies, events, account recovery for enrolled members below Owner | Owners, other organizations, the personal vault of a member who is not enrolled in recovery, the organization API key |
| Organization Owner | The whole organization, including account recovery for enrolled members | Other organizations, the personal vault of a member who is not enrolled in recovery |
| Organization API key holder (Owner-issued) | Directory import into its own organization | Other organizations, item content, Owners |
| Send recipient | One Send, within its limits | Other Sends, access beyond the configured limits, the owner's vault |
| Emergency access grantee | After approval or the wait time: the access the grantor configured, which can be full takeover by design | Anything before that, or more than the access the grantor configured |
| Admin panel (`ADMIN_TOKEN`) | All users, organizations and settings | No limit once authenticated |
| Host operator, database and data folder access | Everything | No limit |
| Services the operator configures (SSO provider, SMTP server, push relay, S3 endpoint, Yubico) | What they need for their function | Vault contents |

### Configuration

Optional features that operators turn on, other than experimental and beta ones, carry the same expectations as the defaults, such as SSO, organization events, anything needing SMTP (email 2FA, invitations), push, S3 storage, the admin panel, and the MySQL and PostgreSQL backends.

Some settings remove a protection on purpose, and using them is the operator's choice: `DISABLE_ADMIN_TOKEN`, a plain-text `ADMIN_TOKEN`, `IP_HEADER_TRUSTED_PROXIES=all` on a directly exposed instance, turning off `HTTP_REQUEST_BLOCK_NON_GLOBAL_IPS`, `SSO_DEBUG_TOKENS`, `SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`, `SSO_PKCE=false`, `SHOW_PASSWORD_HINT`, `SMTP_SECURITY=off`, `SMTP_ACCEPT_INVALID_CERTS`, `SMTP_ACCEPT_INVALID_HOSTNAMES`, `SMTP_DEBUG`, `ALLOWED_IFRAME_ANCESTORS`, `ALLOWED_CONNECT_SRC`, and `LOG_LEVEL` set to `debug` or `trace`. Issues that need one of them are out of scope.

### Upstream Bitwarden

Where this document does not cover a behavior, we follow upstream Bitwarden by default.

## Out of scope

These are intended behavior or outside this model. Several match upstream Bitwarden.

- What an admin token holder or the host operator can do, including running code on the server. We expect them to have admin access to the machine.
- Organization Owners and Admins reading all organization data, and account recovery of enrolled members.
- Organization Managers listing basic member details, such as names and emails. Upstream allows this for all members.
- Settings the client applies: `hide_passwords` ("hidden passwords" in the clients), master password reprompt, and organization policies on values the server never sees, such as master password complexity and password generator rules. The client already holds the data.
- Bugs in Bitwarden's client code, including in the web vault we bundle, such as CSV formula injection (exports are built in the browser) or a client failing on a malformed stored value. The advisory and CVE for those belong to Bitwarden. Report them through [Bitwarden's HackerOne program](https://hackerone.com/bitwarden/). When the bundled web vault is affected, we ship a security release that references theirs. Bugs that our own web vault patches add are ours.
- The server not decrypting or authenticating ciphertext. It holds no key.
- `/identity/accounts/prelogin` and `/identity/accounts/prelogin/password` returning KDF settings for any email, with deterministic fake settings for unknown ones.
- Login timing not being equalized.
- Probing whether an icon is already cached. Setting `ICON_SERVICE` to an external service avoids it.
- Download link replay: an attachment token or Send access token being reusable by its holder until it expires (1 and 2 minutes), and object storage presigned URLs that we cannot count or revoke. The holder already has the content.
- Short-lived tokens that stay valid after an authorization change elsewhere until they expire, such as an organization API token (1 hour) after its key is rotated. This includes connections the notifications WebSocket accepted before the change, which stay open and carry change notifications and device login requests, not vault data.
- The access token in the notifications WebSocket's `access_token` query parameter, which reverse proxies may log. Clients send it that way, and our [hardening guide](https://github.com/dani-garcia/vaultwarden/wiki/Hardening-Guide#access-logs-contain-access_token-parameter) covers redacting it.
- A client's tokens staying valid after it logs out. Logging out discards them on that device, as upstream, and deauthorizing sessions or changing the password ends them.
- The personal API key skipping 2FA, and working after a password change until the user rotates it. It is a separate credential.
- A linked SSO identity still logging in after a master password change, and the SSO provider deciding how long a session lasts (`SSO_AUTH_ONLY_NOT_SESSION` turns that off). The provider manages that credential, and it doesn't unlock the vault.
- A revoked or removed member's login session staying valid. It belongs to their own account, and the server checks membership on every request.
- A revoked or removed member keeping what their client already synced, and the organization key not being rotated when a member leaves.
- Unauthenticated requests to `/api/devices/identifier/<id>/clear-token`. The impact is delayed push delivery.
- Limits we leave out or keep simple by design: no cap on the number of items a user stores, no cleanup of attachments reserved but never uploaded, and rate limits kept in memory per process and IP, which reset on restart and are shared by users behind one address.
- Log injection. It only affects software that parses our logs, such as Fail2Ban with our community wiki's filters.
- Attacks that need a missing or misconfigured reverse proxy, such as one not sending `X-Forwarded-Proto` (it decides the admin cookie's `Secure` flag).
- Attacks that need another component to break its own specification, such as a NAT64 translator that forwards the `64:ff9b::/96` prefix to private addresses, against RFC 6052.
- Outbound requests to the SSO provider, Yubico server or S3 endpoint the operator configures, which skip the outbound filter and can be on the internal network.
- File permissions in the data folder. Host security belongs to the operator.
- Attacks that need physical access to a user's device.
- Self-exploitation, where someone can only affect their own account, such as self-XSS or weak KDF settings they choose.
- Text that users choose showing up in emails or pages, such as an organization, user or device name, as long as it can't cause XSS or modify the page.
- Dependency and base image CVEs without a path reachable through Vaultwarden.
- Packages, images and deployment templates that we don't publish. Report those to their maintainers.
- Missing best practices with no demonstrated impact, such as security headers, `style-src 'unsafe-inline'` (the web vault needs it) or version disclosure, and design recommendations without a concrete issue.
- Bugs already reported on our [issue tracker](https://github.com/dani-garcia/vaultwarden/issues).
- Experimental and beta features. They are opt-in and outside this model until they are stable.
- Issues that only affect outdated versions.

## Severity

We rate issues by what the attacker ends up with, such as decrypted data, ciphertext, or the power to change or delete data, and by the access they needed first. An attack that needs no account usually rates higher than one that does. Our ratings can differ from CVSS 3.1, which doesn't translate well to an end-to-end encrypted system. Older advisories may be rated differently.

Denial of service and resource exhaustion only count if they still apply with a reverse proxy in front. Races, denial of service and resource exhaustion are never rated above Medium.

Secrets written to logs at the default log level are rated by what they give someone who can read the logs but not the host.

### Critical

- Reading another account's data decrypted, with or without an account, such as through script on the vault origin or exposed key material.
- Code execution on the server by anyone other than an admin token holder.
- Changing released builds or images, including through our CI workflows or their secrets.
- Anyone other than the named grantee reaching an emergency access outcome.
- With no account: forging login or admin tokens, reading the JWT signing key, reaching the admin panel without the token, or taking over accounts with no action by the victim.

### High

- Decrypted reads within the same organization, such as a member reaching collections they are not assigned to.
- Changing or deleting another user's or organization's existing data.
- Reading another user's server-held secrets, such as their 2FA secrets, API keys, stored master password hash or encrypted user key.
- SSRF that returns the response to the attacker.
- Escalating within an organization.
- Account takeover through SSO.
- The named emergency access grantee reaching the outcome early.
- Script or a cross-site request acting through an admin panel session.
- Script on the vault origin that needs unusual victim interaction.

### Medium

- Ciphertext read by someone with no key.
- Defeating login brute-force protection.
- 2FA bypass that needs the password, such as a remembered device still skipping 2FA after the method is removed.
- A refresh token still working after a password change or "Deauthorize sessions".
- Getting past an organization policy the server enforces.
- Adding data to another user's or organization's space without permission.
- Data loss for another user or organization that the attacker cannot reliably trigger or aim.
- SSRF where the response is filtered or blind.
- Reading a Send that is disabled or expired.
- Denial of service that lasts until someone restarts the server or repairs data, from one request with no account in the default configuration.

### Low

These may be handled as ordinary hardening.

- Behavior that differs from upstream Bitwarden with low impact.
- Bypassing a non-default limit, such as `USER_ATTACHMENT_LIMIT`.
- Metadata across a boundary, such as who is assigned to which collection.
- Exceeding a Send's access limits when the attacker already holds the link.
- A missing rate limit outside login.
- Forging organization audit events.
- Other ways to tell whether an email has an account.
- Denial of service that lasts until someone acts, from one operation that needs an account or a non-default setting.
- Denial of service that lasts only while the attacker keeps going or that recovers by itself, such as a crash the container restarts from.
