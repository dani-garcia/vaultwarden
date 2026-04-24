# SSO Cookie Vendor — Native App Support Behind Authenticating Reverse Proxies

## Background

Users of Vaultwarden frequently put it behind an authenticating reverse proxy —
most commonly **Cloudflare Access** or similar Zero Trust gateways — so that
only authenticated users can reach the vault at all. This is a strong defensive
layer: bots can't crawl the endpoint, credential-stuffing never reaches the
login form, and the attack surface drops to "whoever passes my IdP."

The problem is that when the proxy sits in front of the API, the **native
Bitwarden clients (mobile, desktop)** can no longer complete their login flow.
The proxy expects a browser with a cookie jar and OAuth redirect support; the
native apps' HTTP clients have neither. After the browser-assisted IdP step,
the client is stuck — requests to the API come back as HTML login pages from
the proxy instead of JSON from Vaultwarden.

Bitwarden's upstream server solved this in February 2026 with a flow they call
**SSO cookie vending**: the server advertises, via `/api/config`, that it lives
behind an authenticating proxy, and exposes an endpoint (`/api/sso-cookie-vendor`)
that reads the proxy's auth cookie after the user authenticates in a browser
and hands it back to the native app via a `bitwarden://` deep link. The app
then attaches that cookie to every subsequent API request, and the proxy lets
those requests through.

See the upstream PRs: [bitwarden/server#6880][pr-6880],
[bitwarden/server#6892][pr-6892], [bitwarden/server#6903][pr-6903],
[bitwarden/clients#18476][pr-18476], [bitwarden/clients#19392][pr-19392].

Vaultwarden shipped the web-vault connector page (from
`bitwarden/clients#18476`) as part of v2026.2.0, but the server-side pieces
(`/api/sso-cookie-vendor` and the `communication.bootstrap` advertisement in
`/api/config`) were missing. Native apps would detect the web-vault connector,
open a browser, complete the Access auth, and then 404 when they tried to
hand the cookie off. This change adds the two missing server pieces.

## What this change does

Four things:

1. **Adds a new config section** `sso_cookie_vendor` with four fields:
   - `SSO_COOKIE_VENDOR_ENABLED` — master switch (default `false`)
   - `SSO_COOKIE_VENDOR_IDP_LOGIN_URL` — the URL the app should navigate to
     in a browser for IdP authentication (e.g. the Cloudflare Access login
     URL for your Vaultwarden application)
   - `SSO_COOKIE_VENDOR_COOKIE_NAME` — the name of the cookie the proxy sets
     on authenticated requests (e.g. `CF_Authorization` for Cloudflare Access)
   - `SSO_COOKIE_VENDOR_COOKIE_DOMAIN` — the cookie's domain scope
2. **Advertises the configuration** in the `/api/config` response as a
   `communication.bootstrap` object, matching the shape Bitwarden's clients
   already expect from `bitwarden/server#6892`.
3. **Adds the `/api/sso-cookie-vendor` endpoint** that reads the proxy cookie
   from the incoming request and 302-redirects to
   `bitwarden://sso-cookie-vendor?<cookie-name>=<url-encoded-value>&d=1`.
4. **Validates config at startup**: if `SSO_COOKIE_VENDOR_ENABLED=true` but
   any of the three string fields is empty, Vaultwarden refuses to start with
   a clear error message.

The endpoint is only registered when the feature is enabled, so disabled
installs behave exactly as before — no new attack surface.

### Sharded cookie support

Cloudflare Access can split its auth JWT across multiple cookies when the JWT
grows past browser size limits (`CF_Authorization-0`, `CF_Authorization-1`,
…). The endpoint checks for up to 20 shards (`{name}-0` through `{name}-19`)
and forwards all present shards in a single deep link. A non-sharded cookie,
if present, takes precedence (matching upstream Bitwarden's semantics).

### Why this belongs in the server and not in a reverse-proxy shim

The original workaround for Cloudflare Access users was a small Cloudflare
Worker that intercepted `/api/config` and `/api/sso-cookie-vendor` and
injected the same behavior. That works, but:

- Every user behind Cloudflare Access has to deploy and maintain a Worker.
- A Worker only helps Cloudflare Access users — Authentik, Authelia,
  oauth2-proxy, and any other authenticating proxy that drops a cookie can
  use the exact same flow, but each would need its own shim.
- The `communication.bootstrap` block is a first-class feature of Bitwarden's
  `/api/config` contract — it should come from the server, not a proxy layer.

Putting the logic in Vaultwarden makes any authenticating proxy work with
native clients just by flipping four env vars.

## How to enable it

In your `.env` (or `config.json`, or the admin UI):

```bash
SSO_COOKIE_VENDOR_ENABLED=true
SSO_COOKIE_VENDOR_IDP_LOGIN_URL=https://example.cloudflareaccess.com/cdn-cgi/access/login/vault.example.com
SSO_COOKIE_VENDOR_COOKIE_NAME=CF_Authorization
SSO_COOKIE_VENDOR_COOKIE_DOMAIN=vault.example.com
```

### Cloudflare Access specifics

`SSO_COOKIE_VENDOR_IDP_LOGIN_URL` is the "Access Login URL" shown on the
application's details page (format:
`https://<team>.cloudflareaccess.com/cdn-cgi/access/login/<your-domain>`).
`SSO_COOKIE_VENDOR_COOKIE_NAME` is always `CF_Authorization` for Cloudflare
Access. `SSO_COOKIE_VENDOR_COOKIE_DOMAIN` is the domain your Access
application protects.

### Other proxies (Authentik, Authelia, oauth2-proxy, …)

Any reverse proxy that (a) redirects unauthenticated requests to a
browser-based IdP flow, and (b) sets a cookie on the authenticated response,
will work. Set `SSO_COOKIE_VENDOR_IDP_LOGIN_URL` to the proxy's login URL
and `SSO_COOKIE_VENDOR_COOKIE_NAME` / `SSO_COOKIE_VENDOR_COOKIE_DOMAIN` to
the cookie your proxy sets on authenticated sessions.

## End-to-end flow (what the user sees)

1. User opens the Bitwarden app and points it at their Vaultwarden server.
2. App fetches `/api/config`, sees `communication.bootstrap.type == "ssoCookieVendor"`,
   and knows to use the cookie-vending flow.
3. App shows a "sync your browser" prompt and opens the system browser at
   `idpLoginUrl`.
4. Browser is redirected through the IdP (Google, GitHub, Okta, …). User
   authenticates.
5. Proxy sets its auth cookie on the response and redirects the browser to
   `/api/sso-cookie-vendor`.
6. Vaultwarden receives the request, pulls the cookie out of the jar, and
   302-redirects the browser to
   `bitwarden://sso-cookie-vendor?CF_Authorization=<value>&d=1`.
7. The OS hands the deep link back to the Bitwarden app.
8. App stores the cookie value and attaches it to every subsequent API
   request. The proxy sees the cookie, lets the request through, and the app
   continues with the normal Bitwarden master-password unlock.

No app-side modifications are required — this uses the cookie-vending support
Bitwarden's clients already ship.

## Security considerations

- The endpoint is only registered when `SSO_COOKIE_VENDOR_ENABLED=true`.
  Default-off installs are byte-identical to current behavior.
- The endpoint **reads the cookie from an already-authenticated request** —
  the proxy has already validated the IdP session before the request ever
  reaches Vaultwarden. No new authentication boundary is introduced.
- The deep-link response never crosses a trust boundary the browser wasn't
  already on: the browser holds the same cookie, the app holds the same
  cookie, the proxy validates the same cookie.
- Vaultwarden's own authentication (master password) is still required after
  the proxy gate — this feature does not weaken the vault.
- Deep-link length is capped at 8192 bytes to match the upstream Bitwarden
  limit; oversize requests return HTTP 400 with the standard error page.
- Missing/empty cookie returns HTTP 404 with the upstream-compatible error
  page telling the user to return to the app.

## Testing

Unit tests live inline in `src/api/core/sso_cookie_vendor.rs` under the usual
`#[cfg(test)] mod tests` pattern. They cover:

- Single-cookie happy path
- Sharded cookies (ordered 0..19)
- Single cookie takes precedence over shards when both are present
- Missing cookie → 404
- URL-encoding of cookie values with spaces and special characters
- Oversize URI handling
- Error-page HTML matches the upstream Bitwarden format

Run with `cargo test --features sqlite -- sso_cookie_vendor`.

## References

- [bitwarden/server#6880][pr-6880] — Config infrastructure
- [bitwarden/server#6892][pr-6892] — Expose config in `/api/config`
- [bitwarden/server#6903][pr-6903] — Endpoint implementation
- [bitwarden/clients#18476][pr-18476] — Web-vault connector page (already in Vaultwarden v2026.2.0)
- [bitwarden/clients#19392][pr-19392] — Client-side cookie acquisition

[pr-6880]: https://github.com/bitwarden/server/pull/6880
[pr-6892]: https://github.com/bitwarden/server/pull/6892
[pr-6903]: https://github.com/bitwarden/server/pull/6903
[pr-18476]: https://github.com/bitwarden/clients/pull/18476
[pr-19392]: https://github.com/bitwarden/clients/pull/19392
