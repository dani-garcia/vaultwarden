# SSO cookie vendor

Lets the Bitwarden mobile and desktop apps log in when Vaultwarden sits behind a
reverse proxy that authenticates every request, such as Cloudflare Access,
Authentik, Authelia, or oauth2-proxy.

## Background

Putting Vaultwarden behind an authenticating proxy means only users who pass
your identity provider (IdP) reach the vault at all. Bots cannot crawl the
endpoint, credential stuffing never reaches the login form, and the exposed
surface shrinks to the proxy.

The cost is that the Bitwarden mobile and desktop apps can no longer finish
logging in. The proxy expects a browser with a cookie jar and OAuth 2.0 redirect
support, and the apps' HTTP clients have neither. After the browser step, the
apps receive the proxy's HTML login page where they expect JSON from
Vaultwarden, and login stalls.

Bitwarden solved this in their own server in February 2026 with a flow called
SSO cookie vending:

1. The server states in `/api/config` that it sits behind an authenticating
   proxy, and names the IdP login URL and the cookie to look for.
2. The app opens a system browser at that IdP login URL.
3. After the user authenticates, the proxy sets its cookie and the browser
   reaches `/api/sso-cookie-vendor`.
4. The server reads the cookie and redirects the browser to a `bitwarden://`
   deep link carrying it.
5. The app attaches that cookie to every later API request, and the proxy lets
   those requests through.

Vaultwarden 2026.2.0 shipped the web-vault connector page from
[bitwarden/clients#18476][pr-18476], but not the two server-side pieces the flow
needs: the `/api/sso-cookie-vendor` endpoint and the `communication.bootstrap`
block in `/api/config`. Without them the apps detect the connector page, open a
browser, complete the proxy's authentication, and then get a 404 when they try
to collect the cookie. This change adds both pieces.

## What this adds

A configuration section, `sso_cookie_vendor`, holding four settings:

| Setting | Purpose |
|---|---|
| `SSO_COOKIE_VENDOR_ENABLED` | Turns the feature on. Defaults to `false`. |
| `SSO_COOKIE_VENDOR_IDP_LOGIN_URL` | URL the app opens in a browser to authenticate. |
| `SSO_COOKIE_VENDOR_COOKIE_NAME` | Name of the cookie the proxy sets on authenticated requests. |
| `SSO_COOKIE_VENDOR_COOKIE_DOMAIN` | Domain scope of that cookie. |

On top of those settings, this change:

- Publishes the three string settings in `/api/config` as a
  `communication.bootstrap` object, in the shape Bitwarden's clients already
  read from [bitwarden/server#6892][pr-6892].
- Serves `GET /api/sso-cookie-vendor`, which reads the proxy's cookie from the
  request and returns a 302 to
  `bitwarden://sso-cookie-vendor?COOKIE_NAME=COOKIE_VALUE&d=1`. Replace
  `COOKIE_NAME` and `COOKIE_VALUE` with your configured cookie name and its
  percent-encoded value; `d=1` is the sentinel the clients look for.
- Refuses to start when `SSO_COOKIE_VENDOR_ENABLED` is `true` and any of the
  three string settings is empty, and reports which ones to set.

The route is registered only when the feature is on. With
`SSO_COOKIE_VENDOR_ENABLED=false`, Vaultwarden serves exactly the routes it
served before.

### Sharded cookies

Cloudflare Access splits its auth JWT across numbered cookies, such as
`CF_Authorization-0` and `CF_Authorization-1`, when the token outgrows the
per-cookie size limit. The endpoint looks for up to 20 shards, `-0` through
`-19`, and forwards every shard it finds in one deep link, in ascending order,
so the app can reassemble the token. An unsuffixed cookie takes precedence over
any shards, matching the Bitwarden server.

### Why this belongs in the server

The existing workaround for Cloudflare Access users is a Cloudflare Worker that
intercepts `/api/config` and `/api/sso-cookie-vendor` and supplies the same
behavior. That works, with three drawbacks:

- Every user behind Cloudflare Access has to deploy and maintain a Worker.
- A Worker helps only Cloudflare Access users. Authentik, Authelia,
  oauth2-proxy, and any other authenticating proxy that sets a cookie can use
  the same flow, but each one needs its own shim.
- `communication.bootstrap` is part of Bitwarden's `/api/config` contract, so it
  belongs in the server rather than in a proxy layer.

Implementing it in Vaultwarden makes any authenticating proxy work with the
mobile and desktop apps once you set four environment variables.

## Configure the endpoint

Set the four settings in `.env`, in `config.json`, or through the admin panel:

```bash
SSO_COOKIE_VENDOR_ENABLED=true
SSO_COOKIE_VENDOR_IDP_LOGIN_URL=https://example.cloudflareaccess.com/cdn-cgi/access/login/vault.example.com
SSO_COOKIE_VENDOR_COOKIE_NAME=CF_Authorization
SSO_COOKIE_VENDOR_COOKIE_DOMAIN=vault.example.com
```

### Cloudflare Access

- `SSO_COOKIE_VENDOR_IDP_LOGIN_URL` is the Access Login URL on the
  application's details page. It takes the form
  `https://TEAM.cloudflareaccess.com/cdn-cgi/access/login/YOUR_DOMAIN`, where
  `TEAM` is your Cloudflare Zero Trust team name and `YOUR_DOMAIN` is the
  hostname the Access application protects.
- `SSO_COOKIE_VENDOR_COOKIE_NAME` is always `CF_Authorization`.
- `SSO_COOKIE_VENDOR_COOKIE_DOMAIN` is the domain the Access application
  protects.

### Other authenticating proxies

Any proxy works that redirects unauthenticated requests to a browser-based IdP
flow and sets a cookie on the authenticated response. Set
`SSO_COOKIE_VENDOR_IDP_LOGIN_URL` to the proxy's login URL, and set
`SSO_COOKIE_VENDOR_COOKIE_NAME` and `SSO_COOKIE_VENDOR_COOKIE_DOMAIN` to the
cookie the proxy sets on authenticated sessions.

Note: Cloudflare Access is the only proxy this has run against in production.
The others meet the requirements above, but no one has reported a tested
configuration for them yet.

## How the login flow runs

From the user's side, with the feature configured:

1. The user opens the Bitwarden app and points it at their Vaultwarden server.
2. The app reads `/api/config`, finds
   `communication.bootstrap.type` set to `ssoCookieVendor`, and switches to the
   cookie vending flow.
3. The app prompts the user to sign in through their browser and opens the
   system browser at `SSO_COOKIE_VENDOR_IDP_LOGIN_URL`.
4. The browser follows the proxy to the IdP. The user authenticates.
5. The proxy sets its auth cookie and sends the browser to
   `/api/sso-cookie-vendor`.
6. Vaultwarden reads the cookie off the request and redirects the browser to
   `bitwarden://sso-cookie-vendor?CF_Authorization=COOKIE_VALUE&d=1`.
7. The operating system hands the deep link to the Bitwarden app.
8. The app stores the cookie and sends it with every later API request. The
   proxy recognizes the cookie, lets the request through, and the app continues
   to the usual master password unlock.

The apps need no changes. This uses the cookie vending support Bitwarden's
clients already ship.

## Security notes

- The endpoint exists only when `SSO_COOKIE_VENDOR_ENABLED` is `true`. An
  install that leaves the feature off serves the same routes it served before.
- The endpoint reads a cookie from a request the proxy has already
  authenticated. The proxy validates the IdP session before the request reaches
  Vaultwarden, so this adds no authentication boundary of its own.
- The redirect moves the cookie between two parties that both already hold it:
  the browser that received it and the app on the same device. The proxy
  validates the same cookie in either case.
- Vaultwarden's own authentication still applies. The user unlocks the vault
  with their master password after the proxy gate, so this does not weaken the
  vault.
- The deep link is capped at 8192 bytes, matching the Bitwarden server. A
  request that would exceed the cap gets a 400 and an HTML error page.
- A request carrying neither the cookie nor any shard gets a 404 and the same
  error page, which tells the user to return to the app.

## Test the change

Unit tests live in `src/api/core/sso_cookie_vendor.rs` under `#[cfg(test)] mod
tests`. Run them with:

```bash
cargo test --features sqlite -- sso_cookie_vendor
```

They cover:

- A single cookie, the common case.
- Sharded cookies, forwarded in suffix order regardless of map iteration order.
- An unsuffixed cookie taking precedence when shards are also present.
- A missing cookie producing a 404.
- Percent-encoding of values holding spaces and reserved characters.
- An oversize cookie producing a link past the 8192-byte cap.
- The error page matching the Bitwarden server's HTML.

## References

- [bitwarden/server#6880][pr-6880]: configuration infrastructure.
- [bitwarden/server#6892][pr-6892]: exposing the configuration in `/api/config`.
- [bitwarden/server#6903][pr-6903]: the endpoint implementation.
- [bitwarden/clients#18476][pr-18476]: the web-vault connector page, shipped in
  Vaultwarden 2026.2.0.
- [bitwarden/clients#19392][pr-19392]: client-side cookie acquisition.

[pr-6880]: https://github.com/bitwarden/server/pull/6880
[pr-6892]: https://github.com/bitwarden/server/pull/6892
[pr-6903]: https://github.com/bitwarden/server/pull/6903
[pr-18476]: https://github.com/bitwarden/clients/pull/18476
[pr-19392]: https://github.com/bitwarden/clients/pull/19392
