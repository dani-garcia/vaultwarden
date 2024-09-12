# SSO using OpenId Connect

To use an external source of authentication your SSO will need to support OpenID Connect :

- An OpenID Connect Discovery endpoint should be available
- Client authentication will be done using Id and Secret.

A master password will still be required and not controlled by the SSO (depending on your point of view this might be a feature ;).
This introduces another way to control who can use the vault without having to use invitation or using an LDAP.

## Configuration

The following configurations are available

 - `SSO_ENABLED` : Activate the SSO
 - `SSO_ONLY` : disable email+Master password authentication
 - `SSO_SIGNUPS_MATCH_EMAIL`: On SSO Signup if a user with a matching email already exists make the association (default `true`)
 - `SSO_AUTHORITY` : the OpenID Connect Discovery endpoint of your SSO
 	- Should not include the `/.well-known/openid-configuration` part and no trailing `/`
 	- $SSO_AUTHORITY/.well-known/openid-configuration should return the a json document: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
 - `SSO_SCOPES` : Optional, allow to override scopes if needed (default `"email profile"`)
 - `SSO_AUTHORIZE_EXTRA_PARAMS` : Optional, allow to add extra parameter to the authorize redirection (default `""`)
 - `SSO_PKCE`: Activate PKCE for the Auth Code flow. Recommended but disabled for now waiting for feedback on support (default `false`).
 - `SSO_AUDIENCE_TRUSTED`: Optional, Regex to trust additional audience for the IdToken (`client_id` is always trusted). Use single quote when writing the regex: `'^$'`.
 - `SSO_CLIENT_ID` : Client Id
 - `SSO_CLIENT_SECRET` : Client Secret
 - `SSO_MASTER_PASSWORD_POLICY`: Optional Master password policy
 - `SSO_AUTH_ONLY_NOT_SESSION`: Enable to use SSO only for authentication not session lifecycle
 - `SSO_CLIENT_CACHE_EXPIRATION`: Cache calls to the discovery endpoint, duration in seconds, `0` to disable (default `0`);
 - `SSO_DEBUG_TOKENS`: Log all tokens (default `false`, `LOG_LEVEL=debug` is required)

The callback url is : `https://your.domain/identity/connect/oidc-signin`

## Account and Email handling

When logging in with SSO an identifier (`{iss}/{sub}` claims from the IdToken) is saved in a separate table (`sso_users`).
This is used to link to the SSO provider identifier without changing the default Vaultwarden user `uuid`. This is needed because:

 - Storing the SSO identifier is important to prevent account takeover due to email change.
 - We can't use the identifier as the User uuid since it's way longer (Max 255 chars for the `sub` part, cf [spec](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken)).
 - We want to be able to associate existing account based on `email` but only when the user logs in for the first time (controlled by `SSO_SIGNUPS_MATCH_EMAIL`).
 - We need to be able to associate with existing stub account, such as the one created when inviting a user to an org (association is possible only if the user does not have a private key).

Additionally:

 - Signup to Vaultwarden will be blocked if the Provider reports the email as `unverified`.
 - Changing the email needs to be done by the user since it requires updating the `key`.
 	 On login if the email returned by the provider is not the one saved in Vaultwarden an email will be sent to the user to ask him to update it.
 - If set `SIGNUPS_DOMAINS_WHITELIST` is applied on SSO signup and when attempting to change the email.

This means that if you ever need to change the provider url or the provider itself; you'll have to first delete the association
then ensure that `SSO_SIGNUPS_MATCH_EMAIL` is activated to allow a new association.

To delete the association (this has no impact on the `Vaultwarden` user):

```sql
TRUNCATE TABLE sso_users;
```

## Client Cache

By default the client cache is disabled since it can cause issues with the signing keys.
\
This means that the discovery endpoint will be called again each time we need to interact with the provider (generating authorize_url, exchange the authorize code, refresh tokens).
This is suboptimal so the `SSO_CLIENT_CACHE_EXPIRATION` allows you to configure an expiration that should work for your provider.

As a protection against a misconfigured expiration if the validation of the `IdToken` fails then the client cache is invalidated (but you'll periodically have an unlucky user ^^).

### Google example (Rolling keys)

If we take Google as an example checking the discovery [endpoint](https://accounts.google.com/.well-known/openid-configuration) response headers we can see that the `max-age` of the cache control is set to `3600` seconds. And the [jwk_uri](https://www.googleapis.com/oauth2/v3/certs) response headers usually contain a `max-age` with an even bigger value.
/
Combined with user [feedback](https://github.com/ramosbugs/openidconnect-rs/issues/152) we can conclude that Google will roll the signing keys each week.

Setting the cache expiration too high has diminishing return but using something like `600` (10 min) should provide plenty benefits.

### Rolling keys manually

If you want to roll the used key, first add a new one but do not immediately start signing with it.
Wait for the delay you configured in `SSO_CLIENT_CACHE_EXPIRATION` then you can start signing with it.

As mentioned in the Google example setting too high of a value has diminishing return even if you do not plan to roll the keys.

## Keycloak

Default access token lifetime might be only `5min`, set a longer value otherwise it will collide with `VaultWarden` front-end expiration detection which is also set at `5min`.
\
At the realm level

- `Realm settings / Tokens / Access Token Lifespan` to at least `10min` (`accessTokenLifespan` setting when using `kcadm.sh`).
- `Realm settings / Sessions / SSO Session Idle/Max` for the Refresh token lifetime

Or for a specific client in `Clients / Client details / Advanced / Advanced settings` you can find `Access Token Lifespan` and `Client Session Idle/Max`.

Server configuration, nothing specific just set:

- `SSO_AUTHORITY=https://${domain}/realms/${realm_name}`
- `SSO_CLIENT_ID`
- `SSO_CLIENT_SECRET`
- `SSO_PKCE=true`

## Auth0

Not working due to the following issue https://github.com/ramosbugs/openidconnect-rs/issues/23 (they appear not to follow the spec).
A feature flag is available to bypass the issue but since it's a compile time feature you will have to patch `Vaultwarden` with something like:

```patch
diff --git a/Cargo.toml b/Cargo.toml
index 0524a7be..9999e852 100644
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -150,7 +150,7 @@ paste = "1.0.15"
 governor = "0.6.3"

 # OIDC for SSO
-openidconnect = "3.5.0"
+openidconnect = { version = "3.5.0", features = ["accept-rfc3339-timestamps"] }
 mini-moka = "0.10.2"
```

There is no plan at the moment to either always activate the feature nor make a specific distribution for Auth0.

## Authelia

To obtain a `refresh_token` to be able to extend session you'll need to add the `offline_access` scope.

Config will look like:

- `SSO_SCOPES="email profile offline_access"`


## Authentik

Default access token lifetime might be only `5min`, set a longer value otherwise it will collide with `VaultWarden` front-end expiration detection which is also set at `5min`.
\
To change the tokens expiration go to `Applications / Providers / Edit / Advanced protocol settings`.

Starting with `2024.2` version you will need to add the `offline_access` scope and ensure it's selected in `Applications / Providers / Edit / Advanced protocol settings / Scopes` ([Doc](https://docs.goauthentik.io/docs/providers/oauth2/#authorization_code)).

Server configuration should look like:

- `SSO_AUTHORITY=https://${domain}/application/o/${application_name}/` : trailing `/` is important
- `SSO_SCOPES="email profile offline_access"`
- `SSO_CLIENT_ID`
- `SSO_CLIENT_SECRET`
- `SSO_PKCE=true`

## Casdoor

Since version [v1.639.0](https://github.com/casdoor/casdoor/releases/tag/v1.639.0) should work (Tested with version [v1.686.0](https://github.com/casdoor/casdoor/releases/tag/v1.686.0)).
When creating the application you will need to select the `Token format -> JWT-Standard`.

Then configure your server with:

- `SSO_AUTHORITY=https://${provider_host}`
- `SSO_CLIENT_ID`
- `SSO_CLIENT_SECRET`
- `SSO_PKCE=true`

## GitLab

Create an application in your Gitlab Settings with

- `redirectURI`: https://your.domain/identity/connect/oidc-signin
- `Confidential`: `true`
- `scopes`: `openid`, `profile`, `email`

Then configure your server with

- `SSO_AUTHORITY=https://gitlab.com`
- `SSO_CLIENT_ID`
- `SSO_CLIENT_SECRET`
- `SSO_PKCE=true`

## Google Auth

Google [Documentation](https://developers.google.com/identity/openid-connect/openid-connect).
\
By default without extra [configuration](https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient) you won´t have a `refresh_token` and session will be limited to 1h.

Configure your server with :

- `SSO_AUTHORITY=https://accounts.google.com`
- `SSO_AUTHORIZE_EXTRA_PARAMS="access_type=offline&prompt=consent"`
- `SSO_PKCE=true`
- `SSO_CLIENT_ID`
- `SSO_CLIENT_SECRET`

## Kanidm

Kanidm recommend always running with PKCE:

Config will look like:

- `SSO_PKCE=true`

Otherwise you can disable the PKCE requirement with: `kanidm system oauth2 warning-insecure-client-disable-pkce CLIENT_NAME --name admin`.

## Microsoft Entra ID

1. Create an "App registration" in [Entra ID](https://entra.microsoft.com/) following [Identity | Applications | App registrations](https://entra.microsoft.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade/quickStartType//sourceType/Microsoft_AAD_IAM).
2. From the "Overview" of your "App registration", you'll need the "Directory (tenant) ID" for the `SSO_AUTHORITY` variable and the "Application (client) ID" as the `SSO_CLIENT_ID` value.
3. In "Certificates & Secrets" create an "App secret" , you'll need the "Secret Value" for the `SSO_CLIENT_SECRET` variable.
4. In "Authentication" add <https://vaultwarden.example.org/identity/connect/oidc-signin> as "Web Redirect URI".
5. In "API Permissions" make sure you have `profile`, `email` and `offline_access` listed under "API / Permission name" (`offline_access` is required, otherwise no refresh_token is returned, see <https://github.com/MicrosoftDocs/azure-docs/issues/17134>).

Only the v2 endpoint is compliant with the OpenID spec, see <https://github.com/MicrosoftDocs/azure-docs/issues/38427> and <https://github.com/ramosbugs/openidconnect-rs/issues/122>.

Your configuration should look like this:

* `SSO_AUTHORITY=https://login.microsoftonline.com/${Directory (tenant) ID}/v2.0`
* `SSO_SCOPES="email profile offline_access"`
* `SSO_CLIENT_ID=${Application (client) ID}`
* `SSO_CLIENT_SECRET=${Secret Value}`

## Zitadel

To obtain a `refresh_token` to be able to extend session you'll need to add the `offline_access` scope.

Additionally Zitadel include the `Project id` and the `Client Id` in the audience of the Id Token.
For the validation to work you will need to add the `Resource Id` as a trusted audience (`Client Id` is trusted by default).
You can control the trusted audience with the config `SSO_AUDIENCE_TRUSTED`

It appears it's not possible to use PKCE with confidential client so it needs to be disabled.

Config will look like:

- `SSO_AUTHORITY=https://${provider_host}`
- `SSO_SCOPES="email profile offline_access"`
- `SSO_CLIENT_ID`
- `SSO_CLIENT_SECRET`
- `SSO_AUDIENCE_TRUSTED='^${Project Id}$'`
- `SSO_PKCE=false`

## Session lifetime

Session lifetime is dependant on refresh token and access token returned after calling your SSO token endpoint (grant type `authorization_code`).
If no refresh token is returned then the session will be limited to the access token lifetime.

Tokens are not persisted in VaultWarden but wrapped in JWT tokens and returned to the application (The `refresh_token` and `access_token` values returned by VW `identity/connect/token` endpoint).
Note that VaultWarden will always return a `refresh_token` for compatibility reasons with the web front and it presence does not indicate that a refresh token was returned by your SSO (But you can decode its value with <https://jwt.io> and then check if the `token` field contain anything).

With a refresh token present, activity in the application will trigger a refresh of the access token when it's close to expiration ([5min](https://github.com/bitwarden/clients/blob/0bcb45ed5caa990abaff735553a5046e85250f24/libs/common/src/auth/services/token.service.ts#L126) in web client).

Additionally for certain action a token check is performed, if we have a refresh token we will perform a refresh otherwise we'll call the user information endpoint to check the access token validity.

### Disabling SSO session handling

If you are unable to obtain a `refresh_token` or for any other reason you can disable SSO session handling and revert to the default handling.
You'll need to enable `SSO_AUTH_ONLY_NOT_SESSION=true` then access token will be valid for 2h and refresh token will allow for an idle time of 7 days (which can be indefinitely extended).

### Debug information

Running with `LOG_LEVEL=debug` you'll be able to see information on token expiration.

## Desktop Client

There is some issue to handle redirection from your browser (used for sso login) to the application.

### Chrome

Probably not much hope, an [issue](https://github.com/bitwarden/clients/issues/2606) is open on the subject and it appears that both Linux and Windows are not working.

## Firefox

On Windows you'll be presented with a prompt the first time you log to confirm which application should be launched (But there is a bug at the moment you might end-up with an empty vault after login atm).


On Linux it's a bit more tricky.
First you'll need to add some config in `about:config` :

```conf
network.protocol-handler.expose.bitwarden=false
network.protocol-handler.external.bitwarden=true
```

If you have any doubt you can check `mailto` to see how it's configured.

The redirection will still not work since it appears that the association to an application can only be done on a link/click. You can trigger it with a dummy page such as:

```html
data:text/html,<a href="bitwarden:///dummy">Click me to register Bitwarden</a>
```

From now on the redirection should now work.
If you need to change the application launched you can now find it in `Settings` by using the search function and entering `application`.
