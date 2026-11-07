# Skipping Vaultwarden 2FA for SSO

Vaultwarden can skip its own 2FA only when the trusted OpenID Connect provider reports that MFA was completed. Social login alone does not prove MFA: an account may have MFA disabled, or the broker may reuse an existing session without performing another factor.

Configure claims for your provider and verify its signed ID token before enabling automatic skipping:

```ini
SSO_2FA_SKIP=auto
SSO_2FA_AMR=mfa,otp,fido2,webauthn,hwk
# Optional exact, issuer-specific ACR value; Vaultwarden requests and matches it.
SSO_2FA_ACR=
```

`auto` matches `acr` exactly against `SSO_2FA_ACR` or configured `amr` entries exactly. Values are case-sensitive. An ACR request is a request, not proof the provider fulfilled the requested assurance.

The default AMR list includes the explicit `mfa` signal, OTP paired with `pwd`, and `fido2`, `webauthn`, or `hwk` for passwordless/security-key sign-ins. OTP is a common second factor when combined with a password; Vaultwarden therefore accepts `otp` only when `pwd` is also present in the ID token. A passkey/security-key method may be strong passwordless authentication, but these generic AMR names alone do not guarantee user verification, phishing resistance, or a particular provider policy. Use them only when your trusted IdP emits them exclusively for the strong authentication you intend to accept. Set `SSO_2FA_AMR` to a stricter list or blank to disable AMR matching. `SSO_2FA_SKIP=false` always requires Vaultwarden 2FA; `SSO_2FA_SKIP=true` bypasses it for every SSO login and should be used only as a deliberate trust decision.

## Provider setup

### Authentik

Authentik can broker social sources ([setup](https://docs.goauthentik.io/users-sources/sources/social-logins/)). Require an Authentik MFA stage after the social login in the authentication flow used by the Vaultwarden application. Authentik's ID-token implementation includes `mfa` in `amr` when the authentication event records MFA devices ([implementation](https://github.com/goauthentik/authentik/blob/95764ad89663f8343c82b13de4fa97c49e8a6b23/authentik/providers/oauth2/id_token.py#L109-L123)). Confirm that the actual ID token for both local and social sign-ins contains `mfa` only after the enforced MFA stage. Do not assume upstream Google, Microsoft, or other social MFA is propagated.

### Keycloak

Keycloak can broker social and other identity providers. Require MFA in the browser authentication flow for the Vaultwarden client, including brokered logins. Configure the AMR protocol mapper so the `mfa` reference is emitted only by a successful execution that enforces MFA ([authentication flow AMR mapping](https://github.com/keycloak/keycloak/blob/d4d55541da034a55a785c09922fcd62e51cd5bde/docs/documentation/server_admin/topics/authentication/flows.adoc#L109-L115)). Confirm the resulting ID token.

Keycloak's broker `identity_provider` session note can be mapped to a separate custom claim to identify the upstream provider ([broker session data](https://github.com/keycloak/keycloak/blob/d4d55541da034a55a785c09922fcd62e51cd5bde/docs/documentation/server_admin/topics/identity-broker/session-data.adoc#L2-L12)). Use that claim for provenance only; it must not satisfy Vaultwarden's MFA check.

### Authelia

Authelia can act as an OIDC provider and apply a client's `two_factor` authorization policy ([client configuration](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/)):

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: vaultwarden
        # Other required client settings...
        authorization_policy: 'two_factor'
```

Authelia includes `mfa` in `amr` when its factor calculation confirms multiple factors; its OIDC integration test expects this value after two-factor authentication ([AMR implementation](https://github.com/authelia/authelia/blob/41f3b1ab5e97f2fabeacd75a65daf83b1f89d6eb/internal/authorization/amr.go#L74-L87), [OIDC test](https://github.com/authelia/authelia/blob/41f3b1ab5e97f2fabeacd75a65daf83b1f89d6eb/internal/suites/scenario_oidc_test.go#L95-L128)). Require `two_factor`, then confirm the deployed version's ID token before setting `SSO_2FA_AMR=mfa`. Do not use ACR for this: the reviewed integration test returns an empty `acr`. Authelia's OIDC provider is currently beta and does not support the Relying Party role, so it cannot broker upstream social logins.

## Social providers and verification

Direct social providers such as Google or Microsoft may not expose a stable MFA claim to Vaultwarden. When using a broker, do not infer MFA from the social source, a persistent user attribute, or an unverified upstream claim. Require MFA at the broker for the current authentication, or keep Vaultwarden 2FA enabled.

Inspect the **ID token** produced by the exact login flow and verify:

- The signed token is issued by the configured, trusted issuer and is intended for the Vaultwarden client.
- `amr` contains `mfa`, or `acr` has the exact configured value, only after the enforced MFA policy succeeds.
- Social/provider provenance, if emitted, is separate from the MFA claim and does not by itself suppress local 2FA.

Avoid sharing ID tokens or enabling token-debug logging in production; tokens contain sensitive authentication data. For OIDC claim semantics, see [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176.html#section-2).
