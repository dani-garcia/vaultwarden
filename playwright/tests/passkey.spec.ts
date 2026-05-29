import { test, expect, type TestInfo } from '@playwright/test';

import * as utils from '../global-utils';
import { createAccount } from './setups/user';
import {
    addVirtualAuthenticator,
    clickLoginWithPasskey,
    enrollLoginPasskey,
    expectLockScreenButtons,
    lockVault,
    removeLoginPasskey,
    removeVirtualAuthenticator,
    resetVirtualAuthenticators,
    unlockWithPasskey,
} from './setups/account_lifecycle_helpers';

let users = utils.loadEnv();
const ADMIN_TOKEN = process.env.ADMIN_TOKEN!;

const useExternalVault = process.env.PW_USE_EXTERNAL_VAULT === '1';

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    if (useExternalVault) return;
    await utils.startVault(browser, testInfo, {});
});

test.afterAll('Teardown', async () => {
    if (useExternalVault) return;
    utils.stopVault();
});

// CDP sessions are bound to a specific Page; Playwright recycles the page
// between tests, so drop the cached session/authenticator IDs each time
// (no-op for the request-only suites below; only the UI flows touch CDP).
test.beforeEach(() => resetVirtualAuthenticators());

// ---------------------------------------------------------------------------
// Unauthenticated API surface — `GET /identity/accounts/webauthn/assertion-options`
// is the only public passkey-login entry point.
// ---------------------------------------------------------------------------

test.describe('Passkey login challenge endpoint', () => {
    test('GET assertion-options returns the documented shape', async ({ request }) => {
        const res = await request.get('/identity/accounts/webauthn/assertion-options');
        expect(res.status()).toBe(200);
        expect(res.headers()['content-type']).toMatch(/application\/json/i);
        const body = await res.json();

        expect(body).toHaveProperty('options');
        expect(body).toHaveProperty('token');
        // `webAuthnLoginAssertionOptions` is also the upstream Bitwarden
        // `WebAuthnLoginAssertionOptionsResponseModel.ResponseObj` constant.
        expect(body).toHaveProperty('object', 'webAuthnLoginAssertionOptions');

        // WEBAUTHN_LOGIN_CHALLENGE_TTL_SECONDS is server-side; the public
        // contract is just that the options carry a challenge and a UV policy.
        expect(body.options).toHaveProperty('challenge');
        expect(body.options).toHaveProperty('userVerification');

        // Don't pin the token format: Vaultwarden mints a UUID, upstream
        // Bitwarden mints a `DataProtectorTokenable` (signed string).
        // Both are non-empty opaque strings as far as the client cares.
        expect(typeof body.token).toBe('string');
        expect(body.token.length).toBeGreaterThan(0);
    });

    test('assertion-options returns a fresh token and challenge on every call', async ({ request }) => {
        // Each call inserts a row in `web_authn_login_challenges`. Token AND
        // challenge bytes must both be unique across calls; if a future
        // refactor accidentally re-used either, an attacker could replay.
        const tokens = new Set<string>();
        const challenges = new Set<string>();
        for (let i = 0; i < 5; i++) {
            const body = await (await request.get('/identity/accounts/webauthn/assertion-options')).json();
            tokens.add(body.token);
            challenges.add(body.options.challenge);
        }
        expect(tokens.size).toBe(5);
        expect(challenges.size).toBe(5);
    });
});

// ---------------------------------------------------------------------------
// `POST /identity/connect/token grant=webauthn` is the unauthenticated login
// path. Every failure must surface the same generic message so an attacker
// cannot probe account state (the "oracle" defense). We cannot fully exercise
// the happy path without a virtual authenticator, but every documented
// failure branch is reachable with bad input.
// ---------------------------------------------------------------------------

function webauthnLoginForm(overrides: Record<string, string> = {}) {
    return {
        grant_type: 'webauthn',
        client_id: 'web',
        scope: 'api offline_access',
        device_identifier: '00000000-0000-0000-0000-000000000000',
        device_name: 'pw-test-device',
        device_type: '9',
        deviceresponse: '{}',
        token: '00000000-0000-0000-0000-000000000000',
        ...overrides,
    };
}

async function failureMessage(res: any): Promise<string> {
    // Vaultwarden's `ApiErrorResponse` serializer puts the user-visible
    // string in top-level `message` and again under `errorModel.message`.
    // The OAuth2-style `error` / `error_description` fields are present
    // but hardcoded to empty string, so we ignore them.
    let body: any;
    let raw: string | undefined;
    try {
        raw = await res.text();
        body = JSON.parse(raw);
    } catch {
        // Not JSON — return the raw text so the test failure is diagnosable.
        return `[non-JSON ${res.status()}] ${raw ?? ''}`;
    }
    const msg = body?.message || body?.errorModel?.message;
    if (!msg) {
        // Attach the unexpected body to the test report (not stdout) so a
        // future serializer-shape change is visible even when the assertion
        // still passes against the raw body.
        test.info().annotations.push({
            type: 'unexpected-error-shape',
            description: `status=${res.status()} body=${raw}`,
        });
    }
    return msg || raw || `[empty body, status ${res.status()}]`;
}

// Vaultwarden's `AUTH_FAILED` constant is "Passkey authentication failed."
// Upstream Bitwarden uses "Invalid credential." — same security contract
// (generic rejection that doesn't reveal which branch failed), different
// surface text. Accept either so this spec runs against either server.
const GENERIC_AUTH_FAILED = /(Passkey authentication failed|Invalid credential)/i;

test.describe('Passkey grant rejects all bad input with the same message', () => {
    test('returns a generic auth-failed message for an unknown token', async ({ request }) => {
        const res = await request.post('/identity/connect/token', {
            form: webauthnLoginForm(),
        });
        expect(res.status()).toBeGreaterThanOrEqual(400);
        expect(await failureMessage(res)).toMatch(GENERIC_AUTH_FAILED);
    });

    test('returns a generic auth-failed message for a malformed deviceresponse', async ({ request }) => {
        // Fresh, valid token; garbage body. Server must still respond with
        // the generic message — not a serde error or a different shape.
        const { token } = await (await request.get('/identity/accounts/webauthn/assertion-options')).json();
        const res = await request.post('/identity/connect/token', {
            form: webauthnLoginForm({ token, deviceresponse: 'not-json' }),
        });
        expect(res.status()).toBeGreaterThanOrEqual(400);
        expect(await failureMessage(res)).toMatch(GENERIC_AUTH_FAILED);
    });

    test('returns a generic auth-failed message for a structurally-valid but unsignable assertion', async ({ request }) => {
        const { token } = await (await request.get('/identity/accounts/webauthn/assertion-options')).json();
        // A shape that parses as PublicKeyCredentialCopy but cannot identify
        // any registered discoverable credential — same end state as garbage,
        // but reaches a deeper branch in `webauthn_login`.
        const fakeAssertion = JSON.stringify({
            id: 'AAAA',
            rawId: 'AAAA',
            type: 'public-key',
            response: {
                authenticatorData: 'AAAA',
                clientDataJson: 'AAAA',
                signature: 'AAAA',
                userHandle: 'AAAA',
            },
        });
        const res = await request.post('/identity/connect/token', {
            form: webauthnLoginForm({ token, deviceresponse: fakeAssertion }),
        });
        expect(res.status()).toBeGreaterThanOrEqual(400);
        expect(await failureMessage(res)).toMatch(GENERIC_AUTH_FAILED);
    });

    test('the unknown-token branch and the malformed-body branch return identical messages', async ({ request }) => {
        // The whole point of the generic auth-failed constant: a client
        // must not be able to tell *why* the login failed. If these two
        // messages ever diverge, that's an oracle — regardless of which
        // string each server uses.
        const unknown = await request.post('/identity/connect/token', {
            form: webauthnLoginForm(),
        });
        const { token } = await (await request.get('/identity/accounts/webauthn/assertion-options')).json();
        const malformed = await request.post('/identity/connect/token', {
            form: webauthnLoginForm({ token, deviceresponse: 'not-json' }),
        });

        const unknownMessage = await failureMessage(unknown);
        const malformedMessage = await failureMessage(malformed);

        // Assert both are the generic message before comparing them, so the
        // test can't pass vacuously: two identical empty/degenerate bodies
        // would satisfy a bare equality check while breaking the oracle
        // contract this test exists to defend.
        expect(unknownMessage).toMatch(GENERIC_AUTH_FAILED);
        expect(malformedMessage).toMatch(GENERIC_AUTH_FAILED);
        expect(unknownMessage).toBe(malformedMessage);
    });
});

// ---------------------------------------------------------------------------
// Authenticated webauthn-management endpoints must reject anonymous callers.
// Rocket's `Headers` guard short-circuits the handler body, so the asserted
// 401 is a property of the route attribute, not the handler logic. Worth
// pinning anyway: a refactor that swaps `Headers` for a non-required guard
// would silently widen the attack surface.
// ---------------------------------------------------------------------------

test.describe('Passkey management endpoints require authentication', () => {
    const cases = [
        { method: 'GET' as const, path: '/api/webauthn' },
        { method: 'POST' as const, path: '/api/webauthn/attestation-options', data: {} },
        { method: 'POST' as const, path: '/api/webauthn/assertion-options', data: {} },
        { method: 'POST' as const, path: '/api/webauthn', data: {} },
        { method: 'PUT' as const, path: '/api/webauthn', data: {} },
        {
            method: 'POST' as const,
            path: '/api/webauthn/00000000-0000-0000-0000-000000000000/delete',
            data: {},
        },
    ];
    for (const c of cases) {
        test(`${c.method} ${c.path} → 401 without bearer token`, async ({ request }) => {
            const res = await request.fetch(c.path, {
                method: c.method,
                ...(c.data === undefined ? {} : { data: c.data }),
            });
            expect(res.status()).toBe(401);
        });

        test(`${c.method} ${c.path} → 401 with a garbage bearer`, async ({ request }) => {
            // A non-empty but unparseable Bearer must still be rejected by
            // the JWT validator before the handler body runs. Upstream
            // Bitwarden's `[Authorize]` and Vaultwarden's `Headers` guard
            // both fail closed on bad tokens.
            const headers = { Authorization: 'Bearer not-a-real-jwt' };
            const res = await request.fetch(c.path, {
                method: c.method,
                headers,
                ...(c.data === undefined ? {} : { data: c.data }),
            });
            expect(res.status()).toBe(401);
        });
    }
});

// ---------------------------------------------------------------------------
// `/identity/connect/token grant=webauthn` rejects requests that are missing
// any of the required form fields before the webauthn handler body runs.
// Both Vaultwarden (`check_is_some(...)`) and upstream Bitwarden
// (`WebAuthnGrantValidator` early null checks) gate on these — the exact
// rejection text differs between projects, so we only assert that the
// response is an error and not the contentful happy path.
// ---------------------------------------------------------------------------

test.describe('Passkey grant rejects requests with missing required form fields', () => {
    for (const field of ['token', 'deviceresponse', 'client_id', 'scope']) {
        test(`missing ${field} is rejected`, async ({ request }) => {
            const form = webauthnLoginForm();
            delete (form as Record<string, string>)[field];
            const res = await request.post('/identity/connect/token', {
                form: form as Record<string, string>,
            });
            expect(res.status()).toBeGreaterThanOrEqual(400);
            // Don't check the specific message: Vaultwarden says
            // "<field> cannot be blank", Bitwarden returns
            // `TokenRequestErrors.InvalidGrant`. The contract being tested
            // is that the missing-field input doesn't sneak through.
        });
    }
});

// ---------------------------------------------------------------------------
// UI smoke — the web vault must surface the new login entry point.
// ---------------------------------------------------------------------------

test.describe('Passkey UI surface', () => {
    test('Login page exposes the "Log in with passkey" entry point', async ({ page }) => {
        await utils.cleanLanding(page);
        // The web vault renders the button conditionally; the
        // `passkey_login` capability comes from the server's /api/config
        // response, which is always-on for any non-SSO_ONLY deployment.
        await expect(page.getByRole('button', { name: /Log in with passkey/i })).toBeVisible();
    });
});

// ---------------------------------------------------------------------------
// Pre-verification user-handle handling inside `webauthn_login`. A forged
// assertion can name an existing user in `userHandle`, but until WebAuthn
// verification succeeds it must not produce a distinguishable response or be
// treated as a proven login attempt for that user.
// ---------------------------------------------------------------------------

function base64url(s: string): string {
    return Buffer.from(s, 'utf8').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function webauthnGrantTargetingUser(token: string, userUuid: string): Record<string, string> {
    return {
        grant_type: 'webauthn',
        client_id: 'web',
        scope: 'api offline_access',
        device_identifier: '00000000-0000-0000-0000-000000000000',
        device_name: 'pw-test-device',
        device_type: '9',
        deviceresponse: JSON.stringify({
            id: 'AAAA',
            rawId: 'AAAA',
            type: 'public-key',
            response: {
                authenticatorData: 'AAAA',
                clientDataJson: 'AAAA',
                signature: 'AAAA',
                userHandle: base64url(userUuid),
            },
        }),
        token,
    };
}

async function adminLogin(request: any) {
    const res = await request.post('/admin', {
        form: { token: ADMIN_TOKEN },
        maxRedirects: 0,
        failOnStatusCode: false,
    });
    expect([200, 302, 303]).toContain(res.status());
}

async function adminGetUserByEmail(request: any, email: string): Promise<{ id: string }> {
    const res = await request.get(`/admin/users/by-mail/${encodeURIComponent(email)}`);
    expect(res.status()).toBe(200);
    return await res.json();
}

async function getFreshChallengeToken(request: any): Promise<string> {
    const res = await request.get('/identity/accounts/webauthn/assertion-options');
    expect(res.status()).toBe(200);
    return (await res.json()).token;
}

async function createUnverifiedAccount(request: any, user: { email?: string, name?: string, password?: string }) {
    const res = await request.post('/identity/accounts/register', {
        data: {
            email: user.email,
            name: user.name,
            kdfType: 0,
            kdfIterations: 600000,
            userSymmetricKey: `test-key-${user.name}`,
            masterPasswordHash: `test-master-password-hash-${user.name}`,
            masterPasswordHint: null,
        },
    });
    expect(res.status()).toBe(200);
}

test.describe('Passkey login rejects forged disabled-user handles with the generic AUTH_FAILED', () => {
    // The user is created in beforeAll and used by the test below; the
    // file-level beforeAll already starts the default-config vault.
    test.beforeAll('Create user1', async ({ browser }) => {
        const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await ctx.newPage();
        await createAccount(test, page, users.user1);
        await ctx.close();
    });

    test('disabled target response is indistinguishable from unknown user before verification', async ({ request }) => {
        await adminLogin(request);
        const user = await adminGetUserByEmail(request, users.user1.email!);

        const disableRes = await request.post(`/admin/users/${user.id}/disable`, {
            headers: { 'Content-Type': 'application/json' },
            failOnStatusCode: false,
        });
        expect(disableRes.status()).toBe(200);

        try {
            const baselineToken = await getFreshChallengeToken(request);
            const baseline = await request.post('/identity/connect/token', {
                form: webauthnGrantTargetingUser(baselineToken, '00000000-0000-0000-0000-000000000000'),
            });
            const targetToken = await getFreshChallengeToken(request);
            const target = await request.post('/identity/connect/token', {
                form: webauthnGrantTargetingUser(targetToken, user.id),
            });
            expect(target.status()).toBeGreaterThanOrEqual(400);
            expect(target.status()).toBe(baseline.status());
            const targetBody: any = await target.json();
            const baselineBody: any = await baseline.json();
            expect(baselineBody?.message, 'baseline must carry a message').toBeTruthy();
            expect(targetBody?.message).toBe(baselineBody?.message);
        } finally {
            await request.post(`/admin/users/${user.id}/enable`, {
                headers: { 'Content-Type': 'application/json' },
                failOnStatusCode: false,
            });
        }
    });
});

test.describe('Passkey grant is rejected when SSO_ONLY is on', () => {
    // Defends `check_sso_only` (deny-by-default whitelist). Restart the
    // vault with SSO_ENABLED + SSO_ONLY for this describe's tests, then
    // restart with default config in afterAll.
    test.beforeAll('Start vault with SSO_ONLY', async ({ browser }, testInfo) => {
        utils.stopVault(true);
        await utils.startVault(browser, testInfo, {
            SSO_ENABLED: 'true',
            SSO_ONLY: 'true',
            SSO_AUTHORITY: 'http://127.0.0.1:65535/realms/test',
            SSO_CLIENT_ID: 'test',
            SSO_CLIENT_SECRET: 'test',
        }, false);
    });

    test.afterAll('Restore default vault', async ({ browser }, testInfo) => {
        utils.stopVault(true);
        await utils.startVault(browser, testInfo, {}, false);
    });

    test('webauthn grant denied with an SSO-mentioning message', async ({ request }) => {
        // The SSO_ONLY gate fires BEFORE token validation, so a dummy
        // token is fine — the dispatcher denies the grant outright.
        const res = await request.post('/identity/connect/token', {
            form: webauthnGrantTargetingUser('00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000'),
        });
        expect(res.status()).toBeGreaterThanOrEqual(400);
        const body: any = await res.json();
        expect(body?.message ?? '').toMatch(/SSO sign-in is required/i);
    });

    test('GET assertion-options (login challenge) denied with an SSO-mentioning message', async ({ request }) => {
        // The unauthenticated entry point for "Log in with passkey" — the
        // SPA fetches this BEFORE invoking the WebAuthn ceremony, so the
        // server-side gate here is what prevents an attacker from
        // attempting passkey login even with a credential a victim has
        // previously enrolled. Mirrors `src/api/identity.rs` line 1250.
        const res = await request.get('/identity/accounts/webauthn/assertion-options');
        expect(res.status()).toBeGreaterThanOrEqual(400);
        const body: any = await res.json();
        expect(body?.message ?? '').toMatch(/SSO sign-in is required/i);
    });
});

test.describe('Passkey enrolment is rejected when SSO_ONLY is on', () => {
    // Defends the deny-by-default gate on the management-side endpoints
    // (`src/api/core/mod.rs` lines 308, 390, 459, 516 — guarded by
    // `sso_enabled() && sso_only() && !sso_only_allow_passkey_unlock()`).
    //
    // The enrol endpoints are authenticated, so we need a Bearer token
    // to reach the gate; under `SSO_ONLY=true` fresh logins must go
    // through the IdP, and the test setup has no Keycloak to satisfy it.
    // Restarting the vault container with `SSO_ONLY=true` would wipe the
    // tmpfs-backed sqlite DB (env-change forces docker to recreate the
    // container), losing both the user and the RSA signing key that the
    // pre-issued token was signed against. Instead we provision the
    // account under default config, sniff its Bearer header from a
    // post-login /api/sync, then toggle `sso_enabled`/`sso_only` at
    // runtime via `POST /admin/config` — no container restart, the user
    // + RSA key + access token all stay valid until the 10-min token
    // expiry.
    let savedToken: string | undefined;
    const enrolUser = {
        email: `e2e-sso-only-enrol-${Date.now()}@example.com`,
        name: 'SSO_ONLY Enrol',
        password: 'Master Password',
    };

    test.beforeAll('Provision user, sniff bearer, flip SSO_ONLY via /admin/config', async ({ browser, request }) => {
        const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await ctx.newPage();
        const tokens: string[] = [];
        page.on('request', req => {
            const auth = req.headers()['authorization'];
            if (auth?.startsWith('Bearer ')) tokens.push(auth.slice('Bearer '.length));
        });
        await createAccount(test, page, enrolUser);
        await expect.poll(() => tokens.length, { timeout: 10_000 }).toBeGreaterThan(0);
        savedToken = tokens[tokens.length - 1];
        await ctx.close();

        await adminLogin(request);
        const r = await request.post('/admin/config', {
            data: {
                sso_enabled: true,
                sso_only: true,
                sso_authority: 'http://127.0.0.1:65535/realms/test',
                sso_client_id: 'test',
                sso_client_secret: 'test',
            },
        });
        expect(r.status(), 'admin /config toggle must succeed').toBeLessThan(400);
    });

    test.afterAll('Toggle SSO back off', async ({ request }) => {
        await adminLogin(request);
        await request.post('/admin/config', {
            data: { sso_enabled: false, sso_only: false },
            failOnStatusCode: false,
        });
    });

    test('POST /api/webauthn/attestation-options denied with an SSO-mentioning message', async ({ request }) => {
        expect(savedToken, 'beforeAll must have sniffed a Bearer token').toBeTruthy();
        // The SSO_ONLY gate fires before `data.validate(...)` (which
        // checks the master-password hash), so a dummy payload is fine.
        const res = await request.post('/api/webauthn/attestation-options', {
            headers: { Authorization: `Bearer ${savedToken}`, 'Content-Type': 'application/json' },
            data: { masterPasswordHash: 'gate-fires-before-this-is-validated' },
        });
        const text = await res.text();
        expect(res.status()).toBeGreaterThanOrEqual(400);
        expect(text).toMatch(/SSO sign-in is required/i);
    });
});

test.describe('Passkey login rejects forged unverified-email handles with the generic AUTH_FAILED', () => {
    // Needs SIGNUPS_VERIFY=true + a configured (any) SMTP host so
    // CONFIG.mail_enabled() returns true. Restart vault with that config; the
    // new signup lands in DB with verified_at = NULL.
    test.beforeAll('Start vault with SIGNUPS_VERIFY', async ({ browser }, testInfo) => {
        utils.stopVault(true);
        await utils.startVault(browser, testInfo, {
            SIGNUPS_VERIFY: 'true',
            // SMTP_HOST + SMTP_FROM are both required when mail is enabled;
            // the address doesn't have to be reachable — the gate only
            // checks that config is present.
            SMTP_HOST: '127.0.0.1',
            SMTP_FROM: 'test@example.invalid',
        }, true);
    });

    test.afterAll('Restore default vault', async ({ browser }, testInfo) => {
        utils.stopVault(true);
        await utils.startVault(browser, testInfo, {}, true);
    });

    test('unverified target response is indistinguishable from unknown user before verification', async ({ request }) => {
        await createUnverifiedAccount(request, users.user2);
        await adminLogin(request);
        const user = await adminGetUserByEmail(request, users.user2.email!);

        const baselineToken = await getFreshChallengeToken(request);
        const baseline = await request.post('/identity/connect/token', {
            form: webauthnGrantTargetingUser(baselineToken, '00000000-0000-0000-0000-000000000000'),
        });
        const targetToken = await getFreshChallengeToken(request);
        const target = await request.post('/identity/connect/token', {
            form: webauthnGrantTargetingUser(targetToken, user.id),
        });
        expect(target.status()).toBeGreaterThanOrEqual(400);
        expect(target.status()).toBe(baseline.status());
        const targetBody: any = await target.json();
        const baselineBody: any = await baseline.json();
        expect(baselineBody?.message, 'baseline must carry a message').toBeTruthy();
        expect(targetBody?.message).toBe(baselineBody?.message);
    });
});

// ---------------------------------------------------------------------------
// `UserDecryptionOptions` (login) and `userDecryption` (sync) response shapes
// must match upstream Bitwarden. Unit tests pin the helpers in isolation; this
// integration test pins what the wire-level responses actually look like —
// catching a regression where a helper exists but is no longer called (or is
// called from the wrong endpoint).
// ---------------------------------------------------------------------------

test.describe('UserDecryption response shapes match upstream Bitwarden', () => {
    test('password login + sync emit upstream-canonical UserDecryption fields', async ({ request }) => {
        // Upstream contract this test pins:
        //
        // 1. `IdentityTokenResponse.UserDecryptionOptions` has only the **singular**
        //    `WebAuthnPrfOption`, populated solely by the webauthn grant via
        //    `UserDecryptionOptionsBuilder.WithWebAuthnLoginCredential`. The password grant
        //    must NOT emit the plural `WebAuthnPrfOptions` here — that field doesn't exist
        //    on this model upstream. A prior refactor added it as API-surface drift; this
        //    assertion catches a regression in that direction.
        //
        // 2. `SyncResponseModel.UserDecryption.WebAuthnPrfOptions` (plural array) MUST be
        //    present on every /sync response. An empty array is the correct shape when the
        //    user has no PRF-enabled credentials. The Bitwarden client's lock-screen
        //    "Unlock with passkey" option reads from this field; if it's absent, the option
        //    never renders even when the user qualifies.

        const email = `prf-shape-${Date.now()}@example.com`;
        const password = `master-pw-${Date.now()}`;

        const reg = await request.post('/identity/accounts/register', {
            data: {
                email,
                name: 'PRF Shape Test',
                kdfType: 0,
                kdfIterations: 600000,
                userSymmetricKey: '2.test-key',
                masterPasswordHash: password,
                masterPasswordHint: null,
            },
        });
        expect(reg.status()).toBe(200);

        const tokenRes = await request.post('/identity/connect/token', {
            form: {
                grant_type: 'password',
                username: email,
                password,
                scope: 'api offline_access',
                client_id: 'web',
                device_identifier: '11111111-1111-1111-1111-111111111111',
                device_name: 'pw-shape-test',
                device_type: '9',
            },
        });
        expect(tokenRes.status()).toBe(200);
        const token: any = await tokenRes.json();

        // (1) password-grant login response must NOT carry the plural — upstream doesn't
        //     emit it on this model regardless of grant type. The singular is also absent
        //     for password grant (the builder only populates it on webauthn grant).
        expect(token.UserDecryptionOptions).toBeTruthy();
        expect(token.UserDecryptionOptions).not.toHaveProperty('WebAuthnPrfOptions');
        expect(token.UserDecryptionOptions).not.toHaveProperty('WebAuthnPrfOption');

        // (2) /sync MUST carry `webAuthnPrfOptions` as an array, possibly empty.
        const syncRes = await request.get('/api/sync', {
            headers: { Authorization: `Bearer ${token.access_token}` },
        });
        expect(syncRes.status()).toBe(200);
        const sync: any = await syncRes.json();
        expect(sync.userDecryption).toBeTruthy();
        expect(Array.isArray(sync.userDecryption.webAuthnPrfOptions)).toBe(true);
        expect(sync.userDecryption.webAuthnPrfOptions).toEqual([]);
    });

    test('/api/config advertises the pm-2035-passkey-unlock feature flag', async ({ request }) => {
        // The lock-screen "Unlock with passkey" option is gated on the
        // `pm-2035-passkey-unlock` feature flag in /api/config featureStates.
        // The Bitwarden web vault's `WebAuthnPrfUnlockService.isPrfUnlockAvailable`
        // short-circuits to `false` when the flag is missing or unset, hiding
        // the button even when the user has a PRF-enabled passkey registered.
        // Vaultwarden supports PRF passkey unlock end-to-end (the /sync
        // `userDecryption.webAuthnPrfOptions` blob feeds the unwrap), so the
        // flag must be advertised as enabled.
        //
        // Reference: `pm-2035-passkey-unlock` in
        // https://github.com/bitwarden/clients/blob/main/libs/common/src/enums/feature-flag.enum.ts
        const res = await request.get('/api/config');
        expect(res.status()).toBe(200);
        const config: any = await res.json();
        expect(config.featureStates, 'featureStates must be an object').toBeTruthy();
        expect(config.featureStates['pm-2035-passkey-unlock']).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// UI flows — Chromium-only, one passkey behaviour per test against a fresh
// user. Smaller-scope companions to `account_lifecycle.spec.ts`'s 23-step
// lifecycle: a regression in (say) "Unlock with passkey" takes out only the
// one relevant test rather than the whole sequence.
// ---------------------------------------------------------------------------

const MP = 'Master Password';

/** Per-test user. Synthesised fresh so tests don't share state. */
function freshUser(slug: string) {
    return {
        email: `e2e-passkey-${slug}-${Date.now()}@example.com`,
        name: `Passkey UI ${slug}`,
        password: MP,
    };
}

test.describe('Passkey UI flows', () => {
    // CDP virtual authenticator + `hmac-secret` PRF extension are
    // Chromium-only. The request-level suites above are browser-agnostic
    // and run under every project; these UI flows skip elsewhere.
    test.skip(
        ({ browserName }) => browserName !== 'chromium',
        'requires Chromium CDP virtual authenticator with hmac-secret/PRF',
    );

    test('Enrol PRF passkey → log out → log in with passkey lands in /vault', async ({ page }) => {
        await addVirtualAuthenticator(page);
        const user = freshUser('login');

        await createAccount(test, page, user);
        await enrollLoginPasskey(page, user.password, 'login-key', { useForEncryption: true });

        await utils.logout(test, page, user);
        await clickLoginWithPasskey(page);

        // The webauthn grant returns the wrapped user key, the SPA unwraps via
        // PRF inline, and the user lands directly in /vault — no 2FA challenge
        // (none enrolled), no lock-screen detour.
        await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });
        expect(page.url(), 'passkey-grant login must not visit /#/2fa').not.toMatch(/\/2fa/);
    });

    test('Enrol PRF passkey → lock vault → unlock with passkey lands in /vault', async ({ page }) => {
        await addVirtualAuthenticator(page);
        const user = freshUser('unlock');

        await createAccount(test, page, user);
        await enrollLoginPasskey(page, user.password, 'unlock-key', { useForEncryption: true });

        // The bundled web vault caches `userDecryption.webAuthnPrfOptions`
        // from the initial /api/sync and does NOT auto-refresh after a
        // credential mutation, so a lock-screen check immediately after
        // enrolment would see the credential-free cache and miss the
        // newly-enrolled passkey-unlock affordance. Log out + log back
        // in with the passkey to force a fresh post-login sync —
        // mirrors the lifecycle spec's pattern around steps 4/19.
        await utils.logout(test, page, user);
        await clickLoginWithPasskey(page);
        await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });

        await lockVault(page, user.name);
        // Lock screen surfaces BOTH the MP unlock AND the passkey-unlock
        // affordance once a PRF credential is enrolled.
        await expectLockScreenButtons(page, true);

        await unlockWithPasskey(page);
        await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });
    });

    test('Non-PRF passkey: login affordance present, unlock affordance absent', async ({ page }) => {
        await addVirtualAuthenticator(page);
        const user = freshUser('noprf');

        await createAccount(test, page, user);
        // `useForEncryption: false` enrols the credential without the
        // PRF-wrapped user-key blobs; /api/sync's `webAuthnPrfOptions` stays
        // empty (already pinned by `account_lifecycle.spec.ts`'s wire-shape
        // probe), so the lock-screen "Unlock with passkey" button must stay
        // hidden even though the credential is registered.
        await enrollLoginPasskey(page, user.password, 'noprf-key', { useForEncryption: false });

        await lockVault(page, user.name);
        await expectLockScreenButtons(page, false);
    });

    test('Two PRF passkeys, remove first, second still unlocks', async ({ page }) => {
        const first = 'multi-key-1';
        const second = 'multi-key-2';
        await addVirtualAuthenticator(page);
        const user = freshUser('multi');

        await createAccount(test, page, user);
        await enrollLoginPasskey(page, user.password, first, { useForEncryption: true });

        // Second enrolment requires a second authenticator: the server passes
        // the existing cred in `excludeCredentials`, and a single authenticator
        // refuses `credentials.create()` for a user it already holds a cred for.
        await addVirtualAuthenticator(page);
        await enrollLoginPasskey(page, user.password, second, { useForEncryption: true });

        // Remove the first passkey — MP fresh from the second enrolment.
        await removeLoginPasskey(page, user.password, first);

        // Detach the first authenticator: it still holds the now-removed
        // `multi-key-1` resident credential, and with an empty allow-list a
        // discoverable `credentials.get()` could non-deterministically answer
        // with it (→ server AUTH_FAILED). Removing it leaves `multi-key-2` as
        // the only credential that can satisfy the login.
        await removeVirtualAuthenticator(0);

        // Log out + log back in (with the remaining passkey) to force a
        // fresh post-login sync — see the unlock test above for context.
        await utils.logout(test, page, user);
        await clickLoginWithPasskey(page);
        await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });

        // Second credential still wraps the user key, so unlock still works.
        await lockVault(page, user.name);
        await expectLockScreenButtons(page, true);
        await unlockWithPasskey(page);
        await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });
    });
});
