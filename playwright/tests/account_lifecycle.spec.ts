import { test, expect, type Page, type TestInfo } from '@playwright/test';

import * as utils from '../global-utils';
import { createAccount, logUser as logUserMP } from './setups/user';
import { logNewUser as ssoLogNewUser, logUser as logUserSSO } from './setups/sso';
import { activateTOTP, disableTOTP, type TwoFactor } from './setups/2fa';
import {
    addVirtualAuthenticator,
    changeKdfIterations,
    changeMasterPassword,
    clickLoginWithPasskey,
    createNewDevice,
    disableWebauthn2FA,
    enrollLoginPasskey,
    enrollWebauthn2FA,
    enterEmailOnLoginPage,
    expectLockScreenButtons,
    lockVault,
    loginWithDeviceAndApprove,
    removeLoginPasskey,
    resetVirtualAuthenticators,
    type Test,
    unlockWithMP,
    unlockWithPasskey,
    withAuthenticatorDisabled,
} from './setups/account_lifecycle_helpers';

/**
 * End-to-end coverage of "Log in with passkey" enrolment, driven via the web
 * vault UI + a Chromium CDP virtual authenticator. Pins the wire shape the
 * lock-screen "Unlock with passkey" option depends on:
 *
 *   `/api/sync` `userDecryption.webAuthnPrfOptions` is a plural array, always
 *   present, populated exactly with PRF-enabled login passkeys.
 *
 * The lifecycle test is **parameterised by project**: it runs once under
 * `account-lifecycle` (MP-mode login flows) and once under `account-lifecycle-sso`
 * (SSO + MP-unlock flows). The two projects differ only in their
 * `dependencies` (SSO depends on `sso-setup` to bring up Keycloak) and the
 * `SSO_ENABLED` env passed to Vaultwarden. The lifecycle body itself is
 * shared, with mode-specific branches limited to login choreography
 * (sign-up, sign-in, affordance assertions).
 *
 * The two smaller tests (PRF-enrolment-populates-sync and
 * no-PRF-leaves-sync-empty) use the MP registration path and are
 * skipped under the SSO project — they probe server wire shape, which
 * is mode-invariant, so the MP-mode coverage is sufficient.
 *
 * The CDP virtual authenticator with the `hmac-secret` (PRF) extension is
 * Chromium-only; both projects override `browserName: 'chromium'` and
 * `locale: 'en'` (the bundled web vault renders different labels for the
 * WebAuthn provider row under `en_GB`).
 */

let users = utils.loadEnv();

// Defence-in-depth: even if someone runs this spec under a non-`account-lifecycle*`
// project, fail closed rather than crash on the CDP call.
test.skip(
    ({ browserName }) => browserName !== 'chromium',
    'requires Chromium CDP virtual authenticator with hmac-secret/PRF',
);

// `PW_USE_EXTERNAL_VAULT=1` skips the docker startVault/stopVault hooks and
// runs the spec against whatever Vaultwarden is already serving on $DOMAIN.
// Local-iteration knob only; CI and the standard docker harness leave it
// unset and bring the vault up via docker compose as usual.
const useExternalVault = process.env.PW_USE_EXTERNAL_VAULT === '1';

function isSSOMode(testInfo: TestInfo): boolean {
    return testInfo.project.name === 'account-lifecycle-sso';
}

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    if (useExternalVault) return;
    const env = isSSOMode(testInfo)
        ? { SSO_ENABLED: true, SSO_ONLY: false }
        : {};
    await utils.startVault(browser, testInfo, env);
});

test.afterAll('Teardown', async () => {
    if (useExternalVault) return;
    utils.stopVault();
});

// CDP sessions are bound to a specific Page; Playwright recycles the page
// between tests, so drop the cached session/authenticator IDs each time
// (the next `addVirtualAuthenticator` lazily re-establishes them).
test.beforeEach(() => resetVirtualAuthenticators());

const MP = 'Master Password';

type LifecycleUser = { email: string; name: string; password: string };

interface ModeOps {
    /** Create the user account in vaultwarden. */
    signUp(test: Test, page: Page, user: LifecycleUser): Promise<void>;
    /**
     * Log in an existing user. `options.twoFactor` selects a 2FA factor
     * if enrolled. `options.kcPassword` overrides the Keycloak password
     * (SSO mode only) for cases where vault MP and the SSO-provider
     * credential have diverged — e.g. after a vault-side MP rotation
     * which leaves Keycloak's stored credential unaffected.
     */
    signIn(test: Test, page: Page, user: LifecycleUser, options?: { twoFactor?: TwoFactor, kcPassword?: string }): Promise<void>;
}

function modeOps(sso: boolean): ModeOps {
    return sso
        ? { signUp: ssoLogNewUser, signIn: logUserSSO }
        : { signUp: createAccount, signIn: logUserMP };
}

/** Lifecycle user. MP mode synthesises a fresh per-run identity to keep the
 *  SQLite-volatile assumption from leaking on the off-chance a prior project
 *  ran without a DB wipe. SSO mode locks to the Keycloak-seeded `user1`
 *  (`test@example.com` / `test`) — those credentials are pre-provisioned in
 *  the `test` realm by `compose/keycloak/setup.sh`. */
function lifecycleUser(sso: boolean): LifecycleUser {
    if (sso) {
        // `loadEnv()` types every field as `string | undefined` because it
        // reads through `process.env`; the SSO fields are seeded by the
        // `compose/keycloak/setup.sh` provisioning and are non-null in any
        // env that actually runs this project — assert that, then return.
        const { email, name, password } = users.user1;
        if (!email || !name || !password) {
            throw new Error('SSO lifecycle requires TEST_USER_MAIL/TEST_USER/TEST_USER_PASSWORD in test.env');
        }
        return { email, name, password };
    }
    return {
        email: `e2e-lifecycle-${Date.now()}@example.com`,
        name: 'Lifecycle E2E',
        password: MP,
    };
}

/**
 * Negative+positive assertion suite for the unauthenticated /#/login page.
 * "Log in with passkey" is always advertised; "Unlock with passkey" must
 * never bleed onto the login page. "Use single sign-on" presence flips on
 * `sso` — present when `SSO_ENABLED=true`, absent otherwise.
 */
async function expectLoginPageButtons(page: Page, sso: boolean) {
    await expect(page.getByRole('button', { name: /Log in with passkey/i })).toBeVisible();
    if (sso) {
        await expect(page.getByRole('button', { name: 'Use single sign-on' })).toBeVisible();
    } else {
        await expect(page.getByRole('button', { name: 'Use single sign-on' })).toHaveCount(0);
    }
    await expect(page.getByRole('button', { name: /Unlock with passkey/i })).toHaveCount(0);
}

/**
 * Post-email login page when no passkey is enrolled and the current device
 * IS already registered server-side. MP-login + "Log in with device" are
 * offered; passkey/unlock affordances stay absent. SSO mode only changes
 * the pre-email page (the SSO button + email-SSO input live there); the
 * post-email page is the MP flow either way.
 */
async function expectPostEmailPageNoPasskey(page: Page, sso: boolean) {
    await expect(page.getByRole('button', { name: 'Log in with master password' })).toBeVisible();
    await expect(page.getByRole('button', { name: /Log in with device/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /Log in with passkey/i })).toHaveCount(0);
    if (!sso) {
        await expect(page.getByRole('button', { name: 'Use single sign-on' })).toHaveCount(0);
    }
    await expect(page.getByRole('button', { name: /Unlock with passkey/i })).toHaveCount(0);
}

/**
 * Sniff the bearer token off any authenticated request the SPA makes, then
 * use it to call /api/sync directly. The SPA caches sync state in IndexedDB
 * and won't re-fetch on demand; sniffing the live token avoids reaching into
 * that store.
 */
function attachBearerSniffer(page: Page): { token: () => string | undefined } {
    let token: string | undefined;
    page.on('request', (req) => {
        const auth = req.headers()['authorization'];
        if (auth?.startsWith('Bearer ') && req.url().includes('/api/')) {
            token = auth.slice('Bearer '.length);
        }
    });
    return { token: () => token };
}

async function fetchSyncWithToken(page: Page, token: string): Promise<any> {
    const result = await page.evaluate(async (bearer) => {
        const res = await fetch('/api/sync?excludeDomains=true', {
            headers: { Authorization: `Bearer ${bearer}` },
        });
        return { status: res.status, body: await res.text() };
    }, token);
    if (result.status !== 200) {
        throw new Error(`/api/sync ${result.status}: ${result.body}`);
    }
    return JSON.parse(result.body);
}

test('Log in with passkey: PRF enrolment populates webAuthnPrfOptions in /api/sync', async ({ page }, testInfo) => {
    test.skip(isSSOMode(testInfo), 'wire-shape probe; MP coverage is sufficient');

    // End-to-end proof that the lock-screen "Unlock with passkey" affordance
    // has its server-side prerequisite. The web vault renders the button when
    // `userDecryption.webAuthnPrfOptions` is non-empty in /sync; without the
    // server-side fix, the field is missing entirely and the button never
    // appears even after a PRF passkey has been registered.
    await addVirtualAuthenticator(page);
    const bearer = attachBearerSniffer(page);

    const user = {
        email: `e2e-prf-sync-${Date.now()}@example.com`,
        name: 'PRF Sync E2E',
        password: MP,
    };

    await createAccount(test, page, user);
    await enrollLoginPasskey(page, user.password, 'e2e-prf-key', { useForEncryption: true });

    const token = bearer.token();
    expect(token, 'a Bearer token must have flown over the wire').toBeTruthy();
    const sync = await fetchSyncWithToken(page, token!);
    expect(sync.userDecryption, 'sync.userDecryption must be present').toBeTruthy();
    expect(Array.isArray(sync.userDecryption.webAuthnPrfOptions)).toBe(true);
    expect(sync.userDecryption.webAuthnPrfOptions.length).toBeGreaterThan(0);

    // PascalCase: Bitwarden API responses keep model casing. The lock-screen
    // option reads these wrapped-key blobs to derive the user key after the
    // PRF assertion. Matches the shape upstream
    // `SyncResponseModel.UserDecryption.WebAuthnPrfOptions` returns
    // (`bitwarden/server` `UserDecryptionResponseModel.cs`):
    // `EncryptedPrivateKey`, `EncryptedUserKey`, `CredentialId`,
    // `Transports`. The public key isn't part of the unlock payload —
    // PRF unwrap only needs the private-key / user-key blobs.
    const option = sync.userDecryption.webAuthnPrfOptions[0];
    expect(typeof option.CredentialId, 'CredentialId must be a string').toBe('string');
    expect(typeof option.EncryptedPrivateKey, 'EncryptedPrivateKey must be a string').toBe('string');
    expect(typeof option.EncryptedUserKey, 'EncryptedUserKey must be a string').toBe('string');
});

test('Log in with passkey: enrolment without PRF leaves webAuthnPrfOptions empty', async ({ page }, testInfo) => {
    test.skip(isSSOMode(testInfo), 'wire-shape probe; MP coverage is sufficient');

    // Mirror of the above: a passkey enrolled WITHOUT `useForEncryption`
    // must produce an empty (but still present) `webAuthnPrfOptions`
    // array. The web vault uses this signal to keep the lock-screen
    // "Unlock with passkey" button hidden — a non-PRF passkey can be used
    // for the login ceremony but can't decrypt the user key.
    await addVirtualAuthenticator(page);
    const bearer = attachBearerSniffer(page);

    const user = {
        email: `e2e-noprf-sync-${Date.now()}@example.com`,
        name: 'NoPRF Sync E2E',
        password: MP,
    };

    await createAccount(test, page, user);
    await enrollLoginPasskey(page, user.password, 'e2e-noprf-key', { useForEncryption: false });

    const token = bearer.token();
    expect(token, 'a Bearer token must have flown over the wire').toBeTruthy();
    const sync = await fetchSyncWithToken(page, token!);
    expect(sync.userDecryption, 'sync.userDecryption must be present').toBeTruthy();
    expect(Array.isArray(sync.userDecryption.webAuthnPrfOptions)).toBe(true);
    expect(sync.userDecryption.webAuthnPrfOptions).toEqual([]);
});

/**
 * Comprehensive account lifecycle on a single Chromium session — covers
 * every code path that a real user actually exercises. Both passkeys are
 * enrolled while MP is "fresh" (right after registration / MP login), so the
 * web vault's user-verification gate uses the MP path; it would otherwise
 * fall back to email-OTP, which would force a maildev round-trip.
 *
 *   1.  register / SSO sign-up → vault
 *   2.  enrol PRF passkey #1 (MP fresh from registration)
 *   3.  enrol PRF passkey #2 (MP still fresh)
 *   4.  log out, log back in *with passkey* (iframe ceremony in main page)
 *   5.  lock vault → unlock with passkey   ← the reported feature
 *   6.  register a second browser context's device via one-shot
 *       MP login (MP mode) or SSO + MP unlock (SSO mode) — before the
 *       login, "Log in with device" must NOT surface (device unknown);
 *       after login + logout it MUST appear
 *   7.  from the second device, "Log in with device" + approve from the
 *       original context's "Review login request" banner
 *   8.  enrol WebAuthn-as-2FA + TOTP-as-2FA (MP fresh from step 5)
 *   9.  log out, log back in with passkey — server skips 2FA on webauthn grant
 *  10.  log out, log back in with MP + WebAuthn-2FA  (or SSO + WebAuthn-2FA + MP-unlock)
 *  11.  lock + unlock with passkey (both credentials still wrap the user key)
 *  12.  remove passkey #1
 *  13.  bump KDF iteration count (auto-logs out)
 *  14.  log back in with WebAuthn-2FA after KDF auto-logout
 *  15.  rotate account encryption keys (auto-logs out)
 *  16.  log back in with TOTP-2FA after rotation auto-logout
 *  17.  lock + unlock with passkey #2 (rotated/re-KDF'd key still PRF-unlocks)
 *  18.  remove passkey #2 — back to no PRF unlock; lock screen shows MP only
 *  19.  log out, log back in with WebAuthn-2FA (refreshes client-side sync
 *       cache so the step-20 lock-screen assertion sees credential-free state)
 *  20.  lock + assert no passkey unlock affordance
 *  21.  unlock with master password (sanity before disabling 2FA)
 *  22.  disable both 2FA providers
 *  23.  log out, log back in — no 2FA challenge
 *
 * Every WebAuthn ceremony — primary (login-with-passkey) and secondary
 * (WebAuthn-as-2FA) — runs inside the same-origin /webauthn-connector.html
 * iframe; the CDP-injected virtual authenticator satisfies them across the
 * iframe boundary in current Chromium. Unlock-with-passkey runs
 * navigator.credentials.get() in the main frame.
 */
test('Log in with passkey: lifecycle — enrol, login (PRF/MP), lock, unlock, 2FA, rotate, remove', async ({ page }, testInfo) => {
    // 23 steps drive a full account lifecycle on a single Chromium session.
    // Multi-second cost contributors that push past the default 120s budget:
    //   • client-side key rewrap during MP rotation + KDF bump (~10s each)
    //   • a fresh BrowserContext + login + auth-request approval flow (step 7)
    //   • lock/unlock/relogin cycles + 2FA enrolment + teardown
    // Host-mode MP runs ~115s; 180s leaves headroom for docker and CI. If
    // the SSO variant's Keycloak round-trips push real runs past ~150s,
    // bump this; for now both modes land comfortably under.
    test.setTimeout(180_000);

    const sso = isSSOMode(testInfo);
    const ops = modeOps(sso);
    const user = lifecycleUser(sso);
    // SSO mode tracks the Keycloak credential separately from the vault
    // MP. They start equal (Keycloak's seeded password = the MP set
    // during "Join organization"), but step 15 below rotates the MP
    // server-side without touching Keycloak. After that point, SSO
    // signIns must use this original value as `kcPassword` while
    // `user.password` continues to reflect the rotated MP. MP mode
    // ignores this entirely.
    const kcPassword = user.password;
    const first = 'lifecycle-key-1';
    const second = 'lifecycle-key-2';

    await addVirtualAuthenticator(page);

    // 1. Register → vault.
    await ops.signUp(test, page, user);

    // 2. Enrol PRF passkey #1 (MP fresh from registration).
    await enrollLoginPasskey(page, user.password, first, { useForEncryption: true });

    // 3. Enrol PRF passkey #2 on a SECOND virtual authenticator. The server
    //    passes the existing credential in `excludeCredentials`; the first
    //    authenticator would refuse `credentials.create()` because it already
    //    holds a matching credential. Simulates a user adding a second device
    //    to their account.
    await addVirtualAuthenticator(page);
    await enrollLoginPasskey(page, user.password, second, { useForEncryption: true });

    // 4. Log out, log back in WITH PASSKEY. Negative-assert the login-page
    //    affordances before clicking, so a regression that re-introduces
    //    (in MP mode) or hides (in SSO mode) the SSO button is caught here.
    await utils.logout(test, page, user);
    await utils.cleanLanding(page);
    await expectLoginPageButtons(page, sso);
    await clickLoginWithPasskey(page);
    await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });

    // 5. Lock vault, unlock with passkey. Assert the lock screen renders BOTH
    //    the passkey-unlock affordance and the MP one (and nothing else
    //    inappropriate).
    await lockVault(page, user.name);
    await expectLockScreenButtons(page, true);
    await unlockWithPasskey(page);

    // 6. On a fresh browser context (a "second device" from the server's
    //    perspective), register the device with a one-shot login. The bundled
    //    web vault gates "Log in with device" on `isKnownDevice` server-side,
    //    so before this login the button is absent on the post-email page;
    //    after it (and logout) the button surfaces.
    const secondDevice = await createNewDevice(page);
    await enterEmailOnLoginPage(secondDevice, user.email, { sso });
    await expect(secondDevice.getByRole('button', { name: 'Log in with master password' })).toBeVisible();
    await expect(secondDevice.getByRole('button', { name: /Log in with device/i })).toHaveCount(0);
    await ops.signIn(test, secondDevice, user);
    await utils.logout(test, secondDevice, user);

    // 7. Device is now known. Click "Log in with device" — POSTs
    //    /api/auth-requests. The original context (still on /vault)
    //    surfaces the "Review login request" banner and confirms. 2FA
    //    isn't enrolled yet, so the secondDevice lands directly in /vault.
    await enterEmailOnLoginPage(secondDevice, user.email, { sso });
    await loginWithDeviceAndApprove(secondDevice, page);
    await secondDevice.context().close();

    // 8. Enrol WebAuthn-as-2FA + TOTP-as-2FA (MP still fresh from step 5).
    await enrollWebauthn2FA(page, user.password, 'lifecycle-2fa-key');
    const totp = await activateTOTP(test, page, user);

    // 9. Log out, log in with passkey — the passkey IS the auth, so the
    //    server skips the 2FA challenge even though TOTP + WebAuthn-2FA are
    //    enabled. Assert on the grant RESPONSE (200 + access token, no
    //    TwoFactorProviders) rather than the landing URL: a regression that
    //    wrongly demanded a second factor would route through /#/2fa, where
    //    the still-attached virtual authenticator could auto-satisfy
    //    WebAuthn-2FA and mask the failure behind a /vault landing. The
    //    response check inspects the first grant, before any such detour.
    await utils.logout(test, page, user);
    const passkeyGrant = page.waitForResponse(
        (r) => r.url().includes('/identity/connect/token') && r.request().method() === 'POST',
        { timeout: 30_000 },
    );
    await clickLoginWithPasskey(page);
    const passkeyGrantRes = await passkeyGrant;
    expect(passkeyGrantRes.status(), 'passkey grant must issue a token in one shot').toBe(200);
    const passkeyGrantBody: any = await passkeyGrantRes.json();
    expect(passkeyGrantBody.access_token, 'passkey grant must return an access token').toBeTruthy();
    expect(passkeyGrantBody.TwoFactorProviders, 'passkey grant must not demand a second factor').toBeUndefined();
    // With a token issued in one shot the PRF secret unlocks the vault inline,
    // so the SPA lands directly in /vault without a 2FA detour.
    await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });

    // Mode-aware sign-in that guarantees MP is fresh afterwards. MP mode
    // types MP at login, so MP is naturally fresh. SSO mode auths via
    // Keycloak and then routes through `/#/lock?promptBiometric=true`;
    // with a PRF passkey enrolled and the virtual authenticator available,
    // the lock screen auto-fires `credentials.get()` and the user lands
    // on /vault without ever typing MP — leaving subsequent MP-gated
    // user-verification gates to fall back to email-OTP instead. Disable
    // the authenticator across the SSO sign-in (and pick TOTP 2FA, since
    // FIDO2 2FA would need the authenticator too) so the lock screen
    // waits for manual MP entry and MP-fresh state survives.
    async function signInFreshMp() {
        if (sso) {
            await withAuthenticatorDisabled(async () => {
                await ops.signIn(test, page, user, { twoFactor: { kind: 'totp', totp } });
            });
        } else {
            await ops.signIn(test, page, user, { twoFactor: { kind: 'fido2' } });
        }
    }

    // 10. Log out, log in (mode-appropriate) + 2FA. MP mode tests
    //     FIDO2 + MP combo; SSO mode uses TOTP under
    //     withAuthenticatorDisabled to force manual MP unlock (see
    //     `signInFreshMp`).
    await utils.logout(test, page, user);
    await signInFreshMp();

    // 11. Lock + unlock — both PRF credentials still wrap the user key.
    await lockVault(page, user.name);
    await expectLockScreenButtons(page, true);
    await unlockWithPasskey(page);

    // 12. Remove passkey #1 (MP fresh from step 10).
    await removeLoginPasskey(page, user.password, first);

    // 13. Bump KDF iterations. Auto-logs out all sessions (security stamp
    //     rotates); we re-login below. The form lives under Settings →
    //     Security → Keys ("Encryption key settings"); add 10k to the
    //     default to force a non-noop change.
    await changeKdfIterations(page, user.password, 610_000);

    // 14. Re-login after KDF auto-logout (mode-appropriate). MP mode
    //     picks FIDO here (vs TOTP) to avoid stamping a TOTP `last_used`
    //     step that step 16's TOTP submission could collide with — the
    //     rotation rewrap between 14 and 16 is well under 30s. SSO mode
    //     uses TOTP under withAuthenticatorDisabled (see `signInFreshMp`);
    //     it stamps `last_used` at step 14, but step 16 below regenerates
    //     a fresh TOTP code for the next period boundary, so no collision.
    await signInFreshMp();

    // 15. Rotate the account encryption keys (re-wraps each PRF credential's
    //     stored encryptedUserKey/encryptedPrivateKey using the existing PRF
    //     output for that credential, so passkey #2 must still unlock).
    //
    //     The bundled web vault's "Change master password" form rejects
    //     `new == current`, so rotation requires picking a new MP. Mutate
    //     `user.password` so every subsequent step uses the rotated value
    //     without rethreading the variable through 8 more calls. The
    //     rotation also auto-logs-out, so the next step picks up from
    //     /#/login.
    const rotatedMp = `${user.password}!`;
    await changeMasterPassword(page, user.password, rotatedMp, true);
    user.password = rotatedMp;

    // 16. Log back in (mode-appropriate) + TOTP (re-establishes fresh MP
    //     for the upcoming remove-passkey + disable-2FA verification gates).
    //     The WebAuthn-2FA connector iframe on /#/2fa would otherwise
    //     auto-fire and race past the picker; the wrapper disables the
    //     virtual authenticators for the duration of the login. SSO mode
    //     additionally pins `kcPassword` to the original Keycloak
    //     credential — the MP rotated above does not propagate to the
    //     SSO provider.
    await withAuthenticatorDisabled(async () => {
        await ops.signIn(test, page, user, { twoFactor: { kind: 'totp', totp }, kcPassword });
    });

    // 17. Lock + unlock — passkey #2 still wraps the (rotated, re-KDF'd) user key.
    await lockVault(page, user.name);
    await expectLockScreenButtons(page, true);
    await unlockWithPasskey(page);

    // 18. Remove passkey #2. The bundled web vault caches
    //     `userDecryption.webAuthnPrfOptions` from sync and does NOT
    //     auto-refresh after a credential delete; step 19 (log out + log
    //     in with WebAuthn-2FA) below naturally triggers a fresh
    //     post-login sync that writes the credential-free state to
    //     client cache, so we do that before the lock-screen assertion
    //     in step 20.
    await removeLoginPasskey(page, user.password, second);

    // 19. Log out + log back in (mode-appropriate). The post-login sync
    //     refreshes the bundled web vault's cached `webAuthnPrfOptions`
    //     so the next lock-screen check sees the credential-free state.
    //     MP mode uses FIDO2-2FA for symmetry with the earlier MP-only
    //     coverage. SSO mode uses TOTP under withAuthenticatorDisabled:
    //     the 2FA picker dialog races with the WebAuthn-connector
    //     iframe's auto-fire under SSO mode's extra Keycloak round-trip
    //     latency (the dialog can transition while the test is in the
    //     middle of clicking through to the FIDO2 row, detaching the
    //     target element). TOTP sidesteps the picker entirely. SSO mode
    //     also pins `kcPassword` — post-rotation, the IdP credential
    //     remains the original.
    await utils.logout(test, page, user);
    if (sso) {
        await withAuthenticatorDisabled(async () => {
            await ops.signIn(test, page, user, { twoFactor: { kind: 'totp', totp }, kcPassword });
        });
    } else {
        await ops.signIn(test, page, user, { twoFactor: { kind: 'fido2' } });
    }

    // 20. Lock + assert the passkey-unlock button is gone (only MP
    //     unlock remains now that passkey #2 has been removed).
    await lockVault(page, user.name);
    await expectLockScreenButtons(page, false);

    // 21. Unlock with master password to re-enter the vault — passkey unlock
    //     is no longer available so the user must use MP. This is a sanity
    //     step before disabling the 2FA factors below.
    await unlockWithMP(page, user.password);

    // 22. Disable both 2FA providers.
    await disableWebauthn2FA(page, user.password);
    await disableTOTP(test, page, user);

    // 23. Log out, log back in (mode-appropriate) — no 2FA challenge. Pin
    //     the post-email baseline before completing the login (in MP mode
    //     that's the only path; in SSO mode the post-email page is reached
    //     after the user picks the MP-flow entry).
    await utils.logout(test, page, user);
    if (!sso) {
        await utils.cleanLanding(page);
        await enterEmailOnLoginPage(page, user.email);
        await expectPostEmailPageNoPasskey(page, sso);
    }
    await ops.signIn(test, page, user, { kcPassword });
});
