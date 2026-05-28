/**
 * Shared helpers for the account-lifecycle specs (MP-mode and SSO-mode
 * lifecycles parameterised across `account-lifecycle` and `account-lifecycle-sso`
 * Playwright projects). Mode-agnostic: nothing here knows whether the
 * test signs the user in via master password or SSO. Login choreography
 * is owned by the spec; these helpers cover the bits that don't vary:
 *
 *   • CDP virtual-authenticator wrangling (with `autoPresence` toggle).
 *   • Login-passkey enrolment + removal (Settings → Security → Master
 *     password).
 *   • WebAuthn-as-2FA enrolment + disable (Settings → Security →
 *     Two-step login).
 *   • Lock vault + unlock helpers (passkey, MP).
 *   • MP change + KDF iterations bump.
 *   • Lock-screen-affordance baseline assertion.
 *   • Fresh-context spawn + "Log in with device" + approve flow.
 *
 * Call `resetVirtualAuthenticators()` from a `test.beforeEach` so the
 * module-scoped CDP session cache is dropped between tests in the same
 * file (Playwright recycles the page each test, and a stale session
 * would crash the next `send()`).
 */

import { test, expect, type CDPSession, type Page } from '@playwright/test';

import * as utils from '../../global-utils';

// `Test` is exported as a value in the playwright runtime but not in the
// .d.ts namespace; mirror the alias the other setups files use.
export type Test = typeof test;

export const AUTHENTICATOR_OPTIONS = {
    protocol: 'ctap2' as const,
    ctap2Version: 'ctap2_1' as const,
    transport: 'internal' as const,
    hasResidentKey: true,
    hasUserVerification: true,
    hasPrf: true,
    automaticPresenceSimulation: true,
    isUserVerified: true,
    defaultBackupEligibility: false,
    defaultBackupState: false,
};

/**
 * Attach a CDP virtual authenticator. The first call also enables the
 * WebAuthn domain on the session. Subsequent calls add another
 * authenticator on the same session, simulating a user with multiple
 * devices — required for multi-credential enrolment, because the server
 * passes `excludeCredentials` and any authenticator already holding a
 * listed credential refuses to create another for the same user.
 *
 * Chrome enforces "at most one `internal` (platform) authenticator per
 * environment", so the first authenticator is internal (Touch ID /
 * Windows Hello-like) and additional ones use USB transport.
 */
let sharedCdpSession: CDPSession | null = null;
const virtualAuthenticatorIds: string[] = [];

export async function addVirtualAuthenticator(page: Page) {
    if (!sharedCdpSession) {
        sharedCdpSession = await page.context().newCDPSession(page);
        await sharedCdpSession.send('WebAuthn.enable');
    }
    const isFirst = virtualAuthenticatorIds.length === 0;
    const options = isFirst
        ? AUTHENTICATOR_OPTIONS
        : { ...AUTHENTICATOR_OPTIONS, transport: 'usb' as const };
    const { authenticatorId } = await sharedCdpSession.send('WebAuthn.addVirtualAuthenticator', { options });
    virtualAuthenticatorIds.push(authenticatorId);
}

/**
 * Detach a previously-added virtual authenticator by add-order index (0 =
 * first added). Used when a test removes a credential server-side and must
 * stop that credential's now-orphaned resident key from answering a later
 * discoverable `credentials.get()`: with multiple authenticators holding
 * resident credentials and an empty allow-list, which one responds is
 * otherwise non-deterministic.
 */
export async function removeVirtualAuthenticator(index: number) {
    if (!sharedCdpSession) {
        throw new Error('removeVirtualAuthenticator called before addVirtualAuthenticator');
    }
    const authenticatorId = virtualAuthenticatorIds[index];
    if (authenticatorId === undefined) {
        throw new Error(`removeVirtualAuthenticator: no authenticator at index ${index}`);
    }
    await sharedCdpSession.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    virtualAuthenticatorIds.splice(index, 1);
}

/**
 * Drop the cached CDP session + authenticator IDs. Call from
 * `test.beforeEach`: CDP sessions are bound to a specific Page;
 * Playwright recycles the page between tests in the same file, so a
 * stale session would crash the next `send()` with "Target page,
 * context or browser has been closed".
 */
export function resetVirtualAuthenticators() {
    sharedCdpSession = null;
    virtualAuthenticatorIds.length = 0;
}

/**
 * Toggle automatic user-presence simulation across every attached
 * virtual authenticator. See `withAuthenticatorDisabled` for the safer
 * wrapper.
 */
export async function setAuthenticatorAutoPresence(enabled: boolean) {
    if (!sharedCdpSession) {
        // A silent no-op here would let `withAuthenticatorDisabled` run its
        // body with auto-presence still live, reintroducing the iframe
        // auto-fire race the wrapper exists to prevent. Fail loudly instead
        // so a future call ordered before `addVirtualAuthenticator` surfaces.
        throw new Error('setAuthenticatorAutoPresence called before addVirtualAuthenticator');
    }
    for (const authenticatorId of virtualAuthenticatorIds) {
        await sharedCdpSession.send('WebAuthn.setAutomaticPresenceSimulation', {
            authenticatorId,
            enabled,
        });
    }
}

/**
 * Run `body` with the virtual authenticators' auto-presence simulation
 * disabled, restoring it (even on failure) when `body` returns. Needed
 * when the test wants to click "Select another method" on /#/2fa — the
 * connector iframe otherwise auto-fires WebAuthn the instant it mounts
 * and the page races to /vault before the picker is reachable.
 */
export async function withAuthenticatorDisabled<T>(body: () => Promise<T>): Promise<T> {
    await setAuthenticatorAutoPresence(false);
    try {
        return await body();
    } finally {
        await setAuthenticatorAutoPresence(true);
    }
}

/**
 * Enrol a login passkey via Settings → Security → Master password. Two
 * entry points open the same dialog: "Turn on" for the first credential,
 * "New passkey" once login-with-passkey is already on.
 */
export async function enrollLoginPasskey(
    page: Page,
    mp: string,
    credentialName: string,
    { useForEncryption }: { useForEncryption: boolean },
) {
    await page.goto('/#/settings/security/password');
    await page.waitForLoadState('networkidle');

    const enrolButton = page
        .getByRole('button', { name: /Turn on|New passkey/i })
        .first();
    await enrolButton.waitFor({ state: 'visible' });
    await enrolButton.click();

    const mpInput = page.locator('input#masterPassword');
    await mpInput.waitFor({ state: 'visible' });
    await mpInput.fill(mp);
    // Two `Continue` buttons coexist on this page; pressing Enter inside
    // the password input submits the dialog form unambiguously.
    await mpInput.press('Enter');

    const nameInput = page.locator('input[formcontrolname="name"]');
    await nameInput.waitFor({ state: 'visible' });
    await nameInput.fill(credentialName);

    // `useForEncryption` is default-checked in the bundled web vault, so
    // the disabled case has to set it explicitly.
    const prfToggle = page.locator('input[formcontrolname="useForEncryption"]');
    if (useForEncryption) {
        await prfToggle.check();
    } else {
        await prfToggle.uncheck();
    }

    // Dialog submit — "Turn on" on first enrolment, "Save" on subsequent;
    // both type=submit inside the bit-dialog.
    await page.locator('bit-dialog button[type="submit"]').click();
    await expect(page.locator('bit-dialog')).toHaveCount(0);
}

/**
 * Remove a registered login passkey. The credentials list is a table;
 * each row has a "Remove <credentialName>" action. Clicking it opens an
 * MP user-verification gate; submitting MP both verifies and applies the
 * removal — no separate "Yes" confirm.
 */
export async function removeLoginPasskey(page: Page, mp: string, credentialName: string) {
    await page.goto('/#/settings/security/password');
    await page.waitForLoadState('networkidle');

    await page.getByRole('button', { name: `Remove ${credentialName}`, exact: true }).click();

    const mpInput = page.locator('input#masterPassword');
    await mpInput.waitFor({ state: 'visible' });
    await mpInput.fill(mp);
    await mpInput.press('Enter');

    // Anchor on the master-password dialog closing before the absence check,
    // so the latter can't pass against the pre-removal DOM (or a still-open
    // dialog after a rejected master password).
    await expect(mpInput).toHaveCount(0);
    await expect(page.getByText(credentialName, { exact: true })).toHaveCount(0);
}

/**
 * Enrol the WebAuthn-as-2FA provider (Settings → Security → Two-step
 * login → Passkey row). Separate code path from "Log in with passkey":
 * the credential is stored in `two_factor` (TwoFactor::Webauthn) rather
 * than `web_authn_credentials`, used as a second factor during login.
 */
export async function enrollWebauthn2FA(page: Page, mp: string, credentialName: string) {
    await page.goto('/#/settings/security/two-factor');
    await page.waitForLoadState('networkidle');
    await page.locator('bit-item').filter({ hasText: 'Passkey' }).first().getByRole('button').first().click();

    const mpInput = page.locator('input#masterPassword');
    await mpInput.waitFor({ state: 'visible' });
    await mpInput.fill(mp);
    await mpInput.press('Enter');

    const nameInput = page.locator('input[formcontrolname="name"]');
    await nameInput.waitFor({ state: 'visible' });
    await nameInput.fill(credentialName);
    await page.getByRole('button', { name: 'Read key' }).click();
    await page.getByRole('button', { name: 'Save' }).click();

    await expect(page.locator('bit-dialog')).toHaveCount(0);
}

/**
 * Disable the WebAuthn-as-2FA provider (Settings → Security → Two-step
 * login → Passkey row → Manage → Deactivate all keys → Yes). The
 * bundled web vault uses "Deactivate all keys" rather than "Turn off"
 * for the WebAuthn provider.
 */
export async function disableWebauthn2FA(page: Page, mp: string) {
    await page.goto('/#/settings/security/two-factor');
    await page.waitForLoadState('networkidle');
    await page.locator('bit-item').filter({ hasText: 'Passkey' }).first().getByRole('button').first().click();

    const mpInput = page.locator('input#masterPassword');
    await mpInput.waitFor({ state: 'visible' });
    await mpInput.fill(mp);
    await mpInput.press('Enter');

    await page.getByRole('button', { name: 'Deactivate all keys' }).click();
    await page.getByRole('button', { name: 'Yes' }).click();
    await utils.checkNotification(page, 'Two-step login provider turned off');
}

/**
 * Click the avatar menu's "Lock now". Vault transitions to /lock.
 * Cipher rows also expose `aria-haspopup="menu"` ellipsis buttons, so
 * we anchor on the avatar's accessible name (the user's display name).
 */
export async function lockVault(page: Page, userName: string) {
    await page.getByRole('button', { name: userName, exact: true }).click();
    await page.getByRole('menuitem', { name: /^Lock/i }).first().click();
    await expect(page).toHaveURL(/\/lock/, { timeout: 10_000 });
}

/**
 * Click "Unlock with passkey" on the lock screen. The web vault performs
 * WebAuthn.get() in the main frame (no iframe ceremony), so the virtual
 * authenticator satisfies it. PRF output decrypts the user key locally
 * from the wrapped-key blobs in /sync's webAuthnPrfOptions.
 */
export async function unlockWithPasskey(page: Page) {
    await page.getByRole('button', { name: /Unlock with passkey/i }).click();
    await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });
}

/** Unlock the (locked) vault by typing the master password. */
export async function unlockWithMP(page: Page, password: string) {
    await page.getByLabel('Master password').fill(password);
    await page.getByRole('button', { name: 'Unlock', exact: true }).click();
    await expect(page).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });
}

/**
 * Click "Log in with passkey" on the unauthenticated login page. The
 * web vault opens a same-origin /webauthn-connector.html iframe which
 * immediately calls navigator.credentials.get() — the CDP virtual
 * authenticator attached to the page satisfies it across the iframe
 * boundary in current Chromium.
 *
 * No URL assertion here on purpose: the caller knows whether 2FA is
 * enrolled and asserts /vault vs /#/2fa accordingly.
 */
export async function clickLoginWithPasskey(page: Page) {
    await utils.cleanLanding(page);
    await page.getByRole('button', { name: /Log in with passkey/i }).click();
}

/**
 * Drive the /#/login email-entry step to the master-password unlock
 * page (where "Log in with master password" + the conditional "Log in
 * with device" affordance live).
 *
 * Vaultwarden's CSS overrides hide a different email field per SSO
 * mode, so the path to the same MP page differs:
 *   • MP mode (`SSO_ENABLED=false`): `.vw-email-sso` and "Other" are
 *     hidden; `.vw-email-continue` + "Continue" are visible. Fill +
 *     Continue gets to MP page.
 *   • SSO mode (`SSO_ENABLED=true`): `.vw-email-continue` + "Continue"
 *     are hidden; `.vw-email-sso` is the only visible email input and
 *     "Other" replaces "Continue" to switch into the MP branch. Fill
 *     the SSO input, click "Other" — lands directly on MP page.
 */
export async function enterEmailOnLoginPage(page: Page, email: string, opts: { sso?: boolean } = {}) {
    if (opts.sso) {
        await page.locator('input[type=email].vw-email-sso').fill(email);
        await page.getByRole('button', { name: 'Other' }).click();
    } else {
        await page.getByLabel(/Email address/).fill(email);
        await page.getByRole('button', { name: 'Continue' }).click();
    }
}

/**
 * Lock-screen affordance baseline assertion: master-password unlock +
 * log-out are always present; passkey-unlock conditional on
 * `expectPasskeyUnlock`. Mode-agnostic — the lock screen looks the same
 * whether the user logged in via MP or SSO.
 */
export async function expectLockScreenButtons(page: Page, expectPasskeyUnlock: boolean) {
    await expect(page.getByRole('button', { name: 'Unlock', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log out' })).toBeVisible();

    const unlock = page.getByRole('button', { name: /Unlock with passkey/i });
    if (expectPasskeyUnlock) {
        await expect(unlock).toBeVisible();
    } else {
        await expect(unlock).toHaveCount(0);
    }
}

/**
 * Drive Settings → Security → Master password → "Change master password".
 * Optionally also ticks "Also rotate my account's encryption key", which
 * opens a confirmation dialog (must be acknowledged before submit).
 *
 * Bitwarden v2026 rotation is async: clicking submit kicks off a
 * multi-second client-side rewrap (re-wraps user key + all PRF/passkey
 * credentials) BEFORE the API call fires. Endpoints:
 *   • non-rotation password change → POST /api/accounts/password
 *   • rotation → POST /api/accounts/key-management/rotate-user-account-keys
 * The bundled web vault auto-navigates to /#/login on success; returning
 * before the POST goes out tears down the in-flight rewrap. Waits on the
 * response so callers can assume rotation is durable.
 */
export async function changeMasterPassword(
    page: Page,
    currentMp: string,
    newMp: string,
    rotateEncryptionKey = false,
) {
    await page.goto('/#/settings/security/password');
    await page.waitForLoadState('networkidle');

    // "Current master password" is unique. "New master password" overlaps
    // with "Confirm new master password" under substring matching, so
    // anchor those by formcontrolname.
    await page.getByLabel('Current master password').first().fill(currentMp);
    await page.locator('input[formcontrolname="newPassword"]').fill(newMp);
    await page.locator('input[formcontrolname="newPasswordConfirm"]').fill(newMp);

    if (rotateEncryptionKey) {
        await page.getByLabel(/Also rotate my account's encryption key/i).check();
        await page
            .getByRole('dialog', { name: /Rotate encryption key/i })
            .getByRole('button', { name: 'Yes' })
            .click();
    }

    const submitResp = page.waitForResponse(r => {
        const u = r.url();
        return u.includes('/api/accounts/password')
            || u.includes('/api/accounts/key-management/rotate-user-account-keys');
    }, { timeout: 60_000 });
    await page.getByRole('button', { name: 'Change master password' }).click();
    await submitResp;
}

/**
 * Bump the user's KDF iteration count via Settings → Security → Keys.
 * Submitting rotates the security stamp (auto-logout) so callers pick
 * up from /#/login. The form requires MP verification before the actual
 * `/api/accounts/kdf` POST fires.
 */
export async function changeKdfIterations(page: Page, mp: string, iterations: number) {
    await page.goto('/#/settings/security/security-keys');
    await page.waitForLoadState('networkidle');

    const iterationsInput = page.getByLabel('KDF iterations');
    await iterationsInput.waitFor({ state: 'visible' });
    await iterationsInput.fill(String(iterations));
    await iterationsInput.press('Tab');

    await page.getByRole('button', { name: 'Update encryption settings' }).click();

    // Confirmation dialog with an MP gate. The actual POST only fires
    // after MP is supplied and "Update settings" inside the dialog is
    // clicked, so register the waitForResponse here, not before the
    // first click.
    const dialog = page.getByRole('dialog', { name: 'Update your encryption settings' });
    await dialog.getByLabel('Master password').fill(mp);
    const kdfPosted = page.waitForResponse(
        r => /\/api\/accounts\/kdf\b/.test(r.url()) && r.request().method() === 'POST',
        { timeout: 60_000 },
    );
    await dialog.getByRole('button', { name: 'Update settings' }).click();
    await kdfPosted;
}

/**
 * Spawn a fresh browser context (a "new device" from the server's
 * perspective) and return its page, parked on /#/login. Caller is
 * responsible for `page.context().close()` to dispose of it.
 */
export async function createNewDevice(existing: Page): Promise<Page> {
    const ctx = await existing.context().browser()!.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    await page.goto(`${process.env.DOMAIN}/#/login`);
    return page;
}

/**
 * Drive the "Log in with device" passwordless flow against a context
 * whose device is already known. Clicks "Log in with device" — POSTs
 * `/api/auth-requests` and parks the second device on /login-with-device
 * polling for approval. The `approver` page (still authenticated)
 * surfaces the "Review login request" banner via its periodic poll;
 * clicking through and confirming the request lands the second device
 * in /vault.
 */
export async function loginWithDeviceAndApprove(secondDevice: Page, approver: Page) {
    const authRequestPosted = secondDevice.waitForResponse(
        r => /\/api\/auth-requests\b/.test(r.url()) && r.request().method() === 'POST' && r.status() === 200,
        { timeout: 30_000 },
    );
    await secondDevice.getByRole('button', { name: /Log in with device/i }).click();
    await authRequestPosted;

    const reviewLink = approver.getByRole('link', { name: /Review login request/i });
    await reviewLink.waitFor({ state: 'visible', timeout: 60_000 });
    await reviewLink.click();
    // Lands on Settings → Security → Devices. The pending request is a
    // row with a "Request pending" badge; clicking the device link opens
    // the approval dialog whose primary action is "Confirm access".
    await approver.getByRole('row').filter({ hasText: /Request pending/i })
        .getByRole('link').first().click();
    await approver.getByRole('button', { name: 'Confirm access' }).click();

    await expect(secondDevice).toHaveURL(/\/(vault|setup-extension)/, { timeout: 30_000 });
}
