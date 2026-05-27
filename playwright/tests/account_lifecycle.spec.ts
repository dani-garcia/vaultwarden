import { test, expect, type Page, type TestInfo } from '@playwright/test';

import * as utils from '../global-utils';
import { createAccount } from './setups/user';

/**
 * End-to-end coverage of "Log in with passkey" enrolment, driven via the web
 * vault UI + a Chromium CDP virtual authenticator. Pins the wire shape the
 * lock-screen "Unlock with passkey" option depends on:
 *
 *   `/api/sync` `userDecryption.webAuthnPrfOptions` is a plural array, always
 *   present, populated exactly with PRF-enabled login passkeys.
 *
 * Enrolment is driven through the real UI (the `Turn on` flow under Settings
 * → Security → Master password). The post-enrolment `/api/sync` is then
 * called directly from the page context with a sniffed bearer token, since
 * the web vault aggressively caches sync state in IndexedDB and won't
 * re-fetch on hash nav or reload.
 *
 * Runs only under the `account-lifecycle` project (Chromium + `en` locale + SQLite
 * volatile), defined in `playwright.config.ts`. The CDP virtual authenticator
 * with the `hmac-secret` (PRF) extension is Chromium-only; the test would
 * fail immediately on Firefox.
 */

utils.loadEnv();

// Defence-in-depth: even if someone runs this spec under a non-`account-lifecycle`
// project, fail closed rather than crash on the CDP call.
test.skip(
    ({ browserName }) => browserName !== 'chromium',
    'requires Chromium CDP virtual authenticator with hmac-secret/PRF',
);

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {});
});

test.afterAll('Teardown', async () => {
    utils.stopVault();
});

const MP = 'Master Password';

const AUTHENTICATOR_OPTIONS = {
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

async function addVirtualAuthenticator(page: Page) {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTHENTICATOR_OPTIONS });
}

async function enrollLoginPasskey(
    page: Page,
    mp: string,
    credentialName: string,
    { useForEncryption }: { useForEncryption: boolean },
) {
    await page.goto('/#/settings/security/password');
    await page.waitForLoadState('networkidle');

    // "Turn on" button's accessible name is "Turn on Log in with passkey".
    await page.locator('button:has-text("Turn on")').click();

    const mpInput = page.locator('input#masterPassword');
    await mpInput.waitFor({ state: 'visible' });
    await mpInput.fill(mp);
    // Two `Continue` buttons coexist on this page; pressing Enter inside the
    // password input submits the dialog form unambiguously.
    await mpInput.press('Enter');

    // The dialog re-renders with a `name` input + `useForEncryption` checkbox
    // once the credential is created.
    const nameInput = page.locator('input[formcontrolname="name"]');
    await nameInput.waitFor({ state: 'visible' });
    await nameInput.fill(credentialName);

    // The `useForEncryption` checkbox is default-checked in the bundled web
    // vault, so the disabled case has to set it explicitly.
    const prfToggle = page.locator('input[formcontrolname="useForEncryption"]');
    if (useForEncryption) {
        await prfToggle.check();
    } else {
        await prfToggle.uncheck();
    }

    await page.locator('bit-dialog button[type="submit"]:has-text("Turn on")').click();
    await expect(page.locator('bit-dialog')).toHaveCount(0);
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
        throw new Error(`/api/sync returned ${result.status}: ${result.body.slice(0, 200)}`);
    }
    return JSON.parse(result.body);
}

test('Log in with passkey: PRF enrolment populates webAuthnPrfOptions in /api/sync', async ({ page }) => {
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
    // PRF assertion.
    const option = sync.userDecryption.webAuthnPrfOptions[0];
    expect(option).toHaveProperty('EncryptedPrivateKey');
    expect(option).toHaveProperty('EncryptedUserKey');
    expect(option).toHaveProperty('CredentialId');
});

test('Log in with passkey: enrolment without PRF leaves webAuthnPrfOptions empty', async ({ page }) => {
    // The complementary case: a registered login passkey that is NOT
    // PRF-enabled (the `useForEncryption` checkbox left unticked) must not
    // appear in `webAuthnPrfOptions`. Together with the test above this pins
    // both branches of the emission filter.
    await addVirtualAuthenticator(page);
    const bearer = attachBearerSniffer(page);

    const user = {
        email: `e2e-noprf-sync-${Date.now()}@example.com`,
        name: 'No-PRF Sync E2E',
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
