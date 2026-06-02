import { expect, type Page, Test } from '@playwright/test';
import { type MailBuffer } from 'maildev';
import * as OTPAuth from "otpauth";

import * as utils from '../../global-utils';
import { openAvatarMenu, submitMasterPasswordVerification } from './user';

/**
 * A 2FA challenge factor used by the login helpers. Discriminated by `kind`
 * so each variant carries only the state it needs:
 *   - `totp`     — TOTP code generator (authenticator app)
 *   - `mail2fa`  — email OTP; the helper retrieves the code from `mailBuffer`
 *   - `fido2`    — WebAuthn-as-2FA (the bundled web vault labels this
 *                  provider "FIDO2 WebAuthn" in en_GB / "Passkey" in en).
 *                  Currently unimplemented; `submitTwoFactor` throws.
 */
export type TwoFactor =
    | { kind: 'totp', totp: OTPAuth.TOTP }
    | { kind: 'mail2fa', mailBuffer: MailBuffer }
    | { kind: 'fido2' };

/** Provider-row label inside the "Select another method" picker dialog
 *  for each `TwoFactor.kind` — matches what the bundled web vault renders
 *  alongside the enrolled provider in the dialog list. */
const PICKER_LABEL: Record<TwoFactor['kind'], RegExp> = {
    totp: /Authenticator app/i,
    mail2fa: /Email/i,
    fido2: /Passkey|FIDO2/i,
};

/** If the page isn't already showing the input for the requested 2FA
 *  kind (i.e. some other provider is the default), click "Select another
 *  method" → the target provider row. No-op when the requested kind's
 *  input is already visible (single-provider case, or it was already the
 *  default). */
async function ensure2FAProvider(page: Page, kind: TwoFactor['kind']) {
    const probe = kind === 'fido2'
        ? page.locator('iframe[src*="webauthn-connector"]')
        : page.getByLabel(/Verification code/);
    // Give the bundled web vault a few seconds to mount the default
    // provider's input before deciding a picker switch is needed. The
    // webauthn-connector iframe in particular can take a moment longer
    // to attach under SSO mode (extra Keycloak round-trip means the
    // `/#/2fa` mount happens after a navigation chain) and a too-short
    // probe would race into the switcher path, which can collide with
    // the connector's auto-fire when the default is already FIDO2.
    if (await probe.first().isVisible({ timeout: 5_000 }).catch(() => false)) {
        return;
    }
    const switcherText = /Select another method|Need a different method/i;
    const switcher = page
        .getByRole('button', { name: switcherText })
        .or(page.getByRole('link', { name: switcherText }))
        .or(page.getByText(switcherText));
    await switcher.first().waitFor({ state: 'visible', timeout: 10_000 });
    await switcher.first().click();
    const target = page
        .getByRole('button', { name: PICKER_LABEL[kind] })
        .or(page.getByRole('link', { name: PICKER_LABEL[kind] }));
    await target.first().click();
}

/**
 * Satisfy the /#/2fa challenge for the given `TwoFactor`. Asserts the
 * "Verify your Identity" heading is shown, then dispatches per `kind`:
 *  - `totp` / `mail2fa`: fill the verification code, click Continue.
 *  - `fido2`: the bundled connector iframe auto-fires WebAuthn on mount and
 *            the page navigates to /vault on its own; the helper just waits
 *            for that transition (caller must have a virtual authenticator
 *            attached with auto-presence enabled).
 *
 * For TOTP, the code is generated for the *next* period boundary to avoid
 * server-side expiry races when the test submits near a 30-second tick.
 * The helper also remembers the last-used time-step (module-scoped) and
 * waits for the next period boundary if a repeat submission would land
 * on a time-step the server has already consumed — its `last_used`
 * tracking rejects equal-or-earlier time-steps even when the code is
 * arithmetically valid.
 */
let lastSubmittedTotpTimeStep: number | null = null;

/**
 * Drop the module-scoped `last_used` cache. With `workers: 1` the variable
 * persists across every spec in a single Playwright invocation, so when
 * project A's lifecycle test consumes a time-step and project B then runs
 * its first TOTP (different DB, different secret, different time-step) the
 * stale value would force a 30s sleep before the otherwise-fresh code. Call
 * this from a `test.beforeEach` in any spec that submits TOTP.
 */
export function resetTotpTimeStep() {
    lastSubmittedTotpTimeStep = null;
}

export async function submitTwoFactor(test: Test, page: Page, twoFactor: TwoFactor): Promise<void> {
    await test.step(`Submit 2FA (${twoFactor.kind})`, async () => {
        await expect(page.getByRole('heading', { name: 'Verify your Identity' })).toBeVisible();
        await ensure2FAProvider(page, twoFactor.kind);
        switch (twoFactor.kind) {
            case 'totp': {
                const { totp } = twoFactor;
                let nowSec = Math.floor(Date.now() / 1000);
                let timestamp = (nowSec + totp.period - (nowSec % totp.period) + 1) * 1000;
                let timeStep = Math.floor(timestamp / 1000 / totp.period);
                if (lastSubmittedTotpTimeStep !== null && timeStep <= lastSubmittedTotpTimeStep) {
                    // Server's `last_used` would reject this code — sleep
                    // until the next period boundary and recompute.
                    const waitMs = (totp.period - (nowSec % totp.period) + 1) * 1000;
                    await page.waitForTimeout(waitMs);
                    nowSec = Math.floor(Date.now() / 1000);
                    timestamp = (nowSec + totp.period - (nowSec % totp.period) + 1) * 1000;
                    timeStep = Math.floor(timestamp / 1000 / totp.period);
                }
                lastSubmittedTotpTimeStep = timeStep;
                await page.getByLabel(/Verification code/).fill(totp.generate({ timestamp }));
                await page.getByRole('button', { name: 'Continue' }).click();
                break;
            }
            case 'mail2fa': {
                const code = await retrieveEmailCode(test, page, twoFactor.mailBuffer);
                await page.getByLabel(/Verification code/).fill(code);
                await page.getByRole('button', { name: 'Continue' }).click();
                break;
            }
            case 'fido2':
                break;
        }
        // MP login + 2FA lands the user in /vault directly (MP unwrapped the
        // user key at login). SSO + 2FA lands on /#/lock — the IdP doesn't
        // carry the unwrap secret, so the SPA routes to the lock screen
        // for MP/passkey unlock. Accept both so callers in either mode can
        // pin their own post-2FA assertion.
        await expect(page).toHaveURL(/#\/(vault|setup-extension|lock)\b/, { timeout: 30_000 });
    });
}

/**
 * Navigate to the two-step-login provider list under Settings → Security.
 * Centralised here so a future web-vault nav restructure only touches one
 * call chain.
 */
export async function gotoTwoStepLogin(page: Page, userName: string) {
    await openAvatarMenu(page, userName);
    await page.getByRole('menuitem', { name: 'Account settings' }).click();
    await page.getByRole('link', { name: 'Security' }).click();
    await page.getByRole('link', { name: 'Two-step login' }).click();
}

/**
 * Click the "Manage" button on a 2FA provider row identified by a substring
 * of its label (e.g. /Authenticator app/, /Passkey/, 'Email'). The Manage
 * dialog typically opens with the user-verification gate as its first step.
 */
export async function clickTwoFactorProviderManage(page: Page, providerLabel: string | RegExp) {
    await page.locator('bit-item').filter({ hasText: providerLabel }).first().getByRole('button').first().click();
}

export async function activateTOTP(test: Test, page: Page, user: { name: string, password: string }): Promise<OTPAuth.TOTP> {
    return await test.step('Activate TOTP 2FA', async () => {
        await gotoTwoStepLogin(page, user.name);
        await clickTwoFactorProviderManage(page, /Authenticator app/);
        await submitMasterPasswordVerification(page, user.password);

        // `getByLabel('Key')` alone is ambiguous: the providers list also
        // has a Yubico SVG with aria-label "Yubico OTP security key" that
        // matches "Key" via substring. Anchor with exact match.
        const secret = (await page.getByLabel('Key', { exact: true }).innerText()).replace(/\s+/g, '');
        let totp = new OTPAuth.TOTP({ secret, period: 30 });

        await page.getByLabel(/Verification code/).fill(totp.generate());
        await page.getByRole('button', { name: 'Turn on' }).click();
        // Wait for the activation request to complete. The current
        // bundled web vault uses an asynchronous Turn-on flow; we don't
        // try to assert the exact success-heading text (it varies across
        // vault versions) — instead we wait for network to settle, then
        // the dialog closes itself.
        await page.waitForLoadState('networkidle');

        return totp;
    })
}

export async function disableTOTP(test: Test, page: Page, user: { name: string, password: string }) {
    await test.step('Disable TOTP 2FA', async () => {
        await gotoTwoStepLogin(page, user.name);
        await clickTwoFactorProviderManage(page, /Authenticator app/);
        await submitMasterPasswordVerification(page, user.password);
        await page.getByRole('button', { name: 'Turn off' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();
        await utils.checkNotification(page, 'Two-step login provider turned off');
    });
}

export async function activateEmail(test: Test, page: Page, user: { name: string, password: string }, mailBuffer: MailBuffer) {
    await test.step('Activate Email 2FA', async () => {
        await gotoTwoStepLogin(page, user.name);
        await clickTwoFactorProviderManage(page, 'Enter a code sent to your email');
        await submitMasterPasswordVerification(page, user.password);
        await page.getByRole('button', { name: 'Send email' }).click();
    });

    let code = await retrieveEmailCode(test, page, mailBuffer);

    await test.step('input code', async () => {
        await page.getByLabel('2. Enter the resulting 6').fill(code);
        await page.getByRole('button', { name: 'Turn on' }).click();
        await page.getByRole('heading', { name: 'Turned on', exact: true });
    });
}

export async function retrieveEmailCode(test: Test, page: Page, mailBuffer: MailBuffer): Promise<string> {
    return await test.step('retrieve code', async () => {
        const codeMail = await mailBuffer.expect((mail) => mail.subject.includes("Login Verification Code"));
        const page2 = await page.context().newPage();
        await page2.setContent(codeMail.html);
        const code = await page2.getByTestId("2fa").innerText();
        await page2.close();
        return code;
    });
}

export async function disableEmail(test: Test, page: Page, user: { name: string, password: string }) {
    await test.step('Disable Email 2FA', async () => {
        await gotoTwoStepLogin(page, user.name);
        await clickTwoFactorProviderManage(page, 'Email');
        await submitMasterPasswordVerification(page, user.password);
        await page.getByRole('button', { name: 'Turn off' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();

        await utils.checkNotification(page, 'Two-step login provider turned off');
    });
}
