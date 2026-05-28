import { expect, type Browser, Page } from '@playwright/test';

import { type MailBuffer } from 'maildev';

import * as utils from '../../global-utils';
import { submitTwoFactor, type TwoFactor } from './2fa';

/**
 * Open the account/avatar menu in the web vault header. The button's
 * accessible name is the user's display name; centralising the locator here
 * insulates callers from web-vault changes to that element's structure.
 *
 * Note: cipher rows also expose `aria-haspopup="menu"` ellipsis buttons, so
 * naïve `aria-haspopup` selectors mis-target on the vault page. Anchor on the
 * accessible-name (`{ exact: true }` to avoid substring matches against any
 * cipher whose name happens to start with the user's display name).
 */
export async function openAvatarMenu(page: Page, userName: string) {
    await page.getByRole('button', { name: userName, exact: true }).click();
}

/**
 * Fill the registration / change-master-password form's "new" + "confirm new"
 * master-password fields. Anchored by `formcontrolname` rather than label —
 * the current bundled web-vault renders three labels matching "Master
 * password" via Playwright's case-insensitive substring matching ("Master
 * password (required)", "Confirm master password (required)", and "Master
 * password hint"), so a label-based locator is ambiguous.
 */
export async function fillNewMasterPassword(page: Page, password: string) {
    await page.locator('input[formcontrolname="newPassword"]').fill(password);
    await page.locator('input[formcontrolname="newPasswordConfirm"]').fill(password);
}

/**
 * Submit the in-dialog user-verification (`app-user-verification`) master-
 * password gate that the bundled web vault renders before any sensitive
 * operation (2FA enrol/disable, passkey enrol/remove, key rotation, KDF
 * change).
 *
 * Pressing Enter inside the password input submits the form unambiguously —
 * the surrounding page often has multiple `Continue` buttons (dialog action,
 * stale settings header), so a button-text click is brittle.
 *
 * Note: the user-verification component falls back to email-OTP verification
 * when the master password isn't "fresh" in the current session (e.g. after a
 * passkey login). Callers reaching this helper from a post-passkey-login
 * state must arrange a recent MP entry first.
 */
export async function submitMasterPasswordVerification(page: Page, masterPassword: string) {
    const mpInput = page.locator('input#masterPassword');
    await mpInput.waitFor({ state: 'visible' });
    await mpInput.fill(masterPassword);
    await mpInput.press('Enter');
}

export async function createAccount(test, page: Page, user: { email: string, name: string, password: string }, mailBuffer?: MailBuffer) {
    await test.step(`Create user ${user.name}`, async () => {
        await utils.cleanLanding(page);

        await page.getByRole('link', { name: 'Create account' }).click();

        // Back to Vault create account
        await expect(page).toHaveTitle(/Create account | Vaultwarden Web/);
        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByLabel('Name').fill(user.name);
        await page.getByRole('button', { name: 'Continue' }).click();

        await fillNewMasterPassword(page, user.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        await utils.checkNotification(page, 'Your new account has been created')
        await utils.ignoreExtension(page);

        // We are now in the default vault page
        await expect(page).toHaveTitle('Vaults | Vaultwarden Web');
        // await utils.checkNotification(page, 'You have been logged in!');

        if( mailBuffer ){
            await mailBuffer.expect((m) => m.subject === "Welcome");
            await mailBuffer.expect((m) => m.subject === "New Device Logged In From Firefox");
        }
    });
}

/**
 * Master-password login.
 *
 * When the account has 2FA enabled, pass `options.twoFactor` — a
 * `TwoFactor` discriminated union carrying the factor's own state (TOTP
 * generator, mail buffer, …). The helper then drives the /#/2fa challenge
 * inline and lands the user in `/vault`. Mirrors `setups/sso.ts:logUser`.
 *
 * `options.mailBuffer` (independent of `twoFactor`) consumes the expected
 * "New Device Logged In" mail at the end of the flow, when the test wants
 * to assert that login emails went out.
 */
export async function logUser(
    test,
    page: Page,
    user: { email: string, password: string },
    options: {
        mailBuffer?: MailBuffer,
        twoFactor?: TwoFactor,
        // Accepted for option-shape parity with `./sso.ts#logUser`, which
        // uses it to support cases where the SSO-provider credential and
        // the vault MP have diverged. Ignored in the MP-only flow.
        kcPassword?: string,
    } = {},
) {
    let mailBuffer = options.mailBuffer;

    await test.step(`Log user ${user.email}`, async () => {
        await utils.cleanLanding(page);

        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByLabel('Master password').fill(user.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        if( options.twoFactor ){
            await submitTwoFactor(test, page, options.twoFactor);
        }

        await utils.ignoreExtension(page);

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaultwarden Web/);

        if( mailBuffer ){
            await mailBuffer.expect((m) => m.subject === "New Device Logged In From Firefox");
        }
    });
}
