import { expect, type Page, Test } from '@playwright/test';
import { type MailBuffer, MailServer } from 'maildev';

import * as utils from '../../global-utils';
import { submitTwoFactor, type TwoFactor } from './2fa';
import { fillNewMasterPassword } from './user';

/**
 * If a MailBuffer is passed it will be used and consume the expected emails
 */
export async function logNewUser(
    test: Test,
    page: Page,
    user: { email: string, name: string, password: string },
    options: { mailBuffer?: MailBuffer } = {}
) {
    await test.step(`Create user ${user.name}`, async () => {
        await page.context().clearCookies();

        await test.step('Landing page', async () => {
            await utils.cleanLanding(page);

            await page.locator("input[type=email].vw-email-sso").fill(user.email);
            await page.getByRole('button', { name: /Use single sign-on/ }).click();
        });

        await test.step('Keycloak login', async () => {
            await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
            await page.getByLabel(/Username/).fill(user.name);
            await page.getByLabel('Password', { exact: true }).fill(user.password);
            await page.getByRole('button', { name: 'Sign In' }).click();
        });

        await test.step('Create Vault account', async () => {
            // Heading spelling tracks the active locale: `en` ("organization")
            // vs. `en_GB` ("organisation"). Both project variants use this
            // helper, so accept either.
            await expect(page.getByRole('heading', { name: /Join organi[sz]ation/ })).toBeVisible();
            await fillNewMasterPassword(page, user.password);
            await page.getByRole('button', { name: 'Create account' }).click();
        });

        await utils.checkNotification(page, 'Account successfully created!');
        await utils.checkNotification(page, 'Invitation accepted');

        await utils.ignoreExtension(page);

        await test.step('Default vault page', async () => {
            await expect(page).toHaveTitle(/Vaultwarden Web/);
            await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
        });

        if( options.mailBuffer ){
            let mailBuffer = options.mailBuffer;
            await test.step('Check emails', async () => {
                await mailBuffer.expect((m) => m.subject === "Welcome");
                await mailBuffer.expect((m) => m.subject.includes("New Device Logged"));
            });
        }
    });
}

/**
 * If a MailBuffer is passed it will be used and consume the expected emails
 */
export async function logUser(
    test: Test,
    page: Page,
    user: { email: string, password: string },
    options: {
        mailBuffer?: MailBuffer,
        twoFactor?: TwoFactor,
        // Override for the Keycloak password when the vault MP and the
        // SSO-provider credential have diverged (e.g. after a master-
        // password rotation in vw, where Keycloak's stored credential
        // is unaffected). Defaults to `user.password` — the common case.
        kcPassword?: string,
    } = {}
) {
    let mailBuffer = options.mailBuffer;

    await test.step(`Log user ${user.email}`, async () => {
        await page.context().clearCookies();

        await test.step('Landing page', async () => {
            await utils.cleanLanding(page);

            await page.locator("input[type=email].vw-email-sso").fill(user.email);
            await page.getByRole('button', { name: /Use single sign-on/ }).click();
        });

        await test.step('Keycloak login', async () => {
            await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
            await page.getByLabel(/Username/).fill(user.name);
            await page.getByLabel('Password', { exact: true }).fill(options.kcPassword ?? user.password);
            await page.getByRole('button', { name: 'Sign In' }).click();
        });

        if( options.twoFactor ){
            await submitTwoFactor(test, page, options.twoFactor);
        }

        await test.step('Unlock vault', async () => {
            // After SSO + (optional) 2FA, the bundled web vault routes to
            // `/#/lock?promptBiometric=true`. When a PRF passkey is
            // enrolled and the user's authenticator can satisfy the
            // assertion, the lock screen auto-fires
            // `navigator.credentials.get()` on mount and the SPA unwraps
            // the user key without manual interaction — the page lands on
            // /#/vault directly. If no PRF credential is available (or it
            // can't satisfy UV), the lock screen waits for MP. Accept
            // either landing so this helper works for both shapes; the
            // Default-vault-page step below pins the final state either way.
            await page.waitForURL(/#\/(lock|vault|setup-extension)\b/, { timeout: 30_000 });
            if (page.url().includes('#/lock')) {
                await expect(page).toHaveTitle('Vaultwarden Web');
                await expect(page.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible();
                await page.getByLabel('Master password').fill(user.password);
                // `exact: true` because the lock screen surfaces an additional
                // "Unlock with passkey" button when the user has a PRF-capable
                // credential enrolled; a substring "Unlock" match would resolve
                // to two elements and Playwright's strict mode would throw.
                await page.getByRole('button', { name: 'Unlock', exact: true }).click();
            }
        });

        await utils.ignoreExtension(page);

        await test.step('Default vault page', async () => {
            await expect(page).toHaveTitle(/Vaultwarden Web/);
            await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
        });

        if( mailBuffer ){
            await test.step('Check email', async () => {
                await mailBuffer.expect((m) => m.subject.includes("New Device Logged"));
            });
        }
    });
}
