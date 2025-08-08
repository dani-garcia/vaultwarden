import { expect, type Browser, Page } from '@playwright/test';

import { type MailBuffer } from 'maildev';

import * as utils from '../../global-utils';

export async function createAccount(test, page: Page, user: { email: string, name: string, password: string }, mailBuffer?: MailBuffer) {
    await test.step(`Create user ${user.name}`, async () => {
        await utils.cleanLanding(page);

        await page.getByRole('link', { name: 'Create account' }).click();

        // Back to Vault create account
        await expect(page).toHaveTitle(/Create account | Vaultwarden Web/);
        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByLabel('Name').fill(user.name);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Vault finish Creation
        await page.getByLabel('New master password (required)', { exact: true }).fill(user.password);
        await page.getByLabel('Confirm new master password (').fill(user.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        await utils.checkNotification(page, 'Your new account has been created')

        // We are now in the default vault page
        await expect(page).toHaveTitle('Vaults | Vaultwarden Web');
        await utils.checkNotification(page, 'You have been logged in!');

        if( mailBuffer ){
            await mailBuffer.expect((m) => m.subject === "Welcome");
            await mailBuffer.expect((m) => m.subject === "New Device Logged In From Firefox");
        }
    });
}

export async function logUser(test, page: Page, user: { email: string, password: string }, mailBuffer?: MailBuffer) {
    await test.step(`Log user ${user.email}`, async () => {
        await utils.cleanLanding(page);

        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByLabel('Master password').fill(user.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaultwarden Web/);

        if( mailBuffer ){
            await mailBuffer.expect((m) => m.subject === "New Device Logged In From Firefox");
        }
    });
}
