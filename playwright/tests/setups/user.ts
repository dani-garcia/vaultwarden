import { expect, type Browser, Page } from '@playwright/test';

import { type MailBuffer } from 'maildev';

import * as utils from '../../global-utils';
import { retrieveEmailCode } from './2fa';

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
        await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(user.password);
        await page.getByRole('textbox', { name: 'Confirm master password * (' }).fill(user.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        await utils.checkNotification(page, 'Your new account has been created')

        // We are now in the default vault page
        await expect(page).toHaveTitle('Vaults | Vaultwarden Web');
        // await utils.checkNotification(page, 'You have been logged in!');

        if( mailBuffer ){
            await mailBuffer.expect((m) => m.subject === "Welcome");
            await mailBuffer.expect((m) => m.subject === "New Device Logged In From Firefox");
        }
    });
}

export async function logUser(
    test,
    page: Page,
    user: { email: string, password: string },
    options: {
        mailBuffer ?: MailBuffer,
        mail2fa?: boolean,
        notNewDevice?: boolean,
    } = {}
) {
    await test.step(`Log user ${user.email}`, async () => {
        await utils.cleanLanding(page);

        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(user.password);
        await page.getByRole('button', { name: 'Log in', exact: true }).click();

        if( options.mail2fa ){
            await test.step('2FA check', async () => {
                await expect(page.getByRole('heading', { name: 'Verify your Identity' })).toBeVisible();
                let code = await retrieveEmailCode(test, page, options.mailBuffer);
                await page.getByLabel(/Verification code/).fill(code);
                await page.getByRole('button', { name: 'Continue' }).click();
            });
        }

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaultwarden Web/);

        if( options.mailBuffer && !options.notNewDevice ){
            await options.mailBuffer.expect((m) => m.subject === "New Device Logged In From Firefox");
        }
    });
}
