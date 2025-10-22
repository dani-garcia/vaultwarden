import { expect, type Page, Test } from '@playwright/test';
import { type MailBuffer, MailServer } from 'maildev';
import * as OTPAuth from "otpauth";

import * as utils from '../../global-utils';
import { retrieveEmailCode } from './2fa';

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
            await expect(page.getByRole('heading', { name: 'Join organisation' })).toBeVisible();
            await page.getByLabel('Master password (required)', { exact: true }).fill(user.password);
            await page.getByLabel('Confirm master password (').fill(user.password);
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
        mailBuffer ?: MailBuffer,
        totp?: OTPAuth.TOTP,
        mail2fa?: boolean,
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
            await page.getByLabel('Password', { exact: true }).fill(user.password);
            await page.getByRole('button', { name: 'Sign In' }).click();
        });

        if( options.totp || options.mail2fa ){
            let code;

            await test.step('2FA check', async () => {
                await expect(page.getByRole('heading', { name: 'Verify your Identity' })).toBeVisible();

                if( options.totp ) {
                    const totp = options.totp;
                    let timestamp = Date.now(); // Needed to use the next token
                    timestamp = timestamp + (totp.period - (Math.floor(timestamp / 1000) % totp.period) + 1) * 1000;
                    code = totp.generate({timestamp});
                } else if( options.mail2fa ){
                    code = await retrieveEmailCode(test, page, mailBuffer);
                }

                await page.getByLabel(/Verification code/).fill(code);
                await page.getByRole('button', { name: 'Continue' }).click();
            });
        }

        await test.step('Unlock vault', async () => {
            await expect(page).toHaveTitle('Vaultwarden Web');
            await expect(page.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible();
            await page.getByLabel('Master password').fill(user.password);
            await page.getByRole('button', { name: 'Unlock' }).click();
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
