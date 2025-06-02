import { test, expect, type Page, type TestInfo } from '@playwright/test';
import * as OTPAuth from "otpauth";

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';
import { activateTOTP, disableTOTP } from './setups/2fa';

let users = utils.loadEnv();
let totp;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {});
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Account creation', async ({ page }) => {
    await createAccount(test, page, users.user1);
});

test('Master password login', async ({ page }) => {
    await logUser(test, page, users.user1);
});

test('Authenticator 2fa', async ({ page }) => {
    await logUser(test, page, users.user1);

    let totp = await activateTOTP(test, page, users.user1);

    await utils.logout(test, page, users.user1);

    await test.step('login', async () => {
        let timestamp = Date.now(); // Needed to use the next token
        timestamp = timestamp + (totp.period - (Math.floor(timestamp / 1000) % totp.period) + 1) * 1000;

        await page.getByLabel(/Email address/).fill(users.user1.email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByLabel('Master password').fill(users.user1.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        await expect(page.getByRole('heading', { name: 'Verify your Identity' })).toBeVisible();
        await page.getByLabel(/Verification code/).fill(totp.generate({timestamp}));
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page).toHaveTitle(/Vaultwarden Web/);
    });

    await disableTOTP(test, page, users.user1);
});
