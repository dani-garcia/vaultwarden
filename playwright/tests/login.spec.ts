import { test, expect, type Page, type TestInfo } from '@playwright/test';
import * as OTPAuth from "otpauth";

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();
let totp;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVaultwarden(browser, testInfo, {});
});

test.afterAll('Teardown', async ({}, testInfo: TestInfo) => {
    utils.stopVaultwarden(testInfo);
});

test('Account creation', async ({ page }) => {
    // Landing page
    await createAccount(test, page, users.user1);

    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user1.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaultwarden Web/);
});

test('Master password login', async ({ page }) => {
    await logUser(test, page, users.user1);
});

test('Authenticator 2fa', async ({ context, page }) => {
    let totp;

    await test.step('Login', async () => {
        await logUser(test, page, users.user1);
    });

    await test.step('Activate', async () => {
        await page.getByRole('button', { name: users.user1.name }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('li').filter({ hasText: 'TOTP Authenticator' }).getByRole('button').click();
        await page.getByLabel('Master password (required)').fill(users.user1.password);
        await page.getByRole('button', { name: 'Continue' }).click();

        const secret = await page.getByLabel('Key').innerText();
        totp = new OTPAuth.TOTP({ secret, period: 30 });

        await page.getByLabel('Verification code (required)').fill(totp.generate());
        await page.getByRole('button', { name: 'Turn on' }).click();
        await page.getByRole('heading', { name: 'Turned on', exact: true });
        await page.getByLabel('Close').click();
    })

    await test.step('logout', async () => {
        await page.getByRole('button', { name: users.user1.name }).click();
        await page.getByRole('menuitem', { name: 'Log out' }).click();
    });

    await test.step('login', async () => {
        let timestamp = Date.now(); // Need to use the next token
        timestamp = timestamp + (totp.period - (Math.floor(timestamp / 1000) % totp.period) + 1) * 1000;

        await page.getByLabel(/Email address/).fill(users.user1.email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByLabel('Master password').fill(users.user1.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        await page.getByLabel('Verification code').fill(totp.generate({timestamp}));
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page).toHaveTitle(/Vaultwarden Web/);
    });

    await test.step('disable', async () => {
        await page.getByRole('button', { name: 'Test' }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('li').filter({ hasText: 'TOTP Authenticator' }).getByRole('button').click();
        await page.getByLabel('Master password (required)').click();
        await page.getByLabel('Master password (required)').fill(users.user1.password);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByRole('button', { name: 'Turn off' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText(/Two-step login provider turned off/);
    });
});
