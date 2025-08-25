import { test, expect, type TestInfo } from '@playwright/test';

import { logNewUser, logUser } from './setups/sso';
import { activateTOTP, disableTOTP } from './setups/2fa';
import * as utils from "../global-utils";

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: false
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Account creation using SSO', async ({ page }) => {
    // Landing page
    await logNewUser(test, page, users.user1);
});

test('SSO login', async ({ page }) => {
    await logUser(test, page, users.user1);
});

test('Non SSO login', async ({ page }) => {
    // Landing page
    await page.goto('/');
    await page.locator("input[type=email].vw-email-sso").fill(users.user1.email);
    await page.getByRole('button', { name: 'Other' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user1.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaultwarden Web/);
});

test('SSO login with TOTP 2fa', async ({ page }) => {
    await logUser(test, page, users.user1);

    let totp = await activateTOTP(test, page, users.user1);

    await logUser(test, page, users.user1, { totp });

    await disableTOTP(test, page, users.user1);
});

test('Non SSO login impossible', async ({ page, browser }, testInfo: TestInfo) => {
    await utils.restartVault(page, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: true
    }, false);

    // Landing page
    await page.goto('/');

    // Check that SSO login is available
    await expect(page.getByRole('button', { name: /Use single sign-on/ })).toHaveCount(1);

    // No Continue/Other
    await expect(page.getByRole('button', { name: 'Other' })).toHaveCount(0);
});


test('No SSO login', async ({ page }, testInfo: TestInfo) => {
    await utils.restartVault(page, testInfo, {
        SSO_ENABLED: false
    }, false);

    // Landing page
    await page.goto('/');

    // No SSO button (rely on a correct selector checked in previous test)
    await expect(page.getByRole('button', { name: /Use single sign-on/ })).toHaveCount(0);

    // Can continue to Master password
    await page.getByLabel(/Email address/).fill(users.user1.email);
    await page.getByRole('button', { name: 'Continue' }).click();
    await expect(page.getByRole('button', { name: 'Log in with master password' })).toHaveCount(1);
});
