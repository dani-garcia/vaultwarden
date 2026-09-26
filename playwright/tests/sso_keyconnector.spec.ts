import { test, expect, type Page, type TestInfo } from '@playwright/test';

import { startMockKeyConnector } from './setups/keyconnector';
import * as utils from "../global-utils";

let users = utils.loadEnv();
let keyConnector;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    keyConnector = startMockKeyConnector(Number(process.env.KEY_CONNECTOR_PORT));
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: false,
        KEY_CONNECTOR_ENABLED: true,
        KEY_CONNECTOR_URL: process.env.KEY_CONNECTOR_URL,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    keyConnector.stop();
});

async function ssoLogin(page: Page, user: { email: string, name: string, password: string }) {
    await page.context().clearCookies();
    await utils.cleanLanding(page);

    await page.locator("input[type=email].vw-email-sso").fill(user.email);
    await page.getByRole('button', { name: /Use single sign-on/ }).click();

    await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
    await page.getByLabel(/Username/).fill(user.name);
    await page.getByLabel('Password', { exact: true }).fill(user.password);
    await page.getByRole('button', { name: 'Sign In' }).click();
}

test('Account creation using SSO enrolls with the key connector', async ({ page }) => {
    await ssoLogin(page, users.user1);

    // Instead of the master password creation we land on the domain confirmation
    await expect(page.getByText(process.env.KEY_CONNECTOR_URL)).toBeVisible();
    // Button label differs between web-vault versions
    await page.getByRole('button', { name: /^(Confirm|Continue with log in)$/ }).click();

    await utils.ignoreExtension(page);

    await expect(page).toHaveTitle(/Vaultwarden Web/);
    await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();

    expect(keyConnector.keys.size).toBe(1);
});

test('SSO login unlocks with the key from the connector', async ({ page }) => {
    await ssoLogin(page, users.user1);

    // No master password prompt, the vault opens directly
    await utils.ignoreExtension(page);

    await expect(page).toHaveTitle(/Vaultwarden Web/);
    await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
});
