import { test, expect, type TestInfo } from '@playwright/test';
const utils = require('../global-utils');

utils.loadEnv();

var proc;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    proc = await utils.startVaultwarden(browser, testInfo, {});
});

test.afterAll('Teardown', async ({}, testInfo: TestInfo) => {
    utils.stopVaultwarden(proc, testInfo);
});

test('Account creation', async ({ page }) => {
    // Landing page
    await page.goto('/');
    await page.getByRole('link', { name: 'Create account' }).click();

    // Back to Vault create account
    await expect(page).toHaveTitle(/Create account | Vaultwarden Web/);
    await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
    await page.getByLabel('Name').fill(process.env.TEST_USER);
    await page.getByLabel('Master password\n   (required)', { exact: true }).fill('Master password');
    await page.getByLabel('Re-type master password').fill('Master password');
    await page.getByRole('button', { name: 'Create account' }).click();

    // Back to the login page
    await expect(page).toHaveTitle('Vaultwarden Web');
    await page.getByLabel('Your new account has been created')
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill('Master password');
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);
});

test('Master password login', async ({ page }) => {
    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill('Master password');
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);
});
