import { test, expect, type Page, type TestInfo } from '@playwright/test';

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

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
    await expect(page).toHaveTitle(/Vaults/);
});

test('Master password login', async ({ page }) => {
    await logUser(test, page, users.user1);
});
