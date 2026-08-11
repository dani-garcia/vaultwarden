import { test, expect, type TestInfo } from '@playwright/test';

import * as utils from "../global-utils";

import * as orgs from './setups/orgs';
import { createAccount } from './setups/user';

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Create', async ({ page }) => {
    await createAccount(test, page, users.user1);

    await orgs.create(test, page, 'New organisation');

    await test.step('Create Collection', async () => {
        await page.getByRole('button', { name: 'New', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Collection' }).click();
        await page.getByRole('textbox', { name: 'Name * (required)', exact: true }).fill('RandomCollec');
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Created collection RandomCollec');
        await expect(page.getByRole('button', { name: 'RandomCollec' })).toBeVisible();
    });
});
