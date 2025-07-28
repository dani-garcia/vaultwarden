import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import * as orgs from './setups/orgs';
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Invite', async ({ page }) => {
    await createAccount(test, page, users.user3);
    await createAccount(test, page, users.user1);

    await orgs.create(test, page, 'New organisation');
    await orgs.members(test, page, 'New organisation');

    await test.step('missing user2', async () => {
        await orgs.invite(test, page, 'New organisation', users.user2.email);
        await expect(page.getByRole('row', { name: users.user2.email })).toHaveText(/Invited/);
    });

    await test.step('existing user3', async () => {
        await orgs.invite(test, page, 'New organisation', users.user3.email);
        await expect(page.getByRole('row', { name: users.user3.email })).toHaveText(/Needs confirmation/);
        await orgs.confirm(test, page, 'New organisation', users.user3.email);
    });

    await test.step('confirm user2', async () => {
        await createAccount(test, page, users.user2);
        await logUser(test, page, users.user1);
        await orgs.members(test, page, 'New organisation');
        await orgs.confirm(test, page, 'New organisation', users.user2.email);
    });

    await test.step('Org visible user2  ', async () => {
        await logUser(test, page, users.user2);
        await page.getByRole('button', { name: 'vault: New organisation', exact: true }).click();
        await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
    });

    await test.step('Org visible user3  ', async () => {
        await logUser(test, page, users.user3);
        await page.getByRole('button', { name: 'vault: New organisation', exact: true }).click();
        await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
    });
});
