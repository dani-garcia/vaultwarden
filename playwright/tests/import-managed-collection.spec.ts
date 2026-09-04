import { test, expect, type TestInfo } from '@playwright/test';

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

test('A member with Manage permission on a collection can import into it under the ownership policy', async ({ page }) => {
    test.setTimeout(300_000);

    // The member account has to exist before being invited (no SMTP configured for this suite).
    await createAccount(test, page, users.user2);
    await createAccount(test, page, users.user1);

    await orgs.create(test, page, 'ImportOrg');

    await test.step('Create a managed and a locked collection', async () => {
        await page.getByRole('button', { name: 'New', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Collection' }).click();
        await page.getByRole('textbox', { name: 'Name * (required)', exact: true }).fill('Managed');
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Created collection Managed');

        await page.getByRole('button', { name: 'New', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Collection' }).click();
        await page.getByRole('textbox', { name: 'Name * (required)', exact: true }).fill('Locked');
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Created collection Locked');
    });

    await test.step('Enable the organisation ownership policy', async () => {
        await orgs.policies(test, page, 'ImportOrg');
        await page.getByRole('button', { name: /^Centralise organisation ownership/ }).click();
        await page.getByRole('checkbox', { name: 'Turn on' }).check();
        await page.getByRole('button', { name: 'Save' }).click();
    });

    await orgs.members(test, page, 'ImportOrg');
    await test.step(`Invite ${users.user2.email} with Manage collection on Managed only`, async () => {
        await page.getByRole('button', { name: 'Invite member' }).click();
        await page.getByRole('textbox', { name: 'Email * (required)', exact: true }).fill(users.user2.email);
        await page.getByRole('tab', { name: 'Collections' }).click();
        await page.getByRole('combobox', { name: 'Permission' }).click();
        await page.getByRole('option', { name: 'Manage collection', exact: true }).click();
        await page.getByRole('combobox', { name: 'Select collections' }).click();
        await page.getByLabel('Options List').getByText('Managed', { exact: true }).click();
        await page.getByRole('columnheader', { name: 'Collection', exact: true }).click();
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'User(s) invited');
    });

    await orgs.confirm(test, page, 'ImportOrg', users.user2.email);

    await logUser(test, page, users.user2);

    await test.step('The import destination and file fields are enabled for the managed collection', async () => {
        await page.goto('/#/tools/import');

        const vaultSelect = page.getByRole('combobox', { name: /^Vault/ });
        await expect(vaultSelect).toBeEnabled();
        // The member has exactly one org they can manage a collection in, so it's preselected
        // instead of "My vault".
        await expect(page.getByText('ImportOrg', { exact: true })).toBeVisible();

        const collectionSelect = page.getByRole('combobox', { name: 'Collection' });
        await expect(collectionSelect).toBeEnabled();

        await expect(page.getByRole('combobox', { name: /^File format/ })).toBeEnabled();
        await expect(page.getByRole('textbox', { name: /or copy\/paste the import file contents/ })).toBeEnabled();
    });
});
