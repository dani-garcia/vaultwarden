import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import * as orgs from './setups/orgs';
import { logNewUser, logUser } from './setups/sso';

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: true,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Create user3', async ({ page }) => {
    await logNewUser(test, page, users.user3);
});

test('Invite users', async ({ page }) => {
    await logNewUser(test, page, users.user1);

    await orgs.create(test, page, '/Test');
    await orgs.members(test, page, '/Test');
    await orgs.invite(test, page, '/Test', users.user2.email);
    await orgs.invite(test, page, '/Test', users.user3.email);
    await orgs.confirm(test, page, '/Test', users.user3.email);
});

test('Create invited account', async ({ page }) => {
    await logNewUser(test, page, users.user2);
});

test('Confirm invited user', async ({ page }) => {
    await logUser(test, page, users.user1);
    await orgs.members(test, page, '/Test');
    await expect(page.getByRole('row', { name: users.user2.name })).toHaveText(/Needs confirmation/);
    await orgs.confirm(test, page, '/Test', users.user2.email);
});

test('Organization is visible', async ({ page }) => {
    await logUser(test, page, users.user2);
    await page.getByLabel('vault: /Test').click();
    await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
});

test('Enforce password policy', async ({ page }) => {
    await logUser(test, page, users.user1);
    await orgs.policies(test, page, '/Test');

    await test.step(`Set master password policy`, async () => {
        await page.getByRole('button', { name: 'Master password requirements' }).click();
        await page.getByRole('checkbox', { name: 'Turn on' }).check();
        await page.getByRole('checkbox', { name: 'Require existing members to' }).check();
        await page.getByRole('spinbutton', { name: 'Minimum length' }).fill('42');
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Edited policy Master password requirements.');
    });

    await utils.logout(test, page, users.user1);

    await test.step(`Unlock trigger policy`, async () => {
        await page.getByRole('textbox', { name: 'Email address (required)' }).fill(users.user1.email);
        await page.getByRole('button', { name: 'Use single sign-on' }).click();

        await page.getByRole('textbox', { name: 'Master password (required)' }).fill(users.user1.password);
        await page.getByRole('button', { name: 'Unlock' }).click();

        await expect(page.getByRole('heading', { name: 'Update master password' })).toBeVisible();
    });
});
