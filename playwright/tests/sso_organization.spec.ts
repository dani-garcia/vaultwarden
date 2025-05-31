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
