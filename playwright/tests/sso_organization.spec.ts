import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import { logNewUser, logUser } from './setups/sso';

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVaultwarden(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: true,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVaultwarden();
});

test('Create user3', async ({ page }) => {
    await logNewUser(test, page, users.user3);
});

test('Invite users', async ({ page }) => {
    await logNewUser(test, page, users.user1);

    await test.step('Create Org', async () => {
        await page.getByRole('link', { name: 'New organisation' }).click();
        await page.getByLabel('Organisation name (required)').fill('Test');
        await page.getByRole('button', { name: 'Submit' }).click();
        await page.locator('div').filter({ hasText: 'Members' }).nth(2).click();
    });

    await test.step('Invite user2', async () => {
        await page.getByRole('button', { name: 'Invite member' }).click();
        await page.getByLabel('Email (required)').fill(users.user2.email);
        await page.getByRole('tab', { name: 'Collections' }).click();
        await page.getByLabel('Permission').selectOption('edit');
        await page.getByLabel('Select collections').click();
        await page.getByLabel('Options list').getByText('Default collection').click();
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText('User(s) invited');
        await page.locator('#toast-container').getByRole('button').click();
        await expect(page.getByRole('row', { name: users.user2.email })).toHaveText(/Invited/);
    });

    await test.step('Invite user3', async () => {
        await page.getByRole('button', { name: 'Invite member' }).click();
        await page.getByLabel('Email (required)').fill(users.user3.email);
        await page.getByRole('tab', { name: 'Collections' }).click();
        await page.getByLabel('Permission').selectOption('edit');
        await page.getByLabel('Select collections').click();
        await page.getByLabel('Options list').getByText('Default collection').click();
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText('User(s) invited');
        await page.locator('#toast-container').getByRole('button').click();
        await expect(page.getByRole('row', { name: users.user3.name })).toHaveText(/Needs confirmation/);
    });

    await test.step('Confirm existing user3', async () => {
        await page.getByRole('row', { name: users.user3.name }).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Confirm' }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText(/confirmed/);
        await page.locator('#toast-container').getByRole('button').click();
    });
});

test('Create invited account', async ({ page }) => {
    await logNewUser(test, page, users.user2);
});

test('Confirm invited user', async ({ page }) => {
    await logUser(test, page, users.user1);
    await page.getByLabel('Switch products').click();
    await page.getByRole('link', { name: ' Admin Console' }).click();
    await page.getByRole('link', { name: 'Members' }).click();

    await expect(page.getByRole('row', { name: users.user2.name })).toHaveText(/Needs confirmation/);

    await test.step('Confirm user2', async () => {
        await page.getByRole('row', { name: users.user2.name }).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Confirm' }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText(/confirmed/);
        await page.locator('#toast-container').getByRole('button').click();
    });
});

test('Organization is visible', async ({ page }) => {
    await logUser(test, page, users.user2);
    await page.getByLabel('vault: Test').click();
    await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
});
