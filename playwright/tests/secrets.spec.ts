import { test, expect, type Page, type TestInfo } from '@playwright/test';
import * as OTPAuth from "otpauth";

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();
let totp;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {});

    const context = await browser.newContext();
    const page = await context.newPage();
    await createAccount(test, page, users.user1);
    await context.close();
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Password', async ({ context, page }, testInfo: TestInfo) => {
    const label = 'Test Password';

    await logUser(test, page, users.user1);

    await test.step('Create password entry', async () => {
        await page.getByRole('button', { name: 'New item' }).click();
        await page.getByRole('textbox', { name: 'Item name * (required)' }).fill(label);
        await page.getByRole('textbox', { name: 'Username' }).fill(users.user1.name);
        await page.getByRole('textbox', { name: 'Password' }).fill(users.user1.password);
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Item added');
        await page.getByRole('button', { name: 'Close' }).click();
    });

    // Log again
    await logUser(test, page, users.user1);

    await test.step('Check', async () => {
        await page.getByRole('row').filter({ hasText: label }).getByRole('button', { name: label }).click();
        await page.getByTestId('copy-username').click();
        await utils.checkNotification(page, 'Username copied');
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(users.user1.name)
        await page.getByTestId('copy-password').click();
        await utils.checkNotification(page, 'Password copied');
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(users.user1.password)
        await page.getByRole('button', { name: 'Close' }).click();
    });

    await test.step('Delete', async () => {
        await page.getByRole('row').filter({ hasText: label }).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Delete' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();
        await utils.checkNotification(page, 'Item sent to bin');
    });

    // Log again
    await logUser(test, page, users.user1);

    await test.step('Deleted', async () => {
        await expect(page.getByRole('row').filter({ hasText: label })).toHaveCount(0)
    });
});


test('SSH Key', async ({ context, page }, testInfo: TestInfo) => {
    const label = 'Test SSH key';

    await logUser(test, page, users.user1);

    const privateKey = await test.step('Create key entry', async () => {
        await page.getByRole('button', { name: 'New', exact: true }).click();
        await page.getByRole('menuitem', { name: 'SSH key' }).click();
        await page.getByRole('textbox', { name: 'Item name * (required)' }).fill('Test SSH key');
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'Item added');

        await page.getByRole('button', { name: 'Copy private key' }).click();
        await utils.checkNotification(page, 'Private key copied');
        return await page.evaluate(() => navigator.clipboard.readText());
    });

    // Log again
    await logUser(test, page, users.user1);

    await test.step('Check', async () => {
        await page.getByRole('row').filter({ hasText: label }).getByRole('button', { name: label }).click();

        await page.getByRole('button', { name: 'Copy private key' }).click();
        await utils.checkNotification(page, 'Private key copied');
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(privateKey)
        await page.getByRole('button', { name: 'Close' }).click();
    });

    await test.step('Delete', async () => {
        await page.getByRole('row').filter({ hasText: label }).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Delete' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();
        await utils.checkNotification(page, 'Item sent to bin');
    });

    // Log again
    await logUser(test, page, users.user1);

    await test.step('Deleted', async () => {
        await expect(page.getByRole('row').filter({ hasText: label })).toHaveCount(0)
    })
});
