import { test, expect, type Page, type TestInfo } from '@playwright/test';
import * as OTPAuth from "otpauth";

import * as utils from "../global-utils";
import { createAccount } from './setups/user';

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {});
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Send', async ({ browser, page }) => {
    await createAccount(test, page, users.user1);

    const send_url = await test.step('Create', async () => {
        await page.getByRole('link', { name: 'Send' }).click();
        await expect(page.locator('#main-content').getByText('Send', { exact: true })).toBeVisible();

        await page.getByRole('button', { name: 'New', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Text' }).click();

        await page.getByRole('textbox', { name: 'Send name (required)' }).fill('Test');
        await page.getByRole('textbox', { name: 'Text to share (required)' }).fill('test');
        await page.getByRole('button', { name: 'Save' }).click();

        await page.locator('footer').getByRole('button', { name: 'Copy link' }).click();

        return await page.evaluate(() => navigator.clipboard.readText());
    });

    const context2 = await browser.newContext();
    const page2 = await context2.newPage();

    await test.step('View', async () => {
        await page2.goto(send_url, { waitUntil: 'domcontentloaded' });
        await expect(page2.getByRole('heading', { name: 'View Send' })).toBeVisible();
        await expect(await page2.getByRole('paragraph').filter({ hasText: 'Test' })).toBeVisible();
    });

    const pwd_url = await test.step('Create with password', async () => {
        await page.getByRole('link', { name: 'Send' }).click();
        await expect(page.locator('#main-content').getByText('Send', { exact: true })).toBeVisible();

        await page.getByRole('button', { name: 'New', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Text' }).click();

        await page.getByRole('textbox', { name: 'Send name (required)' }).fill('Password');
        await page.getByRole('textbox', { name: 'Text to share (required)' }).fill('password');
        await page.getByRole('combobox', { name: 'Who can view' }).click();
        await page.getByText('Anyone with a password set by you').click();
        await page.getByRole('textbox', { name: 'Password (required)' }).fill('password');

        await page.getByRole('button', { name: 'Save' }).click();
        await page.locator('footer').getByRole('button', { name: 'Copy link' }).click();

        return await page.evaluate(() => navigator.clipboard.readText());
    });

    await test.step('View with password', async () => {
        await page2.goto(pwd_url, { waitUntil: 'domcontentloaded' });
        await expect(page2.getByRole('heading', { name: 'Enter the password to view' })).toBeVisible();
        await page2.getByRole('textbox', { name: 'Password (required)' }).fill('password');
        await page2.getByRole('button', { name: 'Continue' }).click();
        await expect(page2.getByRole('heading', { name: 'View Send' })).toBeVisible();
        await expect(await page2.getByRole('paragraph').filter({ hasText: 'Password' })).toBeVisible();
    });
});
