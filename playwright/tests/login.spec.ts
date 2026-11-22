import { test, expect, type Page, type TestInfo } from '@playwright/test';
import * as OTPAuth from "otpauth";

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';
import { activateTOTP, disableTOTP, recoveryCodes } from './setups/2fa';

let users = utils.loadEnv();
let totp;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {});
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Account creation', async ({ page }) => {
    await createAccount(test, page, users.user1);
});

test('Master password login', async ({ page }) => {
    await logUser(test, page, users.user1);
});

test('Authenticator 2fa', async ({ page }) => {
    await logUser(test, page, users.user1);

    let totp = await activateTOTP(test, page, users.user1);

    await utils.logout(test, page, users.user1);

    await logUser(test, page, users.user1, { totp });

    await disableTOTP(test, page, users.user1);
});

test('Recovery codes', async ({ context, page }) => {
    await logUser(test, page, users.user1);

    await activateTOTP(test, page, users.user1);
    let recovery = await recoveryCodes(test, page, users.user1);

    await utils.logout(test, page, users.user1);

    await test.step('login', async () => {
        await page.getByLabel(/Email address/).fill(users.user1.email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(users.user1.password);
        await page.getByRole('button', { name: 'Log in', exact: true }).click();

        await expect(page.getByRole('heading', { name: 'Verify your Identity' })).toBeVisible();

        await expect(page).toHaveTitle(/Vaultwarden Web/);

        const newPagePromise = context.waitForEvent('page');
        await page.getByRole('button', { name: 'Use your recovery code' }).click();
        const newPage = await newPagePromise;

        const tabs = context.pages();
        await tabs[1].bringToFront();
        await expect(tabs[1].getByRole('heading', { name: 'Recover account two-step login' })).toBeVisible();
        await tabs[1].getByRole('textbox', { name: 'Email address * (required)' }).fill(users.user1.email);
        await tabs[1].getByRole('textbox', { name: 'Master password * (required)' }).fill(users.user1.password);
        await tabs[1].getByRole('textbox', { name: 'Recovery code * (required)' }).fill(recovery);
        await tabs[1].getByRole('button', { name: 'Submit' }).click();

        await expect(tabs[1]).toHaveTitle(/Two-step login/);
    });
});

