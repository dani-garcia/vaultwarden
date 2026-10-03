import { test, expect, type Page, type TestInfo } from '@playwright/test';
import * as OTPAuth from "otpauth";
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';
import { retrieveEmailCode } from './setups/2fa';

let users = utils.loadEnv();

let mailserver;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailserver = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailserver.listen();

    await utils.startVault(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
    });

    const context = await browser.newContext();
    const page = await context.newPage();
    await createAccount(test, page, users.user1);
    await context.close();
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    if( mailserver ){
        await mailserver.close();
    }
});

test('Send', async ({ browser, page }) => {
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();

    await logUser(test, page, users.user1);

    const send_url = await test.step('Create', async () => {
        await page.getByRole('link', { name: 'Send' }).click();
        await expect(page.locator('#main-content').getByText('Send', { exact: true })).toBeVisible();

        await page.getByRole('button', { name: 'New Send', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Text' }).click();

        await page.getByRole('textbox', { name: 'Send name * (required)' }).fill('Test');
        await page.getByRole('textbox', { name: 'Text to share * (required)' }).fill('test');
        await page.getByRole('button', { name: 'Save' }).click();

        await page.locator('footer').getByRole('button', { name: 'Copy link' }).click();

        return await page.evaluate(() => navigator.clipboard.readText());
    });

    await test.step('View', async () => {
        await page2.goto(send_url, { waitUntil: 'domcontentloaded' });
        await expect(page2.getByRole('heading', { name: 'View Send' })).toBeVisible();
        await expect(await page2.getByRole('paragraph').filter({ hasText: 'Test' })).toBeVisible();
    });

    await context2.close();
});

test('Password', async ({ browser, page }) => {
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();

    await logUser(test, page, users.user1);

    const pwd_url = await test.step('Create with password', async () => {
        await page.getByRole('link', { name: 'Send' }).click();
        await expect(page.locator('#main-content').getByText('Send', { exact: true })).toBeVisible();

        await page.getByRole('button', { name: 'New' }).click();
        await page.getByRole('menuitem', { name: 'Text' }).click();

        await page.getByRole('textbox', { name: 'Send name * (required)' }).fill('Password');
        await page.getByRole('textbox', { name: 'Text to share * (required)' }).fill('password');
        await page.getByRole('combobox', { name: 'Who can view' }).click();
        await page.getByText('Anyone with a password set by you').click();
        await page.getByRole('textbox', { name: 'Password * (required)', exact: true }).fill('password');

        await page.getByRole('button', { name: 'Save' }).click();
        await page.locator('footer').getByRole('button', { name: 'Copy link' }).click();

        return await page.evaluate(() => navigator.clipboard.readText());
    });

    await test.step('View with password', async () => {
        await page2.goto(pwd_url, { waitUntil: 'domcontentloaded' });
        await expect(page2.getByRole('heading', { name: 'Enter the password to view' })).toBeVisible();
        await page2.getByRole('textbox', { name: 'Password * (required)' }).fill('password');
        await page2.getByRole('button', { name: 'Continue' }).click();
        await expect(page2.getByRole('heading', { name: 'View Send' })).toBeVisible();
        await expect(await page2.getByRole('paragraph').filter({ hasText: 'Password' })).toBeVisible();
    });

    await context2.close();
});

test('Validation', async ({ browser, page }) => {
    const mailBuffer = mailserver.buffer(users.user2.email);
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();
    const pageMail = await context2.newPage();

    await logUser(test, page, users.user1);

    const mail_url = await test.step('Create with email validation', async () => {
        await page.getByRole('link', { name: 'Send' }).click();
        await expect(page.locator('#main-content').getByText('Send', { exact: true })).toBeVisible();

        await page.getByRole('button', { name: 'New', exact: true }).click();
        await page.getByRole('menuitem', { name: 'Text' }).click();

        await page.getByRole('textbox', { name: 'Send name (required)' }).fill('Email');
        await page.getByRole('textbox', { name: 'Text to share (required)' }).fill('Email');
        await page.getByRole('combobox', { name: 'Who can view' }).click();
        await page.getByText('Specific people').click();
        await page.getByRole('textbox', { name: 'Emails (required)' }).fill(users.user2.email);

        await page.getByRole('button', { name: 'Save' }).click();
        await page.locator('footer').getByRole('button', { name: 'Copy link' }).click();

        return await page.evaluate(() => navigator.clipboard.readText());
    });

    await test.step('View with email OTP', async () => {
        await page2.goto(mail_url, { waitUntil: 'domcontentloaded' });
        await expect(page2.getByRole('heading', { name: 'Verify your email to view' })).toBeVisible();
        await page2.getByRole('textbox', { name: 'Email (required)' }).fill(users.user2.email);
        await page2.getByRole('button', { name: 'Send code' }).click();

        let code = await retrieveEmailCode(test, pageMail, mailBuffer);
        await page2.getByRole('textbox', { name: 'Verification code' }).fill(code);
        await page2.getByRole('button', { name: 'View Send' }).click();
        await expect(page2.getByRole('heading', { name: 'View Send' })).toBeVisible();
        await expect(await page2.getByRole('paragraph').filter({ hasText: 'Email' })).toBeVisible();
    });

    mailBuffer.close();
    await context2.close();
});
