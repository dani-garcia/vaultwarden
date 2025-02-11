import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from '../global-utils';
import * as orgs from './setups/orgs';
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

let mailServer, mail1Buffer, mail2Buffer, mail3Buffer;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailServer = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailServer.listen();

    await utils.startVaultwarden(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.VAULTWARDEN_SMTP_FROM,
    });

    mail1Buffer = mailServer.buffer(users.user1.email);
    mail2Buffer = mailServer.buffer(users.user2.email);
    mail3Buffer = mailServer.buffer(users.user3.email);
});

test.afterAll('Teardown', async ({}, testInfo: TestInfo) => {
    utils.stopVaultwarden(testInfo);
    [mail1Buffer, mail2Buffer, mail3Buffer, mailServer].map((m) => m?.close());
});

test('Create user3', async ({ page }) => {
    await createAccount(test, page, users.user3, mail3Buffer);
});

test('Invite users', async ({ page }) => {
    await createAccount(test, page, users.user1, mail1Buffer);
    await logUser(test, page, users.user1, mail1Buffer);

    await orgs.create(test, page, 'Test');
    await orgs.members(test, page, 'Test');
    await orgs.invite(test, page, 'Test', users.user2.email);
    await orgs.invite(test, page, 'Test', users.user3.email, {
        navigate: false,
    });
});

test('invited with new account', async ({ page }) => {
    const invited = await mail2Buffer.next((mail) => mail.subject === 'Join Test');

    await test.step('Create account', async () => {
        await page.setContent(invited.html);
        const link = await page.getByTestId('invite').getAttribute('href');
        await page.goto(link);
        await expect(page).toHaveTitle(/Create account | Vaultwarden Web/);

        await page.getByLabel('Name').fill(users.user2.name);
        await page.getByLabel('Master password\n   (required)', { exact: true }).fill(users.user2.password);
        await page.getByLabel('Re-type master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        // Back to the login page
        await utils.checkNotification(page, 'Your new account has been created');
    });

    await test.step('Login', async () => {
        await page.getByLabel(/Email address/).fill(users.user2.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByLabel('Master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaultwarden Web/);
        await utils.checkNotification(page, 'Invitation accepted');
    });

    await test.step('Check mails', async () => {
        await expect(mail2Buffer.next((m) => m.subject === 'Welcome')).resolves.toBeDefined();
        await expect(mail2Buffer.next((m) => m.subject === 'New Device Logged In From Firefox')).resolves.toBeDefined();
        await expect(mail1Buffer.next((m) => m.subject.includes('Invitation to Test accepted'))).resolves.toBeDefined();
    });
});

test('invited with existing account', async ({ page }) => {
    const invited = await mail3Buffer.next((mail) => mail.subject === 'Join Test');

    await page.setContent(invited.html);
    const link = await page.getByTestId('invite').getAttribute('href');

    await page.goto(link);

    // We should be on login page with email prefilled
    await expect(page).toHaveTitle(/Vaultwarden Web/);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user3.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaultwarden Web/);
    await utils.checkNotification(page, 'Invitation accepted');

    await expect(mail3Buffer.next((m) => m.subject === 'New Device Logged In From Firefox')).resolves.toBeDefined();
    await expect(mail1Buffer.next((m) => m.subject.includes('Invitation to Test accepted'))).resolves.toBeDefined();
});

test('Confirm invited user', async ({ page }) => {
    await logUser(test, page, users.user1, mail1Buffer);

    await orgs.members(test, page, 'Test');
    await orgs.confirm(test, page, 'Test', users.user2.name);

    await expect(mail2Buffer.next((m) => m.subject.includes('Invitation to Test confirmed'))).resolves.toBeDefined();
});

test('Organization is visible', async ({ page }) => {
    await logUser(test, page, users.user2, mail2Buffer);
    await page.getByLabel('vault: Test').click();
    await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
});
