import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import { logNewUser, logUser } from './setups/sso';

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
        SSO_ENABLED: true,
        SSO_ONLY: true,
    });

    mail1Buffer = mailServer.buffer(users.user1.email);
    mail2Buffer = mailServer.buffer(users.user2.email);
    mail3Buffer = mailServer.buffer(users.user3.email);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVaultwarden();
    [mailServer, mail1Buffer, mail2Buffer, mail3Buffer].map((m) => m?.close());
});

test('Create user3', async ({ page }) => {
    await logNewUser(test, page, users.user3, { mailBuffer: mail3Buffer });
});

test('Invite users', async ({ page }) => {
    await logNewUser(test, page, users.user1, { mailBuffer: mail1Buffer });

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
    });
});

test.fail('invited with new account', async ({ page }) => {
    const link = await test.step('Extract email link', async () => {
        const invited = await mail2Buffer.next((m) => m.subject === "Join Test");
        await page.setContent(invited.html);
        return await page.getByTestId("invite").getAttribute("href");
    });

    await test.step('Redirect to Keycloak', async () => {
        await page.goto(link);
    });

    await test.step('Keycloak login', async () => {
        await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
        await page.getByLabel(/Username/).fill(users.user2.name);
        await page.getByLabel('Password', { exact: true }).fill(users.user2.password);
        await page.getByRole('button', { name: 'Sign In' }).click();
    });

    await test.step('Create Vault account', async () => {
        await expect(page.getByText('Set master password')).toBeVisible();
        await page.getByLabel('Master password', { exact: true }).fill(users.user2.password);
        await page.getByLabel('Re-type master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Submit' }).click();
    });

    await test.step('Default vault page', async () => {
        await expect(page).toHaveTitle(/Vaultwarden Web/);
        await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
        await page.locator('#toast-container').getByRole('button').click();
    });

    await test.step('Check mails', async () => {
        await expect(mail2Buffer.next((m) => m.subject.includes("New Device Logged"))).resolves.toBeDefined();
        await expect(mail1Buffer.next((m) => m.subject === "Invitation to Test accepted")).resolves.toBeDefined();
    });
});

test('invited with existing account', async ({ page }) => {
    const link = await test.step('Extract email link', async () => {
        const invited = await mail3Buffer.next((m) => m.subject === "Join Test");
        await page.setContent(invited.html);
        return await page.getByTestId("invite").getAttribute("href");
    });

    await test.step('Redirect to Keycloak', async () => {
        await page.goto(link);
    });

    await test.step('Keycloak login', async () => {
        await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
        await page.getByLabel(/Username/).fill(users.user3.name);
        await page.getByLabel('Password', { exact: true }).fill(users.user3.password);
        await page.getByRole('button', { name: 'Sign In' }).click();
    });

    await test.step('Unlock vault', async () => {
        await expect(page).toHaveTitle('Vaultwarden Web');
        await page.getByLabel('Master password').fill(users.user3.password);
        await page.getByRole('button', { name: 'Unlock' }).click();
    });

    await test.step('Default vault page', async () => {
        await expect(page).toHaveTitle(/Vaultwarden Web/);
        await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
        await page.locator('#toast-container').getByRole('button').click();
    });

    await test.step('Check mails', async () => {
        await expect(mail3Buffer.next((m) => m.subject.includes("New Device Logged"))).resolves.toBeDefined();
        await expect(mail1Buffer.next((m) => m.subject === "Invitation to Test accepted")).resolves.toBeDefined();
    });
});
