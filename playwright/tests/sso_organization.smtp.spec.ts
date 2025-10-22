import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import * as orgs from './setups/orgs';
import { logNewUser, logUser } from './setups/sso';

let users = utils.loadEnv();

let mailServer, mail1Buffer, mail2Buffer, mail3Buffer;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailServer = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailServer.listen();

    await utils.startVault(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
        SSO_ENABLED: true,
        SSO_ONLY: true,
    });

    mail1Buffer = mailServer.buffer(users.user1.email);
    mail2Buffer = mailServer.buffer(users.user2.email);
    mail3Buffer = mailServer.buffer(users.user3.email);
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    [mail1Buffer, mail2Buffer, mail3Buffer, mailServer].map((m) => m?.close());
});

test('Create user3', async ({ page }) => {
    await logNewUser(test, page, users.user3, { mailBuffer: mail3Buffer });
});

test('Invite users', async ({ page }) => {
    await logNewUser(test, page, users.user1, { mailBuffer: mail1Buffer });

    await orgs.create(test, page, '/Test');
    await orgs.members(test, page, '/Test');
    await orgs.invite(test, page, '/Test', users.user2.email);
    await orgs.invite(test, page, '/Test', users.user3.email);
});

test('invited with new account', async ({ page }) => {
    const link = await test.step('Extract email link', async () => {
        const invited = await mail2Buffer.expect((m) => m.subject === "Join /Test");
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
        await expect(page.getByRole('heading', { name: 'Join organisation' })).toBeVisible();
        await page.getByLabel('Master password (required)', { exact: true }).fill(users.user2.password);
        await page.getByLabel('Confirm master password (').fill(users.user2.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        await utils.checkNotification(page, 'Account successfully created!');
        await utils.checkNotification(page, 'Invitation accepted');
        await utils.ignoreExtension(page);
    });

    await test.step('Default vault page', async () => {
        await expect(page).toHaveTitle(/Vaultwarden Web/);
    });

    await test.step('Check mails', async () => {
        await mail2Buffer.expect((m) => m.subject.includes("New Device Logged"));
        await mail1Buffer.expect((m) => m.subject === "Invitation to /Test accepted");
    });
});

test('invited with existing account', async ({ page }) => {
    const link = await test.step('Extract email link', async () => {
        const invited = await mail3Buffer.expect((m) => m.subject === "Join /Test");
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

        await utils.checkNotification(page, 'Invitation accepted');
        await utils.ignoreExtension(page);
    });

    await test.step('Default vault page', async () => {
        await expect(page).toHaveTitle(/Vaultwarden Web/);
    });

    await test.step('Check mails', async () => {
        await mail3Buffer.expect((m) => m.subject.includes("New Device Logged"));
        await mail1Buffer.expect((m) => m.subject === "Invitation to /Test accepted");
    });
});
