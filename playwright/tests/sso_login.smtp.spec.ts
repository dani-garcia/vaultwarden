import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as admin from "./setups/admin";
import { logNewUser, logUser } from './setups/sso';
import { activateEmail, disableEmail } from './setups/2fa';
import * as utils from "../global-utils";

let users = utils.loadEnv();

let mailserver;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailserver = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailserver.listen();

    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: true,
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.PW_SMTP_FROM,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    if( mailserver ){
        await mailserver.close();
    }
});

test('2FA email', async ({ page }) => {

    const mailBuffer = mailserver.buffer(users.user1.email);

    await logNewUser(test, page, users.user1, {mailBuffer: mailBuffer});

    await activateEmail(test, page, users.user1, mailBuffer);

    await logUser(test, page, users.user1, {mailBuffer: mailBuffer, mail2fa: true, notNewDevice: true});

    await disableEmail(test, page, users.user1);

    mailBuffer.close();
});


test('Admin invite', async ({ page }) => {
    const mailBuffer = mailserver.buffer(users.user2.email);

    await admin.login(test, page);
    await admin.invite(test, page, users.user2.email);


    const link = await test.step('Extract email link', async () => {
        const invited = await mailBuffer.expect((m) => m.subject === "Join Vaultwarden");
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
        await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(users.user2.password);
        await page.getByRole('textbox', { name: 'Confirm master password * (' }).fill(users.user2.password);
        await page.getByRole('button', { name: 'Create account' }).click();
    });

    await test.step('Default vault page', async () => {
        await expect(page).toHaveTitle('Vaults | Vaultwarden Web');

        await utils.checkNotification(page, 'Account successfully created!');
        await utils.checkNotification(page, 'Invitation accepted');
    });

    await test.step('Check mails', async () => {
        await mailBuffer.expect((m) => m.subject.includes("New Device Logged"));
        await mailBuffer.expect((m) => m.subject === "Welcome");
    });

    mailBuffer.close();
});
