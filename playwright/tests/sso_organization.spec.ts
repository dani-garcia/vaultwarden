import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/sso';

let users = utils.loadEnv();

let mailserver, user1Mails, user2Mails, user3Mails;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailserver = new MailDev({
        port: process.env.MAILDEV_SMTP_PORT,
        web: { port: process.env.MAILDEV_HTTP_PORT },
    })

    await mailserver.listen();

    await utils.startVaultwarden(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.VAULTWARDEN_SMTP_FROM,
        SSO_ENABLED: true,
        SSO_ONLY: true,
    });

    user1Mails = mailserver.iterator(users.user1.email);
    user2Mails = mailserver.iterator(users.user2.email);
    user3Mails = mailserver.iterator(users.user3.email);
});

test.afterAll('Teardown', async ({}, testInfo: TestInfo) => {
    utils.stopVaultwarden(testInfo);
    utils.closeMails(mailserver, [user1Mails, user2Mails, user3Mails]);
});

test('Create user2', async ({ page }) => {
    await createAccount(test, page, users.user2, user2Mails);
});

test('Invite users', async ({ page }) => {
    await createAccount(test, page, users.user1, user1Mails);

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
        await page.locator('label').filter({ hasText: 'Grant access to all current' }).click();
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText('User(s) invited');
    });

    await test.step('Invite user3', async () => {
        await page.getByRole('button', { name: 'Invite member' }).click();
        await page.getByLabel('Email (required)').fill(users.user3.email);
        await page.getByRole('tab', { name: 'Collections' }).click();
        await page.locator('label').filter({ hasText: 'Grant access to all current' }).click();
        await page.getByRole('button', { name: 'Save' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText('User(s) invited');
    });
});

test('invited with existing account', async ({ page }) => {
    const link = await test.step('Extract email link', async () => {
        const { value: invited } = await user2Mails.next();
        expect(invited.subject).toContain("Join Test")

        await page.setContent(invited.html);
        return await page.getByTestId("invite").getAttribute("href");
    });

    await test.step('Redirect to Keycloak', async () => {
        await page.goto(link);
        await expect(page).toHaveTitle("Enterprise single sign-on | Vaultwarden Web");
        await page.getByRole('button', { name: 'Log in' }).click();
    });

    await test.step('Keycloak login', async () => {
        await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
        await page.getByLabel(/Username/).fill(users.user2.name);
        await page.getByLabel('Password', { exact: true }).fill(users.user2.password);
        await page.getByRole('button', { name: 'Sign In' }).click();
    });

    await test.step('Unlock vault', async () => {
        await expect(page).toHaveTitle('Vaultwarden Web');
        await page.getByLabel('Master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Unlock' }).click();
    });

    await test.step('Default vault page', async () => {
        await expect(page).toHaveTitle(/Vaults/);
        await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
    });

    await test.step('Check mails', async () => {
        const { value: logged } = await user2Mails.next();
        expect(logged.subject).toContain("New Device Logged")

        const { value: accepted } = await user1Mails.next();
        expect(accepted.subject).toContain("Invitation to Test accepted")
    });
});

test('invited with new account', async ({ page }) => {
    const link = await test.step('Extract email link', async () => {
        const { value: invited } = await user3Mails.next();
        expect(invited.subject).toContain("Join Test")

        await page.setContent(invited.html);
        return await page.getByTestId("invite").getAttribute("href");
    });

    await test.step('Redirect to Keycloak', async () => {
        await page.goto(link);
        await expect(page).toHaveTitle("Enterprise single sign-on | Vaultwarden Web");
        await page.getByRole('button', { name: 'Log in' }).click();
    });

    await test.step('Keycloak login', async () => {
        await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
        await page.getByLabel(/Username/).fill(users.user3.name);
        await page.getByLabel('Password', { exact: true }).fill(users.user3.password);
        await page.getByRole('button', { name: 'Sign In' }).click();
    });

    await test.step('Create Vault account', async () => {
        await expect(page.getByText('Set master password')).toBeVisible();
        await page.getByLabel('Master password', { exact: true }).fill(users.user3.password);
        await page.getByLabel('Re-type master password').fill(users.user3.password);
        await page.getByRole('button', { name: 'Submit' }).click();
    });

    await test.step('Default vault page', async () => {
        await expect(page).toHaveTitle(/Vaults/);
        await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
    });

    await test.step('Check mails', async () => {
        const { value: logged } = await user3Mails.next();
        expect(logged.subject).toContain("New Device Logged")

        const { value: accepted } = await user1Mails.next();
        expect(accepted.subject).toContain("Invitation to Test accepted")
    });
});
