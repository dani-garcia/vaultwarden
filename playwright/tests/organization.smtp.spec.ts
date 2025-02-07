import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';

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
    });

    user1Mails = mailserver.iterator(users.user1.email);
    user2Mails = mailserver.iterator(users.user2.email);
    user3Mails = mailserver.iterator(users.user3.email);
});

test.afterAll('Teardown', async ({}, testInfo: TestInfo) => {
    utils.stopVaultwarden(testInfo);
    utils.closeMails(mailserver, [user1Mails, user2Mails, user3Mails]);
});

test('Create user3', async ({ page }) => {
    await createAccount(test, page, users.user3, user3Mails);
});

test('Invite users', async ({ page }) => {
    await createAccount(test, page, users.user1, user1Mails);
    await logUser(test, page, users.user1, user1Mails);

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

test('invited with new account', async ({ page }) => {
    const { value: invited } = await user2Mails.next();
    expect(invited.subject).toContain("Join Test")

    await test.step('Create account', async () => {
        await page.setContent(invited.html);
        const link = await page.getByTestId("invite").getAttribute("href");
        await page.goto(link);
        await expect(page).toHaveTitle(/Create account | Vaultwarden Web/);

        await page.getByLabel('Name').fill(users.user2.name);
        await page.getByLabel('Master password\n   (required)', { exact: true }).fill(users.user2.password);
        await page.getByLabel('Re-type master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        // Back to the login page
        await expect(page).toHaveTitle('Vaultwarden Web');
        await expect(page.getByTestId("toast-message")).toHaveText(/Your new account has been created/);
        await page.locator('#toast-container').getByRole('button').click();

        const { value: welcome } = await user2Mails.next();
        expect(welcome.subject).toContain("Welcome")
    });

    await test.step('Login', async () => {
        await page.getByLabel(/Email address/).fill(users.user2.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByLabel('Master password').fill(users.user2.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaultwarden Web/);
        await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
        await page.locator('#toast-container').getByRole('button').click();

        const { value: logged } = await user2Mails.next();
        expect(logged.subject).toContain("New Device Logged");
    });

    const { value: accepted } = await user1Mails.next();
    expect(accepted.subject).toContain("Invitation to Test accepted")
});

test('invited with existing account', async ({ page }) => {
    const { value: invited } = await user3Mails.next();
    expect(invited.subject).toContain("Join Test")

    await page.setContent(invited.html);
    const link = await page.getByTestId("invite").getAttribute("href");

    await page.goto(link);

    // We should be on login page with email prefilled
    await expect(page).toHaveTitle(/Vaultwarden Web/);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user3.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaultwarden Web/);
    await expect(page.getByTestId("toast-title")).toHaveText("Invitation accepted");
    await page.locator('#toast-container').getByRole('button').click();

    const { value: logged } = await user3Mails.next();
    expect(logged.subject).toContain("New Device Logged")

    const { value: accepted } = await user1Mails.next();
    expect(accepted.subject).toContain("Invitation to Test accepted")
});

test('Confirm invited user', async ({ page }) => {
    await logUser(test, page, users.user1, user1Mails);
    await page.getByLabel('Switch products').click();
    await page.getByRole('link', { name: ' Admin Console' }).click();
    await page.getByRole('link', { name: 'Members' }).click();

    await test.step('Accept user2', async () => {
        await page.getByRole('row', { name: users.user2.name }).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Confirm' }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText(/confirmed/);
        await page.locator('#toast-container').getByRole('button').click();

        const { value: logged } = await user2Mails.next();
        expect(logged.subject).toContain("Invitation to Test confirmed");
    });
});

test('Organization is visible', async ({ page }) => {
    await logUser(test, page, users.user2, user2Mails);
    await page.getByLabel('vault: Test').click();
    await expect(page.getByLabel('Filter: Default collection')).toBeVisible();
});
