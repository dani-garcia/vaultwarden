import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

const utils = require('../global-utils');
const Stream = require('stream')

utils.loadEnv();

var mailserver;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    mailserver = new MailDev({
      port: process.env.MAILDEV_PORT
    })

    await mailserver.listen();

    await utils.startVaultwarden(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: process.env.VAULTWARDEN_SMTP_FROM,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVaultwarden();
    if( mailserver ){
        await mailserver.close();
    }
});

test('Account creation', async ({ page }) => {
    const emails = mailserver.iterator(process.env.TEST_USER_MAIL);

    // Landing page
    await page.goto('/');
    await page.getByRole('link', { name: 'Create account' }).click();

    // Back to Vault create account
    await expect(page).toHaveTitle(/Create account | Vaultwarden Web/);
    await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
    await page.getByLabel('Name').fill(process.env.TEST_USER);
    await page.getByLabel('Master password\n   (required)', { exact: true }).fill('Master password');
    await page.getByLabel('Re-type master password').fill('Master password');
    await page.getByRole('button', { name: 'Create account' }).click();

    const { value: created } = await emails.next();
    expect(created.subject).toBe("Welcome");
    expect(created.to[0]?.address).toBe(process.env.TEST_USER_MAIL);
    expect(created.from[0]?.address).toBe(process.env.VAULTWARDEN_SMTP_FROM);

    // Back to the login page
    await expect(page).toHaveTitle('Vaultwarden Web');
    await page.getByLabel('Your new account has been created')
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill('Master password');
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);

    const { value: logged } = await emails.next();
    expect(logged.subject).toBe("New Device Logged In From Firefox");
    expect(logged.to[0]?.address).toBe(process.env.TEST_USER_MAIL);
    expect(logged.from[0]?.address).toBe(process.env.VAULTWARDEN_SMTP_FROM);

    emails.return();
});

test('Master password login', async ({ page }) => {
    const emails = mailserver.iterator("new");

    // Landing page
    await page.goto('/');
    await page.getByLabel(/Email address/).fill(process.env.TEST_USER_MAIL);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill('Master password');
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaults/);

    const { value: logged } = await emails.next();
    expect(logged.subject).toBe("New Device Logged In From Firefox");
    expect(logged.to[0]?.address).toBe(process.env.TEST_USER_MAIL);
    expect(logged.from[0]?.address).toBe(process.env.VAULTWARDEN_SMTP_FROM);

    emails.return();
});
