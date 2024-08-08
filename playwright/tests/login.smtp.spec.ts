import { test, expect, type TestInfo } from '@playwright/test';

const utils = require('../global-utils');
const MailDev = require('maildev')
const Stream = require('stream')

utils.loadEnv();

var maildev;
var emails;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    maildev = new MailDev({
      smtp: process.env.MAILDEV_PORT
    })

    const [err] = await utils.asyncCallback(maildev.listen);
    if( !err ) {
      console.log('Maildev is up');
      emails = utils.emailGenerator(maildev);
    }

    await utils.startVaultwarden(browser, testInfo, {
        SMTP_HOST: process.env.MAILDEV_HOST,
        SMTP_FROM: "vaultwarden@playwright.test"
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVaultwarden();
    if( maildev ){
        maildev.close();
    }
});

test('Account creation', async ({ page }) => {
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
    expect(created.headers.to).toBe(process.env.TEST_USER_MAIL);
    expect(created.headers.from).toBe("Vaultwarden <vaultwarden@playwright.test>");

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
    expect(logged.headers.to).toBe(process.env.TEST_USER_MAIL);
    expect(logged.headers.from).toBe("Vaultwarden <vaultwarden@playwright.test>");
});

test('Master password login', async ({ page }) => {
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
    expect(logged.headers.to).toBe(process.env.TEST_USER_MAIL);
    expect(logged.headers.from).toBe("Vaultwarden <vaultwarden@playwright.test>");
});
