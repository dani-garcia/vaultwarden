import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

const utils = require('../global-utils');
import { createAccount, logUser } from './setups/user';
import { activateEmail, retrieveEmailCode, disableEmail } from './setups/2fa';

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
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
    if( mailserver ){
        await mailserver.close();
    }
});

test('Account creation', async ({ page }) => {
    const mailBuffer = mailserver.buffer(users.user1.email);

    await createAccount(test, page, users.user1, mailBuffer);

    mailBuffer.close();
});

test('Login', async ({ context, page }) => {
    const mailBuffer = mailserver.buffer(users.user1.email);

    await logUser(test, page, users.user1, mailBuffer);

    await test.step('verify email', async () => {
        await page.getByText('Verify your account\'s email').click();
        await expect(page.getByText('Verify your account\'s email')).toBeVisible();
        await page.getByRole('button', { name: 'Send email' }).click();

        await utils.checkNotification(page, 'Check your email inbox for a verification link');

        const verify = await mailBuffer.expect((m) => m.subject === "Verify Your Email");
        expect(verify.from[0]?.address).toBe(process.env.PW_SMTP_FROM);

        const page2 = await context.newPage();
        await page2.setContent(verify.html);
        const link = await page2.getByTestId("verify").getAttribute("href");
        await page2.close();

        await page.goto(link);
        await utils.checkNotification(page, 'Account email verified');
    });

    mailBuffer.close();
});

test('Activate 2fa', async ({ page }) => {
    const emails = mailserver.buffer(users.user1.email);

    await logUser(test, page, users.user1);

    await activateEmail(test, page, users.user1, emails);

    emails.close();
});

test('2fa', async ({ page }) => {
    const emails = mailserver.buffer(users.user1.email);

    await test.step('login', async () => {
        await page.goto('/');

        await page.getByLabel(/Email address/).fill(users.user1.email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByLabel('Master password').fill(users.user1.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        await expect(page.getByRole('heading', { name: 'Verify your Identity' })).toBeVisible();
        const code = await retrieveEmailCode(test, page, emails);
        await page.getByLabel(/Verification code/).fill(code);
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page).toHaveTitle(/Vaults/);
    })

    await disableEmail(test, page, users.user1);

    emails.close();
});
