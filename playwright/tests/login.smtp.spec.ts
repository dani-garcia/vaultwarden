import { test, expect, type TestInfo } from '@playwright/test';
import { MailDev } from 'maildev';

const utils = require('../global-utils');
import { createAccount, logUser } from './setups/user';

let users = utils.loadEnv();

let mailserver;

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
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVaultwarden();
    if( mailserver ){
        await mailserver.close();
    }
});

test('Account creation', async ({ page }) => {
    const emails = mailserver.iterator(users.user1.email);

    await createAccount(test, page, users.user1);

    const { value: created } = await emails.next();
    expect(created.subject).toBe("Welcome");
    expect(created.from[0]?.address).toBe(process.env.VAULTWARDEN_SMTP_FROM);

    // Back to the login page
    await expect(page).toHaveTitle('Vaultwarden Web');
    await expect(page.getByTestId("toast-message")).toHaveText(/Your new account has been created/);
    await page.getByRole('button', { name: 'Continue' }).click();

    // Unlock page
    await page.getByLabel('Master password').fill(users.user1.password);
    await page.getByRole('button', { name: 'Log in with master password' }).click();

    // We are now in the default vault page
    await expect(page).toHaveTitle(/Vaultwarden Web/);

    const { value: logged } = await emails.next();
    expect(logged.subject).toBe("New Device Logged In From Firefox");
    expect(logged.to[0]?.address).toBe(process.env.TEST_USER_MAIL);
    expect(logged.from[0]?.address).toBe(process.env.VAULTWARDEN_SMTP_FROM);

    emails.return();
});

test('Login', async ({ context, page }) => {
    const emails = mailserver.iterator(users.user1.email);

    await logUser(test, page, users.user1);

    await test.step('new device email', async () => {
        const { value: logged } = await emails.next();
        expect(logged.subject).toBe("New Device Logged In From Firefox");
        expect(logged.from[0]?.address).toBe(process.env.VAULTWARDEN_SMTP_FROM);
    });

    await test.step('verify email', async () => {
        await page.getByText('Verify your account\'s email').click();
        await expect(page.getByText('Verify your account\'s email')).toBeVisible();
        await page.getByRole('button', { name: 'Send email' }).click();

        // Close the toast message
        await expect(page.getByTestId("toast-message")).toHaveText(/Check your email inbox/);
        await page.locator('#toast-container').getByRole('button').click();
        await expect(page.getByTestId("toast-message")).toHaveCount(0);

        const { value: verify } = await emails.next();
        expect(verify.subject).toBe("Verify Your Email");
        expect(verify.from[0]?.address).toBe(process.env.VAULTWARDEN_SMTP_FROM);

        const page2 = await context.newPage();
        await page2.setContent(verify.html);
        const link = await page2.getByTestId("verify").getAttribute("href");
        await page2.close();

        await page.goto(link);
        await expect(page.getByTestId("toast-message")).toHaveText("Account email verified");
    });

    emails.return();
});

test('Activaite 2fa', async ({ context, page }) => {
    const emails = mailserver.buffer(users.user1.email);

    await logUser(test, page, users.user1);

    await page.getByRole('button', { name: users.user1.name }).click();
    await page.getByRole('menuitem', { name: 'Account settings' }).click();
    await page.getByRole('link', { name: 'Security' }).click();
    await page.getByRole('link', { name: 'Two-step login' }).click();
    await page.locator('li').filter({ hasText: 'Email' }).getByRole('button').click();
    await page.getByLabel('Master password (required)').fill(users.user1.password);
    await page.getByRole('button', { name: 'Continue' }).click();
    await page.getByRole('button', { name: 'Send email' }).click();

    const codeMail = await emails.next((mail) => mail.subject === "Vaultwarden Login Verification Code");
    const page2 = await context.newPage();
    await page2.setContent(codeMail.html);
    const code = await page2.getByTestId("2fa").innerText();
    await page2.close();

    await page.getByLabel('2. Enter the resulting 6').fill(code);
    await page.getByRole('button', { name: 'Turn on' }).click();
    await page.getByRole('heading', { name: 'Turned on', exact: true });

    emails.close();
});

test('2fa', async ({ context, page }) => {
    const emails = mailserver.buffer(users.user1.email);

    await test.step('login', async () => {
        await page.goto('/');

        await page.getByLabel(/Email address/).fill(users.user1.email);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByLabel('Master password').fill(users.user1.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        const codeMail = await emails.next((mail) => mail.subject === "Vaultwarden Login Verification Code");
        const page2 = await context.newPage();
        await page2.setContent(codeMail.html);
        const code = await page2.getByTestId("2fa").innerText();
        await page2.close();

        await page.getByLabel('Verification code').fill(code);
        await page.getByRole('button', { name: 'Continue' }).click();

        await expect(page).toHaveTitle(/Vaultwarden Web/);
    })

    await test.step('disable', async () => {
        await page.getByRole('button', { name: 'Test' }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('li').filter({ hasText: 'Email' }).getByRole('button').click();
        await page.getByLabel('Master password (required)').click();
        await page.getByLabel('Master password (required)').fill(users.user1.password);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByRole('button', { name: 'Turn off' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();
        await expect(page.getByTestId("toast-message")).toHaveText(/Two-step login provider turned off/);
    });

    emails.close();
});
