import { test, expect, type Page, type TestInfo, Test } from '@playwright/test';
import { MailDev } from 'maildev';

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';
import { activateTOTP } from './setups/2fa';

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

async function emergencyAccess(test: Test, page: Page, user: { name: string }) {
    await test.step('Navigate', async () => {
        await page.getByRole('button', { name: user.name }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Emergency access' }).click();
        await expect(page.locator('#main-content').getByText('Emergency access', { exact: true })).toBeVisible();
    });
}

test('Emergency access', async ({ browser, page }) => {
    const context2 = await browser.newContext();
    const page2 = await context2.newPage();

    const mailBuffer = mailserver.buffer(users.user1.email);
    const mailBuffer2 = mailserver.buffer(users.user2.email);

    await createAccount(test, page, users.user1);
    await createAccount(test, page2, users.user2);

    await test.step('Add test2', async () => {
        await emergencyAccess(test, page, users.user1);
        await page.getByRole('button', { name: 'Add emergency contact' }).click();
        await page.getByRole('textbox', { name: 'Email * (required)' }).fill(users.user2.email);
        await page.getByRole('radio', { name: 'Takeover Can reset your' }).check();
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'User(s) invited');
    });

    await test.step('Accept', async () => {
        const email = await mailBuffer2.expect((m) => m.subject === "Emergency access for " + users.user1.name);
        const pageE = await context2.newPage();
        await pageE.setContent(email.html);
        const link = await pageE.getByTestId("emergency").getAttribute("href");
        await pageE.close();

        await page2.goto(link);
        await utils.checkNotification(page2, 'Invitation accepted');
    });

    await test.step('Confirm', async () => {
        await emergencyAccess(test, page, users.user1);
        await expect(page.locator('#main-content').getByText('Needs confirmation')).toBeVisible();
        await page.getByRole('button', { name: 'Options' }).click();
        await page.getByRole('menuitem', { name: 'Confirm' }).click();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await utils.checkNotification(page, users.user2.name + ' confirmed');
        await mailBuffer2.expect((m) => m.subject === "Emergency access contact for " + users.user1.name + " confirmed");
    });

    await test.step('Request', async () => {
        await emergencyAccess(test, page2, users.user2);
        await page2.getByRole('button', { name: 'Options' }).click();
        await page2.getByRole('menuitem', { name: 'Request Access' }).click();
        await page2.getByRole('button', { name: 'Request Access' }).click();
        await utils.checkNotification(page2, 'Emergency access requested');
        await mailBuffer.expect((m) => m.subject === "Emergency access request by " + users.user2.name + " initiated");
    });

    await test.step('Approved', async () => {
        await emergencyAccess(test, page, users.user1);
        await page.getByRole('button', { name: 'Options' }).click();
        await page.getByRole('menuitem', { name: 'Approve' }).click();
        await page.getByRole('button', { name: 'Approve' }).click();
        await utils.checkNotification(page, 'Emergency access approved');
        await mailBuffer2.expect((m) => m.subject === "Emergency access request for " + users.user1.name + " approved");
    });
    await activateTOTP(test, page, users.user1);

    let newPassword = "TotoNewPassword";
    await test.step('Access', async () => {
        await emergencyAccess(test, page2, users.user2);
        await page2.getByRole('button', { name: 'Options' }).click();
        await page2.getByRole('menuitem', { name: 'Takeover' }).click();
        await page2.getByRole('textbox', { name: 'New master password * (required)', exact: true }).fill(newPassword);
        await page2.getByRole('textbox', { name: 'Confirm new master password' }).fill(newPassword);
        await page2.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page2, 'Password reset for ' + users.user1.name);
    });

    await test.step('Changed no 2fa', async () => {
        users.user1.password = newPassword;
        await logUser(test, page, users.user1);
    });

    await test.step('Reject', async () => {
        await emergencyAccess(test, page, users.user1);
        await page.getByRole('button', { name: 'Options' }).click();
        await page.getByRole('menuitem', { name: 'Reject' }).click();
        await utils.checkNotification(page, 'Emergency access rejected');
        await mailBuffer2.expect((m) => m.subject === "Emergency access request to " + users.user1.name + " rejected");
    });

    await test.step('Remove', async () => {
        await page.getByRole('button', { name: 'Options' }).click();
        await page.getByRole('menuitem', { name: 'Remove' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();
        await utils.checkNotification(page, 'Removed user ' + users.user2.name);
        await expect(page.getByText('You have not added any emergency contacts')).toBeVisible();
    });
});
