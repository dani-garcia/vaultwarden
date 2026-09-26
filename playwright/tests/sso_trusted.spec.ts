import { test, expect, type TestInfo } from '@playwright/test';

import { keycloak, landing, logNewUser, logUser } from './setups/sso';
import { activateTOTP, disableTOTP } from './setups/2fa';
import * as utils from "../global-utils";

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_TRUSTED_DEVICE_ENCRYPTION: true,
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

export async function startTrusted(test: Test, page: Page) {
    await landing(test, page, users.user1);

    await keycloak(test, page, users.user1);

    await test.step('Approval required', async () => {
        await expect(page.getByRole('heading', { name: 'Device approval required' })).toBeVisible();
    })
}

export async function trustedUnlock(test: Test, page: Page) {
    await test.step('Unlock', async () => {
        await page.getByRole('button', { name: users.user1.name, exact: true }).click();
        await page.getByRole('menuitem', { name: 'Log out' }).click();

        await landing(test, page, users.user1, { noReset: true });
        await expect(page).toHaveTitle(/Vaults/);
    });
}

test('Trusted', async ({ browser, page }) => {
    // No change to onboarding
    await logNewUser(test, page, users.user1);

    await test.step('Password', async () => {
        await startTrusted(test, page);

        await test.step('Only password', async () => {
            await expect(page.getByRole('button', { name: 'Approve from your other device' })).toHaveCount(0);
            await expect(page.getByRole('button', { name: 'Request admin approval' })).toHaveCount(0);
        });

        await test.step('Activate', async () => {
            await page.getByRole('button', { name: 'Use master password' }).click();
            await expect(page.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible();
            await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(users.user1.password);
            await page.getByRole('button', { name: 'Unlock' }).click();
        });

        await test.step('Activated', async () => {
            await expect(page).toHaveTitle(/Vaults/);
            await utils.checkNotification(page, 'Device Trusted');
        });

        await trustedUnlock(test, page);
    });

    const context2 = await browser.newContext();
    const page2 = await context2.newPage();

    await test.step('Approval', async () => {
        await startTrusted(test, page2);

        await test.step('Request', async () => {
            await page2.getByRole('button', { name: 'Approve from your other device' }).click();
            await expect(page2.getByRole('heading', { name: 'Request sent' })).toBeVisible();
        });

        await test.step('Validate', async () => {
            await page.getByText('You have a pending login').click();
            await page.getByRole('link', { name: 'Review login request' }).click();
            await expect(page.getByRole('heading', { name: 'Devices' })).toBeVisible();
            await page.getByRole('row').filter({hasText: "Request pending"}).getByRole('link').click();
            await page.getByRole('button', { name: 'Confirm access' }).click();
            await utils.checkNotification(page, 'Login request approved');
        });

        await test.step('Validated', async () => {
            await expect(page2).toHaveTitle(/Vaults/);
            await utils.checkNotification(page2, 'Login Approved');
            await utils.checkNotification(page2, 'Device Trusted');
        });

        await trustedUnlock(test, page2);
    });

    await test.step('Invalidate', async () => {
        await page.getByRole('link', { name: 'Settings' }).click();
        await page.getByRole('button', { name: 'Deauthorise sessions' }).click();;
        await expect(page.getByRole('heading', { name: 'Deauthorise sessions' })).toBeVisible();
        await page.getByRole('textbox', { name: 'Master password * (required)', exact: true }).fill(users.user1.password);
        await page.getByRole('button', { name: 'Deauthorise sessions' }).click();
    });

    await test.step('Invalidated', async () => {
        await landing(test, page, users.user1, { noReset: true });
        await page.getByRole('heading', { name: 'Device approval required' }).click();

        await landing(test, page2, users.user1, { noReset: true });
        await page2.getByRole('heading', { name: 'Device approval required' }).click();
    });

    await context2.close();
});

