import { test, expect, type TestInfo } from '@playwright/test';

import * as utils from "../global-utils";
import { logNewUser, logUser } from './setups/sso';

let users = utils.loadEnv();

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: true,
        SSO_ONLY: true,
        SSO_ROLES_ENABLED: true,
        SSO_ROLES_DEFAULT_TO_USER: false,
        SSO_SCOPES: "email profile roles",
    });
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('admin have access to vault/admin page', async ({ page }) => {
    await logNewUser(test, page, users.user1);

    await page.goto('/admin');

    await expect(page.getByRole('heading', { name: 'Configuration' })).toBeVisible();
});

test('user have access to vault', async ({ page }) => {
    await logNewUser(test, page, users.user2);

    await page.goto('/admin');

    await expect(page.getByRole('heading', { name: 'You do not have access' })).toBeVisible();
});

test('No role cannot log', async ({ page }) => {
    await test.step('Landing page', async () => {
        await utils.cleanLanding(page);
        await page.locator("input[type=email].vw-email-sso").fill(users.user3.email);
        await page.getByRole('button', { name: /Use single sign-on/ }).click();
    });

    await test.step('Keycloak login', async () => {
        await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
        await page.getByLabel(/Username/).fill(users.user3.name);
        await page.getByLabel('Password', { exact: true }).fill(users.user3.password);
        await page.getByRole('button', { name: 'Sign In' }).click();
    });

    await test.step('Auth failed', async () => {
        await expect(page).toHaveTitle('Vaultwarden Web');
        await utils.checkNotification(page, 'Invalid user role');
    });
});
