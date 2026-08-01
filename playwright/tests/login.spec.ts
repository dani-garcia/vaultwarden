import { test, type TestInfo } from '@playwright/test';

import * as utils from "../global-utils";
import { createAccount, logUser } from './setups/user';
import { activateTOTP, disableTOTP } from './setups/2fa';

let users = utils.loadEnv();
let totp;

test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {});
});

test.afterAll('Teardown', async ({}) => {
    utils.stopVault();
});

test('Account creation', async ({ page }) => {
    await createAccount(test, page, users.user1);
});

test('Master password login', async ({ page }) => {
    await logUser(test, page, users.user1);
});

test('Authenticator 2fa', async ({ page }) => {
    await logUser(test, page, users.user1);

    let totp = await activateTOTP(test, page, users.user1);

    await utils.logout(test, page, users.user1);

    await logUser(test, page, users.user1, { twoFactor: { kind: 'totp', totp } });

    await disableTOTP(test, page, users.user1);
});
