import { test, expect, type TestInfo } from '@playwright/test';

import * as utils from '../global-utils';

/**
 * Web-first checks for SSO + trusted-device (TDE) support:
 * - `sso-connector.html` must be served for browser OIDC redirect.
 */
test.beforeAll('Setup', async ({ browser }, testInfo: TestInfo) => {
    await utils.startVault(browser, testInfo, {
        SSO_ENABLED: 'true',
        SSO_ONLY: 'false',
        SSO_TRUSTED_DEVICE_ENCRYPTION: 'true',
    });
});

test.afterAll('Teardown', async () => {
    utils.stopVault();
});

test('Web vault serves sso-connector.html for browser SSO', async ({ request }) => {
    const res = await request.get('/sso-connector.html');
    expect(res.ok(), await res.text()).toBeTruthy();
    const ct = res.headers()['content-type'] || '';
    expect(ct).toMatch(/text\/html/i);
});
