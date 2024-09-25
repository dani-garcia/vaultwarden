import { test, expect, type TestInfo } from '@playwright/test';

const { exec } = require('node:child_process');
const utils = require('../../global-utils');

utils.loadEnv();

test.beforeAll('Setup', async () => {
    console.log("Starting Keycloak");
    exec(`docker compose --profile keycloak --env-file test.env up`);
});

test('Keycloak is up', async ({ page }) => {
    test.setTimeout(60000);
    await utils.waitFor(process.env.SSO_AUTHORITY, page.context().browser());
    // Dummy authority is created at the end of the setup
    await utils.waitFor(process.env.DUMMY_AUTHORITY, page.context().browser());
    console.log(`Keycloak running on: ${process.env.SSO_AUTHORITY}`);
});
