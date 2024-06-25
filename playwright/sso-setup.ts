import { test, expect, type TestInfo } from '@playwright/test';

const { exec } = require('node:child_process');
const utils = require('./global-utils');

utils.loadEnv();

test.beforeAll('Setup', async () => {
    var kcPath = process.env.KC_SETUP_PATH;
    console.log("Starting Keycloak");
    exec(`ENV=test KC_SETUP_PATH=${kcPath} docker-compose -f ${kcPath}/docker-compose.yml  --project-directory . up >> temp/logs/keycloak.log 2>&1`);
});

test('Keycloak is up', async ({ page }) => {
    test.setTimeout(60000);
    await utils.waitFor(process.env.SSO_AUTHORITY, page.context().browser());
    console.log(`Keycloak running on: ${process.env.SSO_AUTHORITY}`);
});
