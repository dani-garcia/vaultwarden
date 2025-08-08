import { test, type FullConfig } from '@playwright/test';

const { execSync } = require('node:child_process');
const utils = require('../../global-utils');

utils.loadEnv();

test('Keycloak teardown', async () => {
    if( process.env.PW_KEEP_SERVICE_RUNNNING === "true" ) {
        console.log("Keep Keycloak running");
    } else {
        console.log("Keycloak stopping");
        execSync(`docker compose --profile keycloak --env-file test.env stop Keycloak`);
    }
});
