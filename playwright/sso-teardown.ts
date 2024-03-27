import { test, type FullConfig } from '@playwright/test';

const { execSync } = require('node:child_process');
const utils = require('./global-utils');

utils.loadEnv();

test('Keycloak teardown', async () => {
    var kcPath = process.env.KC_SETUP_PATH;

    if( process.env.KC_KEEP_RUNNNING == "true" ) {
        console.log("Keep Keycloak running");
    } else {
        console.log("Keycloak stopping");
        execSync(`ENV=test KC_SETUP_PATH=${kcPath} docker-compose -f ${kcPath}/docker-compose.yml  --project-directory . down`);
    }
});
