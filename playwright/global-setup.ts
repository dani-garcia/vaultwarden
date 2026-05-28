import { firefox, type FullConfig } from '@playwright/test';
import { execSync } from 'node:child_process';
import fs from 'fs';

const utils = require('./global-utils');

utils.loadEnv();

async function globalSetup(config: FullConfig) {
    // PW_USE_EXTERNAL_VAULT=1 points the spec at a Vaultwarden the operator
    // is already running (host-side cargo, a remote dev box, etc.). The
    // docker harness isn't used, so skipping the multi-minute image
    // build keeps the local-iteration loop short.
    if (process.env.PW_USE_EXTERNAL_VAULT === '1') return;

    // Are we running in docker and the project is mounted ?
    const path = (fs.existsSync("/project/playwright/playwright.config.ts") ? "/project/playwright" : ".");
    execSync(`docker compose --project-directory ${path} --profile playwright --env-file test.env build VaultwardenPrebuild`, {
        env: { ...process.env },
        stdio: "inherit"
    });
    execSync(`docker compose --project-directory ${path} --profile playwright --env-file test.env build Vaultwarden`, {
        env: { ...process.env },
        stdio: "inherit"
    });
}

export default globalSetup;
