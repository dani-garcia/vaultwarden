import { firefox, type FullConfig } from '@playwright/test';
import { execSync } from 'node:child_process';
import fs from 'fs';

const utils = require('./global-utils');

utils.loadEnv();

async function globalSetup(config: FullConfig) {
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
