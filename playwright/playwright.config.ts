import { defineConfig, devices } from '@playwright/test';
import { exec } from 'node:child_process';

const utils = require('./global-utils');

utils.loadEnv();

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
    testDir: 'tests',
    /* Run tests in files in parallel */
    fullyParallel: false,

    /* Fail the build on CI if you accidentally left test.only in the source code. */
    forbidOnly: !!process.env.CI,

    /* Retry on CI only */
    retries: process.env.CI ? 2 : 0,
    workers: 1,

    /* Reporter to use. See https://playwright.dev/docs/test-reporters */
    reporter: 'html',
    timeout: 20 * 1000,
    expect: { timeout: 10 * 1000 },

    /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
    use: {
        /* Base URL to use in actions like `await page.goto('/')`. */
        baseURL: process.env.DOMAIN,
        browserName: 'firefox',
        /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
        trace: 'on-first-retry',
    },

    /* Configure projects for major browsers */
    projects: [
        {
            name: 'mariadb-setup',
            testMatch: 'tests/setups/db-setup.ts',
            use: { serviceName: "Mariadb" },
            teardown: 'mariadb-teardown',
        },
        {
            name: 'mysql-setup',
            testMatch: 'tests/setups/db-setup.ts',
            use: { serviceName: "Mysql" },
            teardown: 'mysql-teardown',
        },
        {
            name: 'postgres-setup',
            testMatch: 'tests/setups/db-setup.ts',
            use: { serviceName: "Postgres" },
            teardown: 'postgres-teardown',
        },

        {
            name: 'mariadb',
            testIgnore: 'tests/setups',
            dependencies: ['mariadb-setup'],
        },
        {
            name: 'mysql',
            testIgnore: 'tests/setups',
            dependencies: ['mysql-setup'],
        },
        {
            name: 'postgres',
            testIgnore: 'tests/setups',
            dependencies: ['postgres-setup'],
        },
        {
            name: 'sqlite',
            testIgnore: 'tests/setups',
        },

        {
            name: 'mariadb-teardown',
            testMatch: 'tests/setups/db-teardown.ts',
            use: { serviceName: "Mariadb" },
        },
        {
            name: 'mysql-teardown',
            testMatch: 'tests/setups/db-teardown.ts',
            use: { serviceName: "Mysql" },
        },
        {
            name: 'postgres-teardown',
            testMatch: 'tests/setups/db-teardown.ts',
            use: { serviceName: "Postgres" },
        },
    ],

    globalSetup: require.resolve('./global-setup'),
});
