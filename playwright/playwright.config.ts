import { defineConfig, devices } from '@playwright/test';
import { exec } from 'node:child_process';

const utils = require('./global-utils');

utils.loadEnv();

/**
 * See https://playwright.dev/docs/test-configuration.
 */
export default defineConfig({
    testDir: './.',
    /* Run tests in files in parallel */
    fullyParallel: false,

    /* Fail the build on CI if you accidentally left test.only in the source code. */
    forbidOnly: !!process.env.CI,

    /* Retry on CI only */
    retries: 0,
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
        locale: 'en-GB',
        timezoneId: 'Europe/London',
        /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
        trace: 'on-first-retry',
        viewport: {
            width: 1920,
            height: 1080
        },
        video: "on",
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
            name: 'sso-setup',
            testMatch: 'tests/setups/sso-setup.ts',
            teardown: 'sso-teardown',
        },

        {
            name: 'mariadb',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
            dependencies: ['mariadb-setup'],
        },
        {
            name: 'mysql',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
            dependencies: ['mysql-setup'],
        },
        {
            name: 'postgres',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
            dependencies: ['postgres-setup'],
        },
        {
            name: 'sqlite',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
        },

        {
            name: 'sso-mariadb',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup', 'mariadb-setup'],
        },
        {
            name: 'sso-mysql',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup', 'mysql-setup'],
        },
        {
            name: 'sso-postgres',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup', 'postgres-setup'],
        },
        {
            name: 'sso-sqlite',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup'],
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
        {
            name: 'sso-teardown',
            testMatch: 'tests/setups/sso-teardown.ts',
        },
    ],

    globalSetup: require.resolve('./global-setup'),
});
