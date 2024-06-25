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
    retries: process.env.CI ? 2 : 0,
    workers: 1,

    /* Reporter to use. See https://playwright.dev/docs/test-reporters */
    reporter: 'html',
    timeout: 10 * 1000,
    expect: { timeout: 10 * 1000 },

    /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
    use: {
        /* Base URL to use in actions like `await page.goto('/')`. */
        baseURL: process.env.DOMAIN,

        /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
        trace: 'on-first-retry',
    },

    /* Configure projects for major browsers */
    projects: [
        {
            name: 'sqllite',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'postgres',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'mariadb',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'mysql',
            testMatch: 'tests/*.spec.ts',
            testIgnore: 'tests/sso_*.spec.ts',
            use: { ...devices['Desktop Firefox'] },
        },
        {
            name: 'sso-setup',
            testMatch: 'sso-setup.ts',
            teardown: 'sso-teardown',
        },
        {
            name: 'sso-sqllite',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'sso-postgres',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'sso-mariadb',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'sso-mysql',
            testMatch: 'tests/sso_*.spec.ts',
            dependencies: ['sso-setup'],
            teardown: 'sso-teardown',
        },
        {
            name: 'sso-teardown',
            testMatch: 'sso-teardown.ts',
        },
    ],

    globalSetup: require.resolve('./global-setup'),
});
