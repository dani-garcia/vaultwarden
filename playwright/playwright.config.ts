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

    retries: 0,
    workers: 1,

    /* Reporter to use. See https://playwright.dev/docs/test-reporters */
    reporter: 'html',

    /* Long global timeout for complex tests
     * But short action/nav/expect timeouts to fail on specific step (raise locally if not enough).
     */
    timeout: 120 * 1000,
    actionTimeout: 20 * 1000,
    navigationTimeout: 20 * 1000,
    expect: { timeout: 20 * 1000 },

    /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
    use: {
        /* Base URL to use in actions like `await page.goto('/')`. */
        baseURL: process.env.DOMAIN,
        browserName: 'firefox',
        ignoreHTTPSErrors: true,
        locale: 'en-GB',
        timezoneId: 'Europe/London',

        /* Always collect trace (other values add random test failures) See https://playwright.dev/docs/trace-viewer */
        trace: 'on',
        viewport: {
            width: 1080,
            height: 720,
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
            testIgnore: ['tests/sso_*.spec.ts', 'tests/account_lifecycle.spec.ts'],
            dependencies: ['mariadb-setup'],
        },
        {
            name: 'mysql',
            testMatch: 'tests/*.spec.ts',
            testIgnore: ['tests/sso_*.spec.ts', 'tests/account_lifecycle.spec.ts'],
            dependencies: ['mysql-setup'],
        },
        {
            name: 'postgres',
            testMatch: 'tests/*.spec.ts',
            testIgnore: ['tests/sso_*.spec.ts', 'tests/account_lifecycle.spec.ts'],
            dependencies: ['postgres-setup'],
        },
        {
            name: 'sqlite',
            testMatch: 'tests/*.spec.ts',
            testIgnore: ['tests/sso_*.spec.ts', 'tests/account_lifecycle.spec.ts'],
        },

        {
            // Chromium-only project for the WebAuthn account-lifecycle spec — the rest
            // of the suite runs Firefox, but the spec uses CDP's virtual
            // authenticator (Chromium-only) and the `hmac-secret` PRF extension.
            // SQLite-backed, en locale (the bundled web vault renders different
            // labels for the WebAuthn provider row under `en_GB`).
            name: 'account-lifecycle',
            testMatch: 'tests/account_lifecycle.spec.ts',
            use: {
                browserName: 'chromium',
                locale: 'en',
                launchOptions: {
                    // Local-iteration knob: when set, point Playwright at a
                    // non-bundled Chromium binary. The docker harness has the
                    // bundled Chromium (1194) baked into the image; on a host
                    // where Playwright's `install chromium` is unsupported
                    // (e.g. Ubuntu 26.04), set this env var to your system
                    // Chromium so `npx playwright test --project=account-lifecycle`
                    // can run locally against an external Vaultwarden.
                    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
                        ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH }
                        : {}),
                },
            },
        },

        {
            // SSO variant of the account lifecycle. Same spec file, same
            // launch config; differs in `dependencies: ['sso-setup']` (brings
            // up Keycloak before the test runs) and `account_lifecycle.spec.ts`
            // detects the project name to switch its `beforeAll` env to
            // `SSO_ENABLED=true SSO_ONLY=false` and its login choreography
            // to SSO + MP-unlock.
            name: 'account-lifecycle-sso',
            testMatch: 'tests/account_lifecycle.spec.ts',
            dependencies: ['sso-setup'],
            use: {
                browserName: 'chromium',
                locale: 'en',
                launchOptions: {
                    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
                        ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH }
                        : {}),
                },
            },
        },

        {
            // Chromium project for the UI flows at the bottom of
            // `passkey.spec.ts` — one passkey behaviour per test against
            // a fresh user. Same Chromium + en-locale requirements as
            // `account-lifecycle`. `grep` filters out the request-level
            // suites at the top of the file (those run under the four
            // multi-DB Firefox projects).
            name: 'passkey-ui',
            testMatch: 'tests/passkey.spec.ts',
            grep: /Passkey UI flows/,
            use: {
                browserName: 'chromium',
                locale: 'en',
                launchOptions: {
                    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
                        ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH }
                        : {}),
                },
            },
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
