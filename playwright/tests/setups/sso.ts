import { expect, type Page, Test } from '@playwright/test';
import { type MailBuffer, MailServer } from 'maildev';

/**
 * If a MailBuffer is passed it will be used and consume the expected emails
 */
export async function logNewUser(
    test: Test,
    page: Page,
    user: { email: string, name: string, password: string },
    options: { mailBuffer?: MailBuffer, mailServer?: MailServer } = {}
) {
    let mailBuffer = options.mailBuffer ?? options.mailServer?.buffer(user.email);
    try {
        await test.step('Create user', async () => {
            await test.step('Landing page', async () => {
                await page.goto('/');
                await page.getByLabel(/Email address/).fill(user.email);
                await page.getByRole('button', 'Continue').click();
            });

            await test.step('SSo start page', async () => {
                await page.getByRole('link', { name: /Enterprise single sign-on/ }).click();
            });

            await test.step('Keycloak login', async () => {
                await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
                await page.getByLabel(/Username/).fill(user.name);
                await page.getByLabel('Password', { exact: true }).fill(user.password);
                await page.getByRole('button', { name: 'Sign In' }).click();
            });

            await test.step('Create Vault account', async () => {
                await expect(page.getByText('Set master password')).toBeVisible();
                await page.getByLabel('Master password', { exact: true }).fill(user.password);
                await page.getByLabel('Re-type master password').fill(user.password);
                await page.getByRole('button', { name: 'Submit' }).click();
            });

            await test.step('Default vault page', async () => {
                await expect(page).toHaveTitle(/Vaultwarden Web/);
                await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
            });

            if( mailBuffer ){
                await test.step('Check emails', async () => {
                    await expect(mailBuffer.next((m) => m.subject.includes("New Device Logged"))).resolves.toBeDefined();
                    await expect(mailBuffer.next((m) => m.subject === "Master Password Has Been Changed")).resolves.toBeDefined();
                });
            }
        });
    } finally {
        if( options.mailServer ){
            mailBuffer.close();
        }
    }
}

/**
 * If a MailBuffer is passed it will be used and consume the expected emails
 */
export async function logUser(
    test: Test,
    page: Page,
    user: { email: string, password: string },
    options: { mailBuffer ?: MailBuffer, mailServer?: MailServer} = {}
) {
    let mailBuffer = options.mailBuffer ?? options.mailServer?.buffer(user.email);
    try {
        await test.step('Log user', async () => {
            await test.step('Landing page', async () => {
                await page.goto('/');
                await page.getByLabel(/Email address/).fill(user.email);
                await page.getByRole('button', 'Continue').click();
            });

            await test.step('SSo start page', async () => {
                await page.getByRole('link', { name: /Enterprise single sign-on/ }).click();
            });

            await test.step('Keycloak login', async () => {
                await expect(page.getByRole('heading', { name: 'Sign in to your account' })).toBeVisible();
                await page.getByLabel(/Username/).fill(user.name);
                await page.getByLabel('Password', { exact: true }).fill(user.password);
                await page.getByRole('button', { name: 'Sign In' }).click();
            });

            await test.step('Unlock vault', async () => {
                await expect(page).toHaveTitle('Vaultwarden Web');
                await expect(page.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible();
                await page.getByLabel('Master password').fill(user.password);
                await page.getByRole('button', { name: 'Unlock' }).click();
            });

            await test.step('Default vault page', async () => {
                await expect(page).toHaveTitle(/Vaultwarden Web/);
                await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
            });

            if( options.emails ){
                await test.step('Check email', async () => {
                    await expect(mailBuffer.next((m) => m.subject.includes("New Device Logged"))).resolves.toBeDefined();
                });
            }
        });
    } finally {
        if( options.mailServer ){
            mailBuffer.close();
        }
    }
}
