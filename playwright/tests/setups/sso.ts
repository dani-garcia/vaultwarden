import { expect, type Page, Test } from '@playwright/test';
import { type Mail } from 'maildev';

export async function createAccount(test: Test, page: Page, user: { email: string, name: string, password: string }, emails: AsyncIterator<Mail>) {
    await test.step('Create user', async () => {
        await test.step('Landing page', async () => {
            await page.goto('/');
            await page.getByLabel(/Email address/).fill(user.email);
            await page.getByRole('button', { name: 'Continue' }).click();
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
            await expect(page).toHaveTitle(/Vaults/);
        });

        if( emails ){
            await test.step('Check emails', async () => {
                const { value: logged } = await emails.next();
                expect(logged.subject).toContain("New Device Logged");

                const { value: password } = await emails.next();
                expect(password.subject).toContain("Master Password Has Been Changed");
            });
        }
    });
}

export async function logUser(test: Test, page: Page, user: { email: string, password: string }, emails: AsyncIterator<Mail>) {
    await test.step('Log user', async () => {
        await test.step('Landing page', async () => {
            await page.goto('/');
            await page.getByLabel(/Email address/).fill(user.email);
            await page.getByRole('button', { name: 'Continue' }).click();
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
            await page.getByLabel('Master password').fill(user.password);
            await page.getByRole('button', { name: 'Unlock' }).click();
        });

        await test.step('Default vault page', async () => {
            await expect(page).toHaveTitle(/Vaults/);
        });

        if( emails ){
            await test.step('Check email', async () => {
                const { value: logged } = await emails.next();
                expect(logged.subject).toContain("New Device Logged");
            });
        }
    });
}
