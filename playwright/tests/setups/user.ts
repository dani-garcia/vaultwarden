import { expect, type Browser,Page } from '@playwright/test';

export async function createAccount(test, page: Page, user: { email: string, name: string, password: string }, emails) {
    await test.step('Create user', async () => {
        // Landing page
        await page.goto('/');
        await page.getByRole('link', { name: 'Create account' }).click();

        // Back to Vault create account
        await expect(page).toHaveTitle(/Create account | Vaultwarden Web/);
        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByLabel('Name').fill(user.name);
        await page.getByLabel('Master password\n   (required)', { exact: true }).fill(user.password);
        await page.getByLabel('Re-type master password').fill(user.password);
        await page.getByRole('button', { name: 'Create account' }).click();

        // Back to the login page
        await expect(page).toHaveTitle('Vaultwarden Web');
        await expect(page.getByTestId("toast-message")).toHaveText(/Your new account has been created/);

        if( emails ){
            const { value: welcome } = await emails.next();
            expect(welcome.subject).toContain("Welcome");
        }
    });
}

export async function logUser(test, page: Page, user: { email: string, password: string }, emails) {
    await test.step('Log user', async () => {
        // Landing page
        await page.goto('/');
        await page.getByLabel(/Email address/).fill(user.email);
        await page.getByRole('button', { name: 'Continue' }).click();

        // Unlock page
        await page.getByLabel('Master password').fill(user.password);
        await page.getByRole('button', { name: 'Log in with master password' }).click();

        // We are now in the default vault page
        await expect(page).toHaveTitle(/Vaultwarden Web/);

        if( emails ){
            const { value: logged } = await emails.next();
            expect(logged.subject).toContain("New Device Logged");
        }
    });
}
