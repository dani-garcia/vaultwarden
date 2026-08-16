import { expect, type Browser, Page } from '@playwright/test';
import * as utils from '../../global-utils';

utils.loadEnv();

export async function login(test, page: Page) {
    await test.step(`Admin login`, async () => {
        await page.goto('/admin');
        await page.getByRole('textbox', { name: 'Enter admin token' }).fill(process.env.ADMIN_TOKEN);
        await page.getByRole('button', { name: 'Enter' }).click();
    });
}

export async function invite(test, page: Page, email: string) {
    await test.step(`Invite user with ${email}`, async () => {
        await page.getByRole('link', { name: 'Users' }).click();
        await page.getByRole('textbox', { name: 'Enter email' }).fill(email);
        await page.getByRole('button', { name: 'Invite' }).click();
        await expect(page.getByRole('row', { name: email })).toHaveText(/Invited/);
    });
}
