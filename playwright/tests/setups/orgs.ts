import { expect, type Browser,Page } from '@playwright/test';

import * as utils from '../../global-utils';

export async function create(test, page: Page, name: string) {
    await test.step('Create Org', async () => {
        // The product-switch nav links are icon-only (accessible name set on
        // the link, no text content), so `filter({hasText})` no longer matches
        // on the current bundled web vault — use the accessible-name role
        // selector instead.
        await page.getByRole('link', { name: 'Password Manager' }).click();
        await expect(page.getByTitle('All vaults', { exact: true })).toBeVisible();
        await page.getByRole('link', { name: 'New organisation' }).click();
        await page.getByLabel('Organisation name (required)').fill(name);
        await page.getByRole('button', { name: 'Submit' }).click();

        await utils.checkNotification(page, 'Organisation created');
    });
}

export async function policies(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} policies`, async () => {
        await page.getByRole('link', { name: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        // The org row in the switcher has a hover tooltip that intercepts the
        // click on the current bundled web vault; force-click past it.
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click({ force: true });
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.getByRole('button', { name: 'Toggle collapse Settings' }).click();
        await page.getByRole('link', { name: 'Policies' }).click();
        await expect(page.getByRole('heading', { name: 'Policies' })).toBeVisible();
    });
}

export async function members(test, page: Page, name: string) {
    await test.step(`Navigate to ${name} members`, async () => {
        await page.getByRole('link', { name: 'Admin Console' }).first().click();
        await page.locator('org-switcher').getByLabel(/Toggle collapse/).click();
        // The org row in the switcher has a hover tooltip that intercepts the
        // click on the current bundled web vault; force-click past it.
        await page.locator('org-switcher').getByRole('link', { name: `${name}` }).first().click({ force: true });
        await expect(page.getByRole('heading', { name: `${name} collections` })).toBeVisible();
        await page.getByRole('link', { name: 'Members' }).click();
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await expect(page.getByRole('cell', { name: 'All' })).toBeVisible();
    });
}

export async function invite(test, page: Page, name: string, email: string) {
    await test.step(`Invite ${email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('button', { name: 'Invite member' }).click();
        await page.getByLabel('Email (required)').fill(email);
        await page.getByRole('tab', { name: 'Collections' }).click();
        await page.getByRole('combobox', { name: 'Permission' }).click();
        await page.getByText('Edit items', { exact: true }).click();
        await page.getByLabel('Select collections').click();
        await page.getByText('Default collection').click();
        await page.getByRole('cell', { name: 'Collection', exact: true }).click();
        await page.getByRole('button', { name: 'Save' }).click();
        await utils.checkNotification(page, 'User(s) invited');
    });
}

export async function confirm(test, page: Page, name: string, user_email: string) {
    await test.step(`Confirm ${user_email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('row').filter({hasText: user_email}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Confirm' }).click();
        await expect(page.getByRole('heading', { name: 'Confirm user' })).toBeVisible();
        await page.getByRole('button', { name: 'Confirm' }).click();
        await utils.checkNotification(page, 'confirmed');
    });
}

export async function revoke(test, page: Page, name: string, user_email: string) {
    await test.step(`Revoke ${user_email}`, async () => {
        await expect(page.getByRole('heading', { name: 'Members' })).toBeVisible();
        await page.getByRole('row').filter({hasText: user_email}).getByLabel('Options').click();
        await page.getByRole('menuitem', { name: 'Revoke access' }).click();
        await expect(page.getByRole('heading', { name: 'Revoke access' })).toBeVisible();
        await page.getByRole('button', { name: 'Revoke access' }).click();
        await utils.checkNotification(page, 'Revoked organisation access');
    });
}
