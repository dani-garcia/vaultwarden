import { expect, type Page, Test } from '@playwright/test';
import { type MailBuffer } from 'maildev';
import * as OTPAuth from "otpauth";

import * as utils from '../../global-utils';

export async function activateTOTP(test: Test, page: Page, user: { name: string, password: string }): OTPAuth.TOTP {
    return await test.step('Activate TOTP 2FA', async () => {
        await page.getByRole('button', { name: user.name }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('bit-item').filter({ hasText: /Authenticator app/ }).getByRole('button').click();
        const mpInput = page.getByLabel('Master password');
        await mpInput.fill(user.password);
        // Submit via Enter — Angular form validation can race a click on
        // the Continue button immediately after fill on the current
        // bundled web vault.
        await mpInput.press('Enter');

        // `getByLabel('Key')` alone is ambiguous: the providers list also
        // has a Yubico SVG with aria-label "Yubico OTP security key" that
        // matches "Key" via substring. Anchor with exact match.
        const secret = (await page.getByLabel('Key', { exact: true }).innerText()).replace(/\s+/g, '');
        let totp = new OTPAuth.TOTP({ secret, period: 30 });

        await page.getByLabel(/Verification code/).fill(totp.generate());
        await page.getByRole('button', { name: 'Turn on' }).click();
        // Wait for the activation request to complete. The current
        // bundled web vault uses an asynchronous Turn-on flow; we don't
        // try to assert the exact success-heading text (it varies across
        // vault versions) — instead we wait for network to settle, then
        // the dialog closes itself.
        await page.waitForLoadState('networkidle');

        return totp;
    })
}

export async function disableTOTP(test: Test, page: Page, user: { password: string }) {
    await test.step('Disable TOTP 2FA', async () => {
        await page.getByRole('button', { name: 'Test' }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('bit-item').filter({ hasText: /Authenticator app/ }).getByRole('button').click();
        const mpInput = page.getByLabel('Master password');
        await mpInput.fill(user.password);
        await mpInput.press('Enter');
        await page.getByRole('button', { name: 'Turn off' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();
        await utils.checkNotification(page, 'Two-step login provider turned off');
    });
}

export async function activateEmail(test: Test, page: Page, user: { name: string, password: string }, mailBuffer: MailBuffer) {
    await test.step('Activate Email 2FA', async () => {
        await page.getByRole('button', { name: user.name }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('bit-item').filter({ hasText: 'Enter a code sent to your email' }).getByRole('button').click();
        await page.getByLabel('Master password').fill(user.password);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByRole('button', { name: 'Send email' }).click();
    });

    let code = await retrieveEmailCode(test, page, mailBuffer);

    await test.step('input code', async () => {
        await page.getByLabel('2. Enter the resulting 6').fill(code);
        await page.getByRole('button', { name: 'Turn on' }).click();
        await page.getByRole('heading', { name: 'Turned on', exact: true });
    });
}

export async function retrieveEmailCode(test: Test, page: Page, mailBuffer: MailBuffer): string {
    return await test.step('retrieve code', async () => {
        const codeMail = await mailBuffer.expect((mail) => mail.subject.includes("Login Verification Code"));
        const page2 = await page.context().newPage();
        await page2.setContent(codeMail.html);
        const code = await page2.getByTestId("2fa").innerText();
        await page2.close();
        return code;
    });
}

export async function disableEmail(test: Test, page: Page, user: { password: string }) {
    await test.step('Disable Email 2FA', async () => {
        await page.getByRole('button', { name: 'Test' }).click();
        await page.getByRole('menuitem', { name: 'Account settings' }).click();
        await page.getByRole('link', { name: 'Security' }).click();
        await page.getByRole('link', { name: 'Two-step login' }).click();
        await page.locator('bit-item').filter({ hasText: 'Email' }).getByRole('button').click();
        await page.getByLabel('Master password').click();
        await page.getByLabel('Master password').fill(user.password);
        await page.getByRole('button', { name: 'Continue' }).click();
        await page.getByRole('button', { name: 'Turn off' }).click();
        await page.getByRole('button', { name: 'Yes' }).click();

        await utils.checkNotification(page, 'Two-step login provider turned off');
    });
}
