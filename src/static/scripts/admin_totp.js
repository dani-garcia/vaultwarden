"use strict";
/* eslint-env es2017, browser */
/* global BASE_URL:readable, _post:readable */

function totpGenerate() {
    fetch(`${BASE_URL}/totp/generate`, {
        method: "POST",
        mode: "same-origin",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
    }).then(resp => {
        if (!resp.ok) {
            return resp.text().then(body => Promise.reject(body));
        }
        return resp.json();
    }).then(data => {
        const enroll = document.getElementById("totp-enroll");
        enroll.dataset.secret = data.secret;
        document.getElementById("totp-qr").innerHTML = data.qr_svg;
        document.getElementById("totp-secret").textContent = data.secret;
        enroll.classList.remove("d-none");
        document.getElementById("totp-generate").textContent = "Generate a new secret";
        document.getElementById("totp-enable-code").focus();
    }).catch(e => {
        alert(`Failed to generate a TOTP secret\n${e}`);
    });
}

function totpEnable() {
    const secret = document.getElementById("totp-enroll").dataset.secret;
    const code = document.getElementById("totp-enable-code").value.trim();
    if (!code) {
        alert("Please enter the 6-digit code from your authenticator app");
        return;
    }
    _post(`${BASE_URL}/totp/enable`,
        "2FA for the admin page is now enabled",
        "Failed to enable 2FA",
        JSON.stringify({ secret, code })
    );
}

function totpDisable() {
    const code = document.getElementById("totp-disable-code").value.trim();
    if (!code) {
        alert("Please enter the current 6-digit code from your authenticator app");
        return;
    }
    if (!confirm("Really disable two-factor authentication for the admin page?")) {
        return;
    }
    _post(`${BASE_URL}/totp/disable`,
        "2FA for the admin page is now disabled",
        "Failed to disable 2FA",
        JSON.stringify({ code })
    );
}

document.addEventListener("DOMContentLoaded", (/*event*/) => {
    document.getElementById("totp-generate")?.addEventListener("click", totpGenerate);
    document.getElementById("totp-enable")?.addEventListener("click", totpEnable);
    document.getElementById("totp-disable")?.addEventListener("click", totpDisable);
});
