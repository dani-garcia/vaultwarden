"use strict";
/* global _post:readable, BASE_URL:readable, qrcode:readable */

const ADMIN_TOTP_SECRET_BYTES = 20;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
let generatedAdminTotpSecret = null;

function encodeBase32(bytes) {
    let output = "";
    let buffer = 0;
    let bits = 0;

    bytes.forEach(byte => {
        buffer = (buffer << 8) | byte;
        bits += 8;

        while (bits >= 5) {
            bits -= 5;
            output += BASE32_ALPHABET[(buffer >>> bits) & 31];
        }
        buffer &= (1 << bits) - 1;
    });

    if (bits > 0) {
        output += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
    }
    return output;
}

function buildAdminTotpUri(secret) {
    const issuer = "Vaultwarden";
    const account = "Admin";
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
    return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}` +
        "&algorithm=SHA1&digits=6&period=30";
}

function resetAdminTotpQrDialog() {
    generatedAdminTotpSecret = null;

    const secretOutput = document.getElementById("adminTotpQrSecret");
    const qrImage = document.getElementById("adminTotpQrCode");
    const error = document.getElementById("adminTotpQrError");
    const useButton = document.getElementById("adminTotpQrUse");

    secretOutput.value = "";
    qrImage.removeAttribute("src");
    qrImage.classList.add("d-none");
    error.textContent = "";
    error.classList.add("d-none");
    useButton.disabled = true;
}

function showAdminTotpQrError(message) {
    const error = document.getElementById("adminTotpQrError");
    error.textContent = message;
    error.classList.remove("d-none");
}

function generateAdminTotpQr() {
    resetAdminTotpQrDialog();

    if (!window.crypto || typeof window.crypto.getRandomValues !== "function") {
        showAdminTotpQrError("Secure random number generation is not available in this browser.");
        return;
    }
    if (typeof qrcode !== "function") {
        showAdminTotpQrError("The local QR code generator could not be loaded.");
        return;
    }

    const randomBytes = new Uint8Array(ADMIN_TOTP_SECRET_BYTES);
    let secret;
    try {
        window.crypto.getRandomValues(randomBytes);
        secret = encodeBase32(randomBytes);
    } catch (_error) {
        showAdminTotpQrError("Unable to generate a secure TOTP secret in this browser.");
        return;
    } finally {
        randomBytes.fill(0);
    }

    try {
        const qr = qrcode(0, "M");
        qr.addData(buildAdminTotpUri(secret), "Byte");
        qr.make();

        generatedAdminTotpSecret = secret;
        document.getElementById("adminTotpQrSecret").value = secret;
        const qrImage = document.getElementById("adminTotpQrCode");
        qrImage.src = qr.createDataURL(5, 20);
        qrImage.classList.remove("d-none");
        document.getElementById("adminTotpQrUse").disabled = false;
    } catch (_error) {
        resetAdminTotpQrDialog();
        showAdminTotpQrError("Unable to create the QR code in this browser.");
    }
}

function regenerateAdminTotpQr() {
    if (generatedAdminTotpSecret &&
        !confirm("Generate a different secret? If you already scanned this QR code, you will need to scan the new one.")) {
        return;
    }
    generateAdminTotpQr();
}

function useGeneratedAdminTotpSecret() {
    if (!generatedAdminTotpSecret) {
        return;
    }

    const input = document.getElementById("input_admin_totp_secret");
    const clear = document.querySelector('[data-vw-clear-target="input_admin_totp_secret"]');
    input.disabled = false;
    input.value = generatedAdminTotpSecret;
    if (clear) {
        clear.checked = false;
    }
    input.dispatchEvent(new Event("input", { bubbles: true }));
}

function smtpTest(event) {
    event.preventDefault();
    event.stopPropagation();
    if (formHasChanges(config_form)) {
        alert("Config has been changed but not yet saved.\nPlease save the changes first before sending a test email.");
        return false;
    }

    const test_email = document.getElementById("smtp-test-email");

    // Do a very very basic email address check.
    if (test_email.value.match(/\S+@\S+/i) === null) {
        test_email.parentElement.classList.add("was-validated");
        return false;
    }

    const data = JSON.stringify({ "email": test_email.value });
    _post(`${BASE_URL}/admin/test/smtp`,
        "SMTP Test email sent correctly",
        "Error sending SMTP test email",
        data, false
    );
}

function getFormData() {
    let data = {};

    document.querySelectorAll(".conf-checkbox").forEach(function (e) {
        data[e.name] = e.checked;
    });

    document.querySelectorAll(".conf-number").forEach(function (e) {
        data[e.name] = e.value ? +e.value : null;
    });

    document.querySelectorAll(".conf-text, .conf-password").forEach(function (e) {
        data[e.name] = e.value || null;
    });

    document.querySelectorAll(".conf-write-only").forEach(function (e) {
        const clear = document.querySelector(`[data-vw-clear-target="${e.id}"]`);
        if (clear && clear.checked) {
            // An explicit empty string removes the saved config value.
            data[e.name] = "";
        } else if (e.value.trim()) {
            // Omitting an untouched write-only field keeps the currently saved value.
            data[e.name] = e.value.trim();
        }
    });
    return data;
}

function saveConfig(event) {
    const data = JSON.stringify(getFormData());
    _post(`${BASE_URL}/admin/config`,
        "Config saved correctly",
        "Error saving config",
        data
    );
    event.preventDefault();
}

function deleteConf(event) {
    event.preventDefault();
    event.stopPropagation();
    const input = prompt(
        "This will remove all user configurations, and restore the defaults and the " +
        "values set by the environment. This operation could be dangerous. Type 'DELETE' to proceed:"
    );
    if (input === "DELETE") {
        _post(`${BASE_URL}/admin/config/delete`,
            "Config deleted correctly",
            "Error deleting config"
        );
    } else {
        alert("Wrong input, please try again");
    }
}

function backupDatabase(event) {
    event.preventDefault();
    event.stopPropagation();
    _post(`${BASE_URL}/admin/config/backup_db`,
        "Backup created successfully",
        "Error creating backup", null, false
    );
}

// Two functions to help check if there were changes to the form fields
// Useful for example during the smtp test to prevent people from clicking save before testing there new settings
function initChangeDetection(form) {
    const ignore_fields = ["smtp-test-email"];
    Array.from(form).forEach((el) => {
        if (! ignore_fields.includes(el.id)) {
            el.dataset.origValue = el.value;
        }
    });
}

function formHasChanges(form) {
    return Array.from(form).some(el => "origValue" in el.dataset && ( el.dataset.origValue !== el.value));
}

// This function will prevent submitting a from when someone presses enter.
function preventFormSubmitOnEnter(form) {
    if (form) {
        form.addEventListener("keypress", (event) => {
            if (event.key == "Enter") {
                event.preventDefault();
            }
        });
    }
}

// This function will hook into the smtp-test-email input field and will call the smtpTest() function when enter is pressed.
function submitTestEmailOnEnter() {
    const smtp_test_email_input = document.getElementById("smtp-test-email");
    if (smtp_test_email_input) {
        smtp_test_email_input.addEventListener("keypress", (event) => {
            if (event.key == "Enter") {
                event.preventDefault();
                smtpTest(event);
            }
        });
    }
}

// Colorize some settings which are high risk
function colorRiskSettings() {
    const risk_items = document.getElementsByClassName("col-form-label");
    Array.from(risk_items).forEach((el) => {
        if (el.textContent.toLowerCase().includes("risks") ) {
            el.parentElement.className += " alert-danger";
        }
    });
}

function toggleVis(event) {
    event.preventDefault();
    event.stopPropagation();

    const elem = document.getElementById(event.target.dataset.vwPwToggle);
    const type = elem.getAttribute("type");
    if (type === "text") {
        elem.setAttribute("type", "password");
    } else {
        elem.setAttribute("type", "text");
    }
}

function toggleWriteOnlyClear(event) {
    const input = document.getElementById(event.target.dataset.vwClearTarget);
    input.disabled = event.target.checked;
    if (event.target.checked) {
        input.value = "";
    }
}

function masterCheck(check_id, inputs_query) {
    function onChanged(checkbox, inputs_query) {
        return function _fn() {
            document.querySelectorAll(inputs_query).forEach(function (e) { e.disabled = !checkbox.checked; });
            checkbox.disabled = false;
        };
    }

    const checkbox = document.getElementById(check_id);
    if (checkbox) {
        const onChange = onChanged(checkbox, inputs_query);
        onChange(); // Trigger the event initially
        checkbox.addEventListener("change", onChange);
    }
}

// This will check if the ADMIN_TOKEN is not a Argon2 hashed value.
// Else it will show a warning, unless someone has closed it.
// Then it will not show this warning for 30 days.
function checkAdminToken() {
    const admin_token = document.getElementById("input_admin_token");
    const disable_admin_token = document.getElementById("input_disable_admin_token");
    if (!disable_admin_token.checked && !admin_token.value.startsWith("$argon2")) {
        // Check if the warning has been closed before and 30 days have passed
        const admin_token_warning_closed = localStorage.getItem("admin_token_warning_closed");
        if (admin_token_warning_closed !== null) {
            const closed_date = new Date(parseInt(admin_token_warning_closed));
            const current_date = new Date();
            const thirtyDays = 1000*60*60*24*30;
            if (current_date - closed_date < thirtyDays) {
                return;
            }
        }

        // When closing the alert, store the current date/time in the browser
        const admin_token_warning = document.getElementById("admin_token_warning");
        admin_token_warning.addEventListener("closed.bs.alert", function() {
            const d = new Date();
            localStorage.setItem("admin_token_warning_closed", d.getTime());
        });

        // Display the warning
        admin_token_warning.classList.remove("d-none");
    }
}

// This will check for specific configured values, and when needed will show a warning div
function showWarnings() {
    checkAdminToken();
}

const config_form = document.getElementById("config-form");

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    initChangeDetection(config_form);
    // Prevent enter to submitting the form and save the config.
    // Users need to really click on save, this also to prevent accidental submits.
    preventFormSubmitOnEnter(config_form);

    submitTestEmailOnEnter();
    colorRiskSettings();

    document.querySelectorAll("input[id^='input__enable_']").forEach(group_toggle => {
        const input_id = group_toggle.id.replace("input__enable_", "#g_");
        masterCheck(group_toggle.id, `${input_id} input`);
    });

    document.querySelectorAll("button[data-vw-pw-toggle]").forEach(password_toggle_btn => {
        password_toggle_btn.addEventListener("click", toggleVis);
    });

    document.querySelectorAll("input[data-vw-clear-target]").forEach(clear_checkbox => {
        clear_checkbox.addEventListener("change", toggleWriteOnlyClear);
    });

    const adminTotpQrDialog = document.getElementById("adminTotpQrDialog");
    if (adminTotpQrDialog) {
        adminTotpQrDialog.addEventListener("show.bs.modal", generateAdminTotpQr);
        adminTotpQrDialog.addEventListener("hidden.bs.modal", resetAdminTotpQrDialog);
        document.getElementById("adminTotpQrRegenerate").addEventListener("click", regenerateAdminTotpQr);
        document.getElementById("adminTotpQrUse").addEventListener("click", useGeneratedAdminTotpSecret);
    }

    const btnBackupDatabase = document.getElementById("backupDatabase");
    if (btnBackupDatabase) {
        btnBackupDatabase.addEventListener("click", backupDatabase);
    }
    const btnDeleteConf = document.getElementById("deleteConf");
    if (btnDeleteConf) {
        btnDeleteConf.addEventListener("click", deleteConf);
    }
    const btnSmtpTest = document.getElementById("smtpTest");
    if (btnSmtpTest) {
        btnSmtpTest.addEventListener("click", smtpTest);
    }

    config_form.addEventListener("submit", saveConfig);

    showWarnings();
});
