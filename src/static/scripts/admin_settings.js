"use strict";
/* eslint-env es2017, browser */
/* global _post:readable, BASE_URL:readable */

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
    _post(`${BASE_URL}/admin/test/smtp/`,
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
    return data;
}

function saveConfig(event) {
    const data = JSON.stringify(getFormData());
    _post(`${BASE_URL}/admin/config/`,
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
        if (el.innerText.toLowerCase().includes("risks") ) {
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