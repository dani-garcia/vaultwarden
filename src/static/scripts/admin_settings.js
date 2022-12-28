"use strict";

function smtpTest() {
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

function saveConfig() {
    const data = JSON.stringify(getFormData());
    _post(`${BASE_URL}/admin/config/`,
        "Config saved correctly",
        "Error saving config",
        data
    );
    event.preventDefault();
}

function deleteConf() {
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

function backupDatabase() {
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
    form.onkeypress = function(e) {
        const key = e.charCode || e.keyCode || 0;
        if (key == 13) {
            e.preventDefault();
        }
    };
}

// This function will hook into the smtp-test-email input field and will call the smtpTest() function when enter is pressed.
function submitTestEmailOnEnter() {
    const smtp_test_email_input = document.getElementById("smtp-test-email");
    smtp_test_email_input.onkeypress = function(e) {
        const key = e.charCode || e.keyCode || 0;
        if (key == 13) {
            e.preventDefault();
            smtpTest();
        }
    };
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

function toggleVis(evt) {
    event.preventDefault();
    event.stopPropagation();

    const elem = document.getElementById(evt.target.dataset.vwPwToggle);
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
    const onChange = onChanged(checkbox, inputs_query);
    onChange(); // Trigger the event initially
    checkbox.addEventListener("change", onChange);
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

    document.getElementById("backupDatabase").addEventListener("click", backupDatabase);
    document.getElementById("deleteConf").addEventListener("click", deleteConf);
    document.getElementById("smtpTest").addEventListener("click", smtpTest);

    config_form.addEventListener("submit", saveConfig);
});