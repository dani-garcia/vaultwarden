"use strict";
/* global jQuery, _post:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

function deleteOrganization(event) {
    event.preventDefault();
    event.stopPropagation();
    const org_uuid = event.target.dataset.vwOrgUuid;
    const org_name = event.target.dataset.vwOrgName;
    const billing_email = event.target.dataset.vwBillingEmail;
    if (!org_uuid) {
        alert("Required parameters not found!");
        return false;
    }

    // First make sure the user wants to delete this organization
    const continueDelete = confirm(`WARNING: All data of this organization (${org_name}) will be lost!\nMake sure you have a backup, this cannot be undone!`);
    if (continueDelete == true) {
        const input_org_uuid = prompt(`To delete the organization "${org_name} (${billing_email})", please type the organization uuid below.`);
        if (input_org_uuid != null) {
            if (input_org_uuid == org_uuid) {
                _post(`${BASE_URL}/admin/organizations/${org_uuid}/delete`,
                    "Organization deleted correctly",
                    "Error deleting organization"
                );
            } else {
                alert("Wrong organization uuid, please try again");
            }
        }
    }
}

function updateVaultTimeoutControls() {
    const enabled = document.getElementById("vault-timeout-enabled").checked;
    const timeoutType = document.getElementById("vault-timeout-type");
    const timeoutAction = document.getElementById("vault-timeout-action");
    const customFields = document.getElementById("vault-timeout-custom-fields");
    const hours = document.getElementById("vault-timeout-hours");
    const minutes = document.getElementById("vault-timeout-minutes");

    timeoutType.disabled = !enabled;
    timeoutAction.disabled = !enabled;
    const customEnabled = enabled && timeoutType.value === "custom";
    customFields.classList.toggle("d-none", !customEnabled);
    hours.disabled = !customEnabled;
    minutes.disabled = !customEnabled;

    const singleOrgEnabled = document.getElementById("org-policies-form").dataset.vwSingleOrgEnabled === "true";
    document.getElementById("vault-timeout-single-org-warning").classList.toggle("d-none", !enabled || singleOrgEnabled);
}

function loadOrganizationPolicies(event) {
    const button = event.relatedTarget;
    if (!button) {
        return;
    }

    const form = document.getElementById("org-policies-form");
    form.classList.remove("was-validated");
    form.dataset.vwSingleOrgEnabled = button.dataset.vwSingleOrgEnabled;
    document.getElementById("org-policies-org-uuid").value = button.dataset.vwOrgUuid;
    document.getElementById("org-policies-org-name").textContent = button.dataset.vwOrgName;
    document.getElementById("vault-timeout-enabled").checked = button.dataset.vwTimeoutEnabled === "true";
    document.getElementById("vault-timeout-type").value = button.dataset.vwTimeoutType || "custom";
    document.getElementById("vault-timeout-action").value = button.dataset.vwTimeoutAction || "";
    document.getElementById("disable-personal-vault-export").checked = button.dataset.vwExportDisabled === "true";

    const totalMinutes = Number.parseInt(button.dataset.vwTimeoutMinutes, 10) || 480;
    document.getElementById("vault-timeout-hours").value = Math.floor(totalMinutes / 60);
    document.getElementById("vault-timeout-minutes").value = totalMinutes % 60;
    document.getElementById("vault-timeout-minutes").setCustomValidity("");
    updateVaultTimeoutControls();
}

function saveOrganizationPolicies(event) {
    event.preventDefault();
    const form = event.target;
    const timeoutEnabled = document.getElementById("vault-timeout-enabled").checked;
    const singleOrgEnabled = form.dataset.vwSingleOrgEnabled === "true";
    if (timeoutEnabled && !singleOrgEnabled) {
        document.getElementById("vault-timeout-single-org-warning").classList.remove("d-none");
        return;
    }

    const timeoutType = document.getElementById("vault-timeout-type").value;
    const hours = Number.parseInt(document.getElementById("vault-timeout-hours").value, 10);
    const minutes = Number.parseInt(document.getElementById("vault-timeout-minutes").value, 10);
    let totalMinutes = 480;
    document.getElementById("vault-timeout-minutes").setCustomValidity("");
    if (timeoutType === "custom") {
        totalMinutes = hours * 60 + minutes;
        if (!Number.isInteger(hours) || hours < 0 || !Number.isInteger(minutes) || minutes < 0 || minutes > 59 || totalMinutes < 1) {
            document.getElementById("vault-timeout-minutes").setCustomValidity("Invalid custom timeout");
        } else {
            document.getElementById("vault-timeout-minutes").setCustomValidity("");
        }
    }

    form.classList.add("was-validated");
    if (!form.checkValidity()) {
        return;
    }

    const action = document.getElementById("vault-timeout-action").value || null;
    const body = JSON.stringify({
        maximumVaultTimeout: {
            enabled: timeoutEnabled,
            type: timeoutType,
            minutes: totalMinutes,
            action: action
        },
        disablePersonalVaultExport: document.getElementById("disable-personal-vault-export").checked
    });
    const orgUuid = document.getElementById("org-policies-org-uuid").value;
    _post(`${BASE_URL}/admin/organizations/${orgUuid}/policies`,
        "Organization policies saved correctly",
        "Error saving organization policies",
        body
    );
}

function initActions() {
    document.querySelectorAll("button[vw-delete-organization]").forEach(btn => {
        btn.addEventListener("click", deleteOrganization);
    });

    if (jdenticon) {
        jdenticon();
    }
}

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    const policiesModal = document.getElementById("orgPoliciesModal");
    policiesModal.addEventListener("show.bs.modal", loadOrganizationPolicies);
    document.getElementById("org-policies-form").addEventListener("submit", saveOrganizationPolicies);
    document.getElementById("vault-timeout-enabled").addEventListener("change", updateVaultTimeoutControls);
    document.getElementById("vault-timeout-type").addEventListener("change", updateVaultTimeoutControls);

    jQuery("#orgs-table").DataTable({
        "drawCallback": function() {
            initActions();
        },
        "stateSave": true,
        "responsive": true,
        "lengthMenu": [
            [-1, 5, 10, 25, 50],
            ["All", 5, 10, 25, 50]
        ],
        "pageLength": -1, // Default show all
        "columnDefs": [{
            "targets": [4,5],
            "searchable": false,
            "orderable": false
        }]
    });

    // Add click events for organization actions
    initActions();

    const btnReload = document.getElementById("reload");
    if (btnReload) {
        btnReload.addEventListener("click", reload);
    }
});
