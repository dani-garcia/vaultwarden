"use strict";
/* eslint-env es2017, browser, jquery */
/* global _post:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

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
            "targets": 4,
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