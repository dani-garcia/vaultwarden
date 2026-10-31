"use strict";
/* global DataTable, _post:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

const tOrgs = key => (window.VW_ADMIN_I18N && window.VW_ADMIN_I18N[key]) || key;

function deleteOrganization(event) {
    event.preventDefault();
    event.stopPropagation();
    const org_uuid = event.target.dataset.vwOrgUuid;
    const org_name = event.target.dataset.vwOrgName;
    const billing_email = event.target.dataset.vwBillingEmail;
    if (!org_uuid) {
        alert(tOrgs("required_params_not_found"));
        return false;
    }

    // First make sure the user wants to delete this organization
    const continueDelete = confirm(`${tOrgs("warn_delete_org_prefix")} (${org_name}) ${tOrgs("warn_delete_org_suffix")}`);
    if (continueDelete == true) {
        const input_org_uuid = prompt(`${tOrgs("prompt_delete_org_prefix")} "${org_name} (${billing_email})", ${tOrgs("prompt_type_org_uuid")}`);
        if (input_org_uuid != null) {
            if (input_org_uuid == org_uuid) {
                _post(`${BASE_URL}/admin/organizations/${org_uuid}/delete`,
                    tOrgs("org_delete_ok"),
                    tOrgs("org_delete_error")
                );
            } else {
                alert(tOrgs("wrong_org_uuid_retry"));
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
document.addEventListener("DOMContentLoaded", async (/*event*/) => {
    if (window.VW_ADMIN_I18N_READY) {
        await window.VW_ADMIN_I18N_READY;
    }

    const columnCount = document.getElementById("orgs-table").querySelectorAll("thead th").length;
    new DataTable("#orgs-table", {
        "drawCallback": function () {
            initActions();
        },
        "language": {
            "search": tOrgs("datatable_search"),
            "emptyTable": tOrgs("datatable_empty_table"),
            "info": tOrgs("datatable_info"),
            "infoEmpty": tOrgs("datatable_info_empty"),
            "infoFiltered": tOrgs("datatable_info_filtered"),
            "lengthMenu": tOrgs("datatable_length_menu"),
            "loadingRecords": tOrgs("datatable_loading_records"),
            "processing": tOrgs("datatable_processing"),
            "zeroRecords": tOrgs("datatable_zero_records"),
            "paginate": {
                "first": tOrgs("datatable_paginate_first"),
                "last": tOrgs("datatable_paginate_last"),
                "next": tOrgs("datatable_paginate_next"),
                "previous": tOrgs("datatable_paginate_previous")
            },
            "aria": {
                "orderable": tOrgs("datatable_aria_orderable"),
                "orderableReverse": tOrgs("datatable_aria_orderable_reverse")
            }
        },
        "stateSave": true,
        "responsive": true,
        "lengthMenu": [
            [-1, 5, 10, 25, 50],
            [tOrgs("datatable_all"), 5, 10, 25, 50]
        ],
        "pageLength": -1, // Default show all
        "columnDefs": [{
            "targets": [columnCount - 2, columnCount - 1], // Do not include the last two columns into the search/order features
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
