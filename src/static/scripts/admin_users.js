"use strict";
/* global DataTable, _post:readable, _delete:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

const tUsers = key => (window.VW_ADMIN_I18N && window.VW_ADMIN_I18N[key]) || key;

function deleteUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert(tUsers("required_params_not_found"));
        return false;
    }
    const input_email = prompt(`${tUsers("prompt_delete_user_prefix")} "${email}", ${tUsers("prompt_type_email_below")}`);
    if (input_email != null) {
        if (input_email == email) {
            _post(`${BASE_URL}/admin/users/${id}/delete`,
                tUsers("user_deleted_ok"),
                tUsers("user_deleted_error")
            );
        } else {
            alert(tUsers("wrong_email_retry"));
        }
    }
}

function deleteSSOUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert(tUsers("required_params_not_found"));
        return false;
    }
    const input_email = prompt(`${tUsers("prompt_delete_user_sso_prefix")} "${email}" ${tUsers("prompt_delete_user_sso_suffix")}`);
    if (input_email != null) {
        if (input_email == email) {
            _delete(`${BASE_URL}/admin/users/${id}/sso`,
                tUsers("user_sso_deleted_ok"),
                tUsers("user_sso_deleted_error")
            );
        } else {
            alert(tUsers("wrong_email_retry"));
        }
    }
}

function remove2fa(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert(tUsers("required_params_not_found"));
        return false;
    }
    const confirmed = confirm(`${tUsers("confirm_remove_2fa_prefix")} "${email}"?`);
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/remove-2fa`,
            tUsers("remove_2fa_ok"),
            tUsers("remove_2fa_error")
        );
    }
}

function deauthUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert(tUsers("required_params_not_found"));
        return false;
    }
    const confirmed = confirm(`${tUsers("confirm_deauth_prefix")} "${email}"?`);
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/deauth`,
            tUsers("deauth_ok"),
            tUsers("deauth_error")
        );
    }
}

function disableUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert(tUsers("required_params_not_found"));
        return false;
    }
    const confirmed = confirm(`${tUsers("confirm_disable_user_prefix")} "${email}"? ${tUsers("confirm_disable_user_suffix")}`);
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/disable`,
            tUsers("user_disable_ok"),
            tUsers("user_disable_error")
        );
    }
}

function enableUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert(tUsers("required_params_not_found"));
        return false;
    }
    const confirmed = confirm(`${tUsers("confirm_enable_user_prefix")} "${email}"?`);
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/enable`,
            tUsers("user_enable_ok"),
            tUsers("user_enable_error")
        );
    }
}

function updateRevisions(event) {
    event.preventDefault();
    event.stopPropagation();
    _post(`${BASE_URL}/admin/users/update_revision`,
        tUsers("sync_clients_ok"),
        tUsers("sync_clients_error")
    );
}

function inviteUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const email = document.getElementById("inviteEmail");
    const data = JSON.stringify({
        "email": email.value
    });
    email.value = "";
    _post(`${BASE_URL}/admin/invite`,
        tUsers("invite_user_ok"),
        tUsers("invite_user_error"),
        data
    );
}

function resendUserInvite(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert(tUsers("required_params_not_found"));
        return false;
    }
    const confirmed = confirm(`${tUsers("confirm_resend_invite_prefix")} "${email}"?`);
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/invite/resend`,
            tUsers("resend_invite_ok"),
            tUsers("resend_invite_error")
        );
    }
}

const ORG_TYPES = {
    "0": {
        "name": tUsers("role_owner"),
        "bg": "orange",
        "font": "black"
    },
    "1": {
        "name": tUsers("role_admin"),
        "bg": "blueviolet"
    },
    "2": {
        "name": tUsers("role_user"),
        "bg": "blue"
    },
    "4": {
        "name": tUsers("role_manager"),
        "bg": "green"
    },
};

const userOrgTypeDialog = document.getElementById("userOrgTypeDialog");
// Fill the form and title
userOrgTypeDialog.addEventListener("show.bs.modal", function (event) {
    // Get shared values
    const userEmail = event.relatedTarget.parentNode.dataset.vwUserEmail;
    const userUuid = event.relatedTarget.parentNode.dataset.vwUserUuid;
    // Get org specific values
    const userOrgType = event.relatedTarget.dataset.vwOrgType;
    const userOrgTypeName = ORG_TYPES[userOrgType]["name"];
    const orgName = event.relatedTarget.dataset.vwOrgName;
    const orgUuid = event.relatedTarget.dataset.vwOrgUuid;

    document.getElementById("userOrgTypeDialogOrgName").textContent = orgName;
    document.getElementById("userOrgTypeDialogUserEmail").textContent = userEmail;
    document.getElementById("userOrgTypeUserUuid").value = userUuid;
    document.getElementById("userOrgTypeOrgUuid").value = orgUuid;
    document.getElementById(`userOrgType${userOrgTypeName}`).checked = true;
}, false);

// Prevent accidental submission of the form with valid elements after the modal has been hidden.
userOrgTypeDialog.addEventListener("hide.bs.modal", function () {
    document.getElementById("userOrgTypeDialogOrgName").textContent = "";
    document.getElementById("userOrgTypeDialogUserEmail").textContent = "";
    document.getElementById("userOrgTypeUserUuid").value = "";
    document.getElementById("userOrgTypeOrgUuid").value = "";
}, false);

function updateUserOrgType(event) {
    event.preventDefault();
    event.stopPropagation();

    const data = JSON.stringify(Object.fromEntries(new FormData(event.target).entries()));

    _post(`${BASE_URL}/admin/users/org_type`,
        tUsers("user_org_type_update_ok"),
        tUsers("user_org_type_update_error"),
        data
    );
}

function initUserTable() {
    // Color all the org buttons per type
    document.querySelectorAll("button[data-vw-org-type]").forEach(function (e) {
        const orgType = ORG_TYPES[e.dataset.vwOrgType];
        e.style.backgroundColor = orgType.bg;
        if (orgType.font !== undefined) {
            e.style.color = orgType.font;
        }
        e.title = orgType.name;
    });

    document.querySelectorAll("button[vw-remove2fa]").forEach(btn => {
        btn.addEventListener("click", remove2fa);
    });
    document.querySelectorAll("button[vw-deauth-user]").forEach(btn => {
        btn.addEventListener("click", deauthUser);
    });
    document.querySelectorAll("button[vw-delete-user]").forEach(btn => {
        btn.addEventListener("click", deleteUser);
    });
    document.querySelectorAll("button[vw-delete-sso-user]").forEach(btn => {
        btn.addEventListener("click", deleteSSOUser);
    });
    document.querySelectorAll("button[vw-disable-user]").forEach(btn => {
        btn.addEventListener("click", disableUser);
    });
    document.querySelectorAll("button[vw-enable-user]").forEach(btn => {
        btn.addEventListener("click", enableUser);
    });
    document.querySelectorAll("button[vw-resend-user-invite]").forEach(btn => {
        btn.addEventListener("click", resendUserInvite);
    });

    if (jdenticon) {
        jdenticon();
    }
}

// Special sort function to sort dates in ISO format and have anything else as 0
DataTable.ext.type.order["date-iso-pre"] = function (a) {
    let x;
    const sortDate = a.replace(/(<([^>]+)>)/gi, "").trim();
    if (sortDate !== "") {
        const dtParts = sortDate.split(" ");
        const timeParts = (undefined != dtParts[1]) ? dtParts[1].split(":") : ["00", "00", "00"];
        const dateParts = dtParts[0].split("-");
        x = (dateParts[0] + dateParts[1] + dateParts[2] + timeParts[0] + timeParts[1] + ((undefined != timeParts[2]) ? timeParts[2] : 0)) * 1;
        if (isNaN(x)) {
            x = 0;
        }
    } else {
        x = Infinity;
    }
    return x;
};

// onLoad events
document.addEventListener("DOMContentLoaded", async (/*event*/) => {
    if (window.VW_ADMIN_I18N_READY) {
        await window.VW_ADMIN_I18N_READY;
    }

    DataTable.ext.type.detect.unshift(function (data) {
        if (typeof data !== "string") { return null; }
        return data.indexOf("data-sort-type=\"date-iso\"") !== -1
            ? "date-iso"
            : null;
    });

    const columnCount = document.getElementById("users-table").querySelectorAll("thead th").length;
    new DataTable("#users-table", {
        "typeDetect": true,
        "drawCallback": function () {
            initUserTable();
        },
        "language": {
            "search": tUsers("datatable_search"),
            "emptyTable": tUsers("datatable_empty_table"),
            "info": tUsers("datatable_info"),
            "infoEmpty": tUsers("datatable_info_empty"),
            "infoFiltered": tUsers("datatable_info_filtered"),
            "lengthMenu": tUsers("datatable_length_menu"),
            "loadingRecords": tUsers("datatable_loading_records"),
            "processing": tUsers("datatable_processing"),
            "zeroRecords": tUsers("datatable_zero_records"),
            "paginate": {
                "first": tUsers("datatable_paginate_first"),
                "last": tUsers("datatable_paginate_last"),
                "next": tUsers("datatable_paginate_next"),
                "previous": tUsers("datatable_paginate_previous")
            },
            "aria": {
                "orderable": tUsers("datatable_aria_orderable"),
                "orderableReverse": tUsers("datatable_aria_orderable_reverse")
            }
        },
        "stateSave": true,
        "responsive": true,
        "lengthMenu": [
            [-1, 2, 5, 10, 25, 50],
            [tUsers("datatable_all"), 2, 5, 10, 25, 50]
        ],
        "pageLength": -1, // Default show all
        "columnDefs": [{
            "targets": columnCount - 1, // Do not include the last column into the search/order features
            "searchable": false,
            "orderable": false
        }]
    });

    // Add click events for user actions
    initUserTable();

    const btnUpdateRevisions = document.getElementById("updateRevisions");
    if (btnUpdateRevisions) {
        btnUpdateRevisions.addEventListener("click", updateRevisions);
    }
    const btnReload = document.getElementById("reload");
    if (btnReload) {
        btnReload.addEventListener("click", reload);
    }
    const btnUserOrgTypeForm = document.getElementById("userOrgTypeForm");
    if (btnUserOrgTypeForm) {
        btnUserOrgTypeForm.addEventListener("submit", updateUserOrgType);
    }
    const btnInviteUserForm = document.getElementById("inviteUserForm");
    if (btnInviteUserForm) {
        btnInviteUserForm.addEventListener("submit", inviteUser);
    }
});
