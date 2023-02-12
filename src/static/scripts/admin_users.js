"use strict";
/* eslint-env es2017, browser, jquery */
/* global _post:readable, BASE_URL:readable, reload:readable, jdenticon:readable */

function deleteUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("Required parameters not found!");
        return false;
    }
    const input_email = prompt(`To delete user "${email}", please type the email below`);
    if (input_email != null) {
        if (input_email == email) {
            _post(`${BASE_URL}/admin/users/${id}/delete`,
                "User deleted correctly",
                "Error deleting user"
            );
        } else {
            alert("Wrong email, please try again");
        }
    }
}

function remove2fa(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    if (!id) {
        alert("Required parameters not found!");
        return false;
    }
    _post(`${BASE_URL}/admin/users/${id}/remove-2fa`,
        "2FA removed correctly",
        "Error removing 2FA"
    );
}

function deauthUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    if (!id) {
        alert("Required parameters not found!");
        return false;
    }
    _post(`${BASE_URL}/admin/users/${id}/deauth`,
        "Sessions deauthorized correctly",
        "Error deauthorizing sessions"
    );
}

function disableUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("Required parameters not found!");
        return false;
    }
    const confirmed = confirm(`Are you sure you want to disable user "${email}"? This will also deauthorize their sessions.`);
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/disable`,
            "User disabled successfully",
            "Error disabling user"
        );
    }
}

function enableUser(event) {
    event.preventDefault();
    event.stopPropagation();
    const id = event.target.parentNode.dataset.vwUserUuid;
    const email = event.target.parentNode.dataset.vwUserEmail;
    if (!id || !email) {
        alert("Required parameters not found!");
        return false;
    }
    const confirmed = confirm(`Are you sure you want to enable user "${email}"?`);
    if (confirmed) {
        _post(`${BASE_URL}/admin/users/${id}/enable`,
            "User enabled successfully",
            "Error enabling user"
        );
    }
}

function updateRevisions(event) {
    event.preventDefault();
    event.stopPropagation();
    _post(`${BASE_URL}/admin/users/update_revision`,
        "Success, clients will sync next time they connect",
        "Error forcing clients to sync"
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
    _post(`${BASE_URL}/admin/invite/`,
        "User invited correctly",
        "Error inviting user",
        data
    );
}

const ORG_TYPES = {
    "0": {
        "name": "Owner",
        "color": "orange"
    },
    "1": {
        "name": "Admin",
        "color": "blueviolet"
    },
    "2": {
        "name": "User",
        "color": "blue"
    },
    "3": {
        "name": "Manager",
        "color": "green"
    },
};

// Special sort function to sort dates in ISO format
jQuery.extend(jQuery.fn.dataTableExt.oSort, {
    "date-iso-pre": function(a) {
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
    },

    "date-iso-asc": function(a, b) {
        return a - b;
    },

    "date-iso-desc": function(a, b) {
        return b - a;
    }
});

const userOrgTypeDialog = document.getElementById("userOrgTypeDialog");
// Fill the form and title
userOrgTypeDialog.addEventListener("show.bs.modal", function(event) {
    // Get shared values
    const userEmail = event.relatedTarget.parentNode.dataset.vwUserEmail;
    const userUuid = event.relatedTarget.parentNode.dataset.vwUserUuid;
    // Get org specific values
    const userOrgType = event.relatedTarget.dataset.vwOrgType;
    const userOrgTypeName = ORG_TYPES[userOrgType]["name"];
    const orgName = event.relatedTarget.dataset.vwOrgName;
    const orgUuid = event.relatedTarget.dataset.vwOrgUuid;

    document.getElementById("userOrgTypeDialogTitle").innerHTML = `<b>Update User Type:</b><br><b>Organization:</b> ${orgName}<br><b>User:</b> ${userEmail}`;
    document.getElementById("userOrgTypeUserUuid").value = userUuid;
    document.getElementById("userOrgTypeOrgUuid").value = orgUuid;
    document.getElementById(`userOrgType${userOrgTypeName}`).checked = true;
}, false);

// Prevent accidental submission of the form with valid elements after the modal has been hidden.
userOrgTypeDialog.addEventListener("hide.bs.modal", function() {
    document.getElementById("userOrgTypeDialogTitle").innerHTML = "";
    document.getElementById("userOrgTypeUserUuid").value = "";
    document.getElementById("userOrgTypeOrgUuid").value = "";
}, false);

function updateUserOrgType(event) {
    event.preventDefault();
    event.stopPropagation();

    const data = JSON.stringify(Object.fromEntries(new FormData(event.target).entries()));

    _post(`${BASE_URL}/admin/users/org_type`,
        "Updated organization type of the user successfully",
        "Error updating organization type of the user",
        data
    );
}

function initUserTable() {
    // Color all the org buttons per type
    document.querySelectorAll("button[data-vw-org-type]").forEach(function(e) {
        const orgType = ORG_TYPES[e.dataset.vwOrgType];
        e.style.backgroundColor = orgType.color;
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
    document.querySelectorAll("button[vw-disable-user]").forEach(btn => {
        btn.addEventListener("click", disableUser);
    });
    document.querySelectorAll("button[vw-enable-user]").forEach(btn => {
        btn.addEventListener("click", enableUser);
    });

    if (jdenticon) {
        jdenticon();
    }
}

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    jQuery("#users-table").DataTable({
        "drawCallback": function() {
            initUserTable();
        },
        "stateSave": true,
        "responsive": true,
        "lengthMenu": [
            [-1, 2, 5, 10, 25, 50],
            ["All", 2, 5, 10, 25, 50]
        ],
        "pageLength": 2, // Default show all
        "columnDefs": [{
            "targets": [1, 2],
            "type": "date-iso"
        }, {
            "targets": 6,
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