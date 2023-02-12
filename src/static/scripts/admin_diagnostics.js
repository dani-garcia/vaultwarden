"use strict";
/* eslint-env es2017, browser */
/* global BASE_URL:readable, BSN:readable */

var dnsCheck = false;
var timeCheck = false;
var domainCheck = false;
var httpsCheck = false;

// ================================
// Date & Time Check
const d = new Date();
const year = d.getUTCFullYear();
const month = String(d.getUTCMonth()+1).padStart(2, "0");
const day = String(d.getUTCDate()).padStart(2, "0");
const hour = String(d.getUTCHours()).padStart(2, "0");
const minute = String(d.getUTCMinutes()).padStart(2, "0");
const seconds = String(d.getUTCSeconds()).padStart(2, "0");
const browserUTC = `${year}-${month}-${day} ${hour}:${minute}:${seconds} UTC`;

// ================================
// Check if the output is a valid IP
const isValidIp = value => (/^(?:(?:^|\.)(?:2(?:5[0-5]|[0-4]\d)|1?\d?\d)){4}$/.test(value) ? true : false);

function checkVersions(platform, installed, latest, commit=null) {
    if (installed === "-" || latest === "-") {
        document.getElementById(`${platform}-failed`).classList.remove("d-none");
        return;
    }

    // Only check basic versions, no commit revisions
    if (commit === null || installed.indexOf("-") === -1) {
        if (installed !== latest) {
            document.getElementById(`${platform}-warning`).classList.remove("d-none");
        } else {
            document.getElementById(`${platform}-success`).classList.remove("d-none");
        }
    } else {
        // Check if this is a branched version.
        const branchRegex = /(?:\s)\((.*?)\)/;
        const branchMatch = installed.match(branchRegex);
        if (branchMatch !== null) {
            document.getElementById(`${platform}-branch`).classList.remove("d-none");
        }

        // This will remove branch info and check if there is a commit hash
        const installedRegex = /(\d+\.\d+\.\d+)-(\w+)/;
        const instMatch = installed.match(installedRegex);

        // It could be that a new tagged version has the same commit hash.
        // In this case the version is the same but only the number is different
        if (instMatch !== null) {
            if (instMatch[2] === commit) {
                // The commit hashes are the same, so latest version is installed
                document.getElementById(`${platform}-success`).classList.remove("d-none");
                return;
            }
        }

        if (installed === latest) {
            document.getElementById(`${platform}-success`).classList.remove("d-none");
        } else {
            document.getElementById(`${platform}-warning`).classList.remove("d-none");
        }
    }
}

// ================================
// Generate support string to be pasted on github or the forum
async function generateSupportString(event, dj) {
    event.preventDefault();
    event.stopPropagation();

    let supportString = "### Your environment (Generated via diagnostics page)\n";

    supportString += `* Vaultwarden version: v${dj.current_release}\n`;
    supportString += `* Web-vault version: v${dj.web_vault_version}\n`;
    supportString += `* OS/Arch: ${dj.host_os}/${dj.host_arch}\n`;
    supportString += `* Running within Docker: ${dj.running_within_docker} (Base: ${dj.docker_base_image})\n`;
    supportString += "* Environment settings overridden: ";
    if (dj.overrides != "") {
        supportString += "true\n";
    } else {
        supportString += "false\n";
    }
    supportString += `* Uses a reverse proxy: ${dj.ip_header_exists}\n`;
    if (dj.ip_header_exists) {
        supportString += `* IP Header check: ${dj.ip_header_match} (${dj.ip_header_name})\n`;
    }
    supportString += `* Internet access: ${dj.has_http_access}\n`;
    supportString += `* Internet access via a proxy: ${dj.uses_proxy}\n`;
    supportString += `* DNS Check: ${dnsCheck}\n`;
    supportString += `* Time Check: ${timeCheck}\n`;
    supportString += `* Domain Configuration Check: ${domainCheck}\n`;
    supportString += `* HTTPS Check: ${httpsCheck}\n`;
    supportString += `* Database type: ${dj.db_type}\n`;
    supportString += `* Database version: ${dj.db_version}\n`;
    supportString += "* Clients used: \n";
    supportString += "* Reverse proxy and version: \n";
    supportString += "* Other relevant information: \n";

    const jsonResponse = await fetch(`${BASE_URL}/admin/diagnostics/config`, {
        "headers": { "Accept": "application/json" }
    });
    if (!jsonResponse.ok) {
        alert("Generation failed: " + jsonResponse.statusText);
        throw new Error(jsonResponse);
    }
    const configJson = await jsonResponse.json();
    supportString += "\n### Config (Generated via diagnostics page)\n<details><summary>Show Running Config</summary>\n";
    supportString += `\n**Environment settings which are overridden:** ${dj.overrides}\n`;
    supportString += "\n\n```json\n" + JSON.stringify(configJson, undefined, 2) + "\n```\n</details>\n";

    document.getElementById("support-string").innerText = supportString;
    document.getElementById("support-string").classList.remove("d-none");
    document.getElementById("copy-support").classList.remove("d-none");
}

function copyToClipboard(event) {
    event.preventDefault();
    event.stopPropagation();

    const supportStr = document.getElementById("support-string").innerText;
    const tmpCopyEl = document.createElement("textarea");

    tmpCopyEl.setAttribute("id", "copy-support-string");
    tmpCopyEl.setAttribute("readonly", "");
    tmpCopyEl.value = supportStr;
    tmpCopyEl.style.position = "absolute";
    tmpCopyEl.style.left = "-9999px";
    document.body.appendChild(tmpCopyEl);
    tmpCopyEl.select();
    document.execCommand("copy");
    tmpCopyEl.remove();

    new BSN.Toast("#toastClipboardCopy").show();
}

function checkTimeDrift(browserUTC, serverUTC) {
    const timeDrift = (
        Date.parse(serverUTC.replace(" ", "T").replace(" UTC", "")) -
        Date.parse(browserUTC.replace(" ", "T").replace(" UTC", ""))
    ) / 1000;
    if (timeDrift > 20 || timeDrift < -20) {
        document.getElementById("time-warning").classList.remove("d-none");
    } else {
        document.getElementById("time-success").classList.remove("d-none");
        timeCheck = true;
    }
}

function checkDomain(browserURL, serverURL) {
    if (serverURL == browserURL) {
        document.getElementById("domain-success").classList.remove("d-none");
        domainCheck = true;
    } else {
        document.getElementById("domain-warning").classList.remove("d-none");
    }

    // Check for HTTPS at domain-server-string
    if (serverURL.startsWith("https://") ) {
        document.getElementById("https-success").classList.remove("d-none");
        httpsCheck = true;
    } else {
        document.getElementById("https-warning").classList.remove("d-none");
    }
}

function initVersionCheck(dj) {
    const serverInstalled = dj.current_release;
    const serverLatest = dj.latest_release;
    const serverLatestCommit = dj.latest_commit;

    if (serverInstalled.indexOf("-") !== -1 && serverLatest !== "-" && serverLatestCommit !== "-") {
        document.getElementById("server-latest-commit").classList.remove("d-none");
    }
    checkVersions("server", serverInstalled, serverLatest, serverLatestCommit);

    if (!dj.running_within_docker) {
        const webInstalled = dj.web_vault_version;
        const webLatest = dj.latest_web_build;
        checkVersions("web", webInstalled, webLatest);
    }
}

function checkDns(dns_resolved) {
    if (isValidIp(dns_resolved)) {
        document.getElementById("dns-success").classList.remove("d-none");
        dnsCheck = true;
    } else {
        document.getElementById("dns-warning").classList.remove("d-none");
    }
}

function init(dj) {
    // Time check
    document.getElementById("time-browser-string").innerText = browserUTC;
    checkTimeDrift(browserUTC, dj.server_time);

    // Domain check
    const browserURL = location.href.toLowerCase();
    document.getElementById("domain-browser-string").innerText = browserURL;
    checkDomain(browserURL, dj.admin_url.toLowerCase());

    // Version check
    initVersionCheck(dj);

    // DNS Check
    checkDns(dj.dns_resolved);
}

// onLoad events
document.addEventListener("DOMContentLoaded", (event) => {
    const diag_json = JSON.parse(document.getElementById("diagnostics_json").innerText);
    init(diag_json);

    const btnGenSupport = document.getElementById("gen-support");
    if (btnGenSupport) {
        btnGenSupport.addEventListener("click", () => {
            generateSupportString(event, diag_json);
        });
    }
    const btnCopySupport = document.getElementById("copy-support");
    if (btnCopySupport) {
        btnCopySupport.addEventListener("click", copyToClipboard);
    }
});