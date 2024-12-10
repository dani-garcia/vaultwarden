"use strict";
/* eslint-env es2017, browser */
/* global BASE_URL:readable, bootstrap:readable */

var dnsCheck = false;
var timeCheck = false;
var ntpTimeCheck = false;
var domainCheck = false;
var httpsCheck = false;
var websocketCheck = false;
var httpResponseCheck = false;

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
function isValidIp(ip) {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|((?:[a-fA-F0-9]{1,4}:){1,7}:|:(:[a-fA-F0-9]{1,4}){1,7}|[a-fA-F0-9]{1,4}:((:[a-fA-F0-9]{1,4}){1,6}))$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

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

    let supportString = "### Your environment (Generated via diagnostics page)\n\n";

    supportString += `* Vaultwarden version: v${dj.current_release}\n`;
    supportString += `* Web-vault version: v${dj.web_vault_version}\n`;
    supportString += `* OS/Arch: ${dj.host_os}/${dj.host_arch}\n`;
    supportString += `* Running within a container: ${dj.running_within_container} (Base: ${dj.container_base_image})\n`;
    supportString += `* Database type: ${dj.db_type}\n`;
    supportString += `* Database version: ${dj.db_version}\n`;
    supportString += `* Environment settings overridden!: ${dj.overrides !== ""}\n`;
    supportString += `* Uses a reverse proxy: ${dj.ip_header_exists}\n`;
    if (dj.ip_header_exists) {
        supportString += `* IP Header check: ${dj.ip_header_match} (${dj.ip_header_name})\n`;
    }
    supportString += `* Internet access: ${dj.has_http_access}\n`;
    supportString += `* Internet access via a proxy: ${dj.uses_proxy}\n`;
    supportString += `* DNS Check: ${dnsCheck}\n`;
    supportString += `* Browser/Server Time Check: ${timeCheck}\n`;
    supportString += `* Server/NTP Time Check: ${ntpTimeCheck}\n`;
    supportString += `* Domain Configuration Check: ${domainCheck}\n`;
    supportString += `* HTTPS Check: ${httpsCheck}\n`;
    if (dj.enable_websocket) {
        supportString += `* Websocket Check: ${websocketCheck}\n`;
    } else {
        supportString += "* Websocket Check: disabled\n";
    }
    supportString += `* HTTP Response Checks: ${httpResponseCheck}\n`;

    const jsonResponse = await fetch(`${BASE_URL}/admin/diagnostics/config`, {
        "headers": { "Accept": "application/json" }
    });
    if (!jsonResponse.ok) {
        alert("Generation failed: " + jsonResponse.statusText);
        throw new Error(jsonResponse);
    }
    const configJson = await jsonResponse.json();

    // Start Config and Details section within a details block which is collapsed by default
    supportString += "\n### Config & Details (Generated via diagnostics page)\n\n";
    supportString += "<details><summary>Show Config & Details</summary>\n";

    // Add overrides if they exists
    if (dj.overrides != "") {
        supportString += `\n**Environment settings which are overridden:** ${dj.overrides}\n`;
    }

    // Add http response check messages if they exists
    if (httpResponseCheck === false) {
        supportString += "\n**Failed HTTP Checks:**\n";
        // We use `innerText` here since that will convert <br> into new-lines
        supportString += "\n```yaml\n" + document.getElementById("http-response-errors").innerText.trim() + "\n```\n";
    }

    // Add the current config in json form
    supportString += "\n**Config:**\n";
    supportString += "\n```json\n" + JSON.stringify(configJson, undefined, 2) + "\n```\n";

    supportString += "\n</details>\n";

    // Add the support string to the textbox so it can be viewed and copied
    document.getElementById("support-string").textContent = supportString;
    document.getElementById("support-string").classList.remove("d-none");
    document.getElementById("copy-support").classList.remove("d-none");
}

function copyToClipboard(event) {
    event.preventDefault();
    event.stopPropagation();

    const supportStr = document.getElementById("support-string").textContent;
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

    new bootstrap.Toast("#toastClipboardCopy").show();
}

function checkTimeDrift(utcTimeA, utcTimeB, statusPrefix) {
    const timeDrift = (
        Date.parse(utcTimeA.replace(" ", "T").replace(" UTC", "")) -
        Date.parse(utcTimeB.replace(" ", "T").replace(" UTC", ""))
    ) / 1000;
    if (timeDrift > 15 || timeDrift < -15) {
        document.getElementById(`${statusPrefix}-warning`).classList.remove("d-none");
        return false;
    } else {
        document.getElementById(`${statusPrefix}-success`).classList.remove("d-none");
        return true;
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

    if (!dj.running_within_container) {
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

async function fetchCheckUrl(url) {
    try {
        const response = await fetch(url);
        return { headers: response.headers, status: response.status, text: await response.text() };
    } catch (error) {
        console.error(`Error fetching ${url}: ${error}`);
        return { error };
    }
}

function checkSecurityHeaders(headers, omit) {
    let securityHeaders = {
        "x-frame-options": ["SAMEORIGIN"],
        "x-content-type-options": ["nosniff"],
        "referrer-policy": ["same-origin"],
        "x-xss-protection": ["0"],
        "x-robots-tag": ["noindex", "nofollow"],
        "content-security-policy": [
            "default-src 'self'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'self' blob:",
            "script-src 'self' 'wasm-unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "child-src 'self' https://*.duosecurity.com https://*.duofederal.com",
            "frame-src 'self' https://*.duosecurity.com https://*.duofederal.com",
            "frame-ancestors 'self' chrome-extension://nngceckbapebfimnlniiiahkandclblb chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh moz-extension://*",
            "img-src 'self' data: https://haveibeenpwned.com",
            "connect-src 'self' https://api.pwnedpasswords.com https://api.2fa.directory https://app.simplelogin.io/api/ https://app.addy.io/api/ https://api.fastmail.com/ https://api.forwardemail.net",
        ]
    };

    let messages = [];
    for (let header in securityHeaders) {
        // Skip some headers for specific endpoints if needed
        if (typeof omit === "object" && omit.includes(header) === true) {
            continue;
        }
        // If the header exists, check if the contents matches what we expect it to be
        let headerValue = headers.get(header);
        if (headerValue !== null) {
            securityHeaders[header].forEach((expectedValue) => {
                if (headerValue.indexOf(expectedValue) === -1) {
                    messages.push(`'${header}' does not contain '${expectedValue}'`);
                }
            });
        } else {
            messages.push(`'${header}' is missing!`);
        }
    }
    return messages;
}

async function checkHttpResponse() {
    const [apiConfig, webauthnConnector, notFound, notFoundApi, badRequest, unauthorized, forbidden] = await Promise.all([
        fetchCheckUrl(`${BASE_URL}/api/config`),
        fetchCheckUrl(`${BASE_URL}/webauthn-connector.html`),
        fetchCheckUrl(`${BASE_URL}/admin/does-not-exist`),
        fetchCheckUrl(`${BASE_URL}/admin/diagnostics/http?code=404`),
        fetchCheckUrl(`${BASE_URL}/admin/diagnostics/http?code=400`),
        fetchCheckUrl(`${BASE_URL}/admin/diagnostics/http?code=401`),
        fetchCheckUrl(`${BASE_URL}/admin/diagnostics/http?code=403`),
    ]);

    const respErrorElm = document.getElementById("http-response-errors");

    // Check and validate the default API header responses
    let apiErrors = checkSecurityHeaders(apiConfig.headers);
    if (apiErrors.length >= 1) {
        respErrorElm.innerHTML += "<b>API calls:</b><br>";
        apiErrors.forEach((errMsg) => {
            respErrorElm.innerHTML += `<b>Header:</b> ${errMsg}<br>`;
        });
    }

    // Check the special `-connector.html` headers, these should have some headers omitted.
    const omitConnectorHeaders = ["x-frame-options", "content-security-policy"];
    let connectorErrors = checkSecurityHeaders(webauthnConnector.headers, omitConnectorHeaders);
    omitConnectorHeaders.forEach((header) => {
        if (webauthnConnector.headers.get(header) !== null) {
            connectorErrors.push(`'${header}' is present while it should not`);
        }
    });
    if (connectorErrors.length >= 1) {
        respErrorElm.innerHTML += "<b>2FA Connector calls:</b><br>";
        connectorErrors.forEach((errMsg) => {
            respErrorElm.innerHTML += `<b>Header:</b> ${errMsg}<br>`;
        });
    }

    // Check specific error code responses if they are not re-written by a reverse proxy
    let responseErrors = [];
    if (notFound.status !== 404 || notFound.text.indexOf("return to the web-vault") === -1) {
        responseErrors.push("404 (Not Found) HTML is invalid");
    }

    if (notFoundApi.status !== 404 || notFoundApi.text.indexOf("\"message\":\"Testing error 404 response\",") === -1) {
        responseErrors.push("404 (Not Found) JSON is invalid");
    }

    if (badRequest.status !== 400 || badRequest.text.indexOf("\"message\":\"Testing error 400 response\",") === -1) {
        responseErrors.push("400 (Bad Request) is invalid");
    }

    if (unauthorized.status !== 401 || unauthorized.text.indexOf("\"message\":\"Testing error 401 response\",") === -1) {
        responseErrors.push("401 (Unauthorized) is invalid");
    }

    if (forbidden.status !== 403 || forbidden.text.indexOf("\"message\":\"Testing error 403 response\",") === -1) {
        responseErrors.push("403 (Forbidden) is invalid");
    }

    if (responseErrors.length >= 1) {
        respErrorElm.innerHTML += "<b>HTTP error responses:</b><br>";
        responseErrors.forEach((errMsg) => {
            respErrorElm.innerHTML += `<b>Response to:</b> ${errMsg}<br>`;
        });
    }

    if (responseErrors.length >= 1 || connectorErrors.length >= 1 || apiErrors.length >= 1) {
        document.getElementById("http-response-warning").classList.remove("d-none");
    } else {
        httpResponseCheck = true;
        document.getElementById("http-response-success").classList.remove("d-none");
    }
}

async function fetchWsUrl(wsUrl) {
    return new Promise((resolve, reject) => {
        try {
            const ws = new WebSocket(wsUrl);
            ws.onopen = () => {
                ws.close();
                resolve(true);
            };

            ws.onerror = () => {
                reject(false);
            };
        } catch (_) {
            reject(false);
        }
    });
}

async function checkWebsocketConnection() {
    // Test Websocket connections via the anonymous (login with device) connection
    const isConnected = await fetchWsUrl(`${BASE_URL}/notifications/anonymous-hub?token=admin-diagnostics`).catch(() => false);
    if (isConnected) {
        websocketCheck = true;
        document.getElementById("websocket-success").classList.remove("d-none");
    } else {
        document.getElementById("websocket-error").classList.remove("d-none");
    }
}

function init(dj) {
    // Time check
    document.getElementById("time-browser-string").textContent = browserUTC;

    // Check if we were able to fetch a valid NTP Time
    // If so, compare both browser and server with NTP
    // Else, compare browser and server.
    if (dj.ntp_time.indexOf("UTC") !== -1) {
        timeCheck = checkTimeDrift(dj.server_time, browserUTC, "time");
        checkTimeDrift(dj.ntp_time, browserUTC, "ntp-browser");
        ntpTimeCheck = checkTimeDrift(dj.ntp_time, dj.server_time, "ntp-server");
    } else {
        timeCheck = checkTimeDrift(dj.server_time, browserUTC, "time");
        ntpTimeCheck = "n/a";
    }

    // Domain check
    const browserURL = location.href.toLowerCase();
    document.getElementById("domain-browser-string").textContent = browserURL;
    checkDomain(browserURL, dj.admin_url.toLowerCase());

    // Version check
    initVersionCheck(dj);

    // DNS Check
    checkDns(dj.dns_resolved);

    checkHttpResponse();

    if (dj.enable_websocket) {
        checkWebsocketConnection();
    }
}

// onLoad events
document.addEventListener("DOMContentLoaded", (event) => {
    const diag_json = JSON.parse(document.getElementById("diagnostics_json").textContent);
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