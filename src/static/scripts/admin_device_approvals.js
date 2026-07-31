"use strict";
/* eslint-env es2017, browser */
/* global BASE_URL:readable */

// Answering a device approval means handing a member their own user key, encrypted for the key
// pair of the device that is asking. The server cannot do that: it holds the organization's
// private key only encrypted with the organization key, and that one exists solely as RSA
// envelopes addressed to each administrator. So the whole chain runs here, in the browser, and
// the master password never leaves this page.
//
//   master password -> master key          PBKDF2-SHA256(password, email, iterations)
//                   -> own user key        AES from profile.key
//                   -> own private key     AES from profile.privateKey
//                   -> organization key    RSA from profile.organizations[].key
//                   -> org private key     AES from reset-password-details.encryptedPrivateKey
//                   -> member's user key   RSA from reset-password-details.resetPasswordKey
//                   -> encryptedUserKey    RSA for the public key out of the request

const DEVICE_IDENTIFIER_KEY = "vw_admin_device_approvals_device_id";

let session = null; // { token, profile, privateKey }
let requests = [];

function element(id) {
    return document.getElementById(id);
}

function setStatus(message, kind) {
    const box = element("approval-status");
    box.textContent = message;
    box.className = message ? `alert alert-${kind || "info"}` : "d-none";
}

function fromBase64(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function toBase64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}

// --------------------------------------------------------------------------- crypto

async function pbkdf2(password, salt, iterations) {
    const key = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" }, key, 256);
    return new Uint8Array(bits);
}

// HKDF-Expand only, with the master key used directly as the pseudorandom key. WebCrypto's HKDF
// always runs the extract step first, which would give a different result, so this is by hand.
async function hkdfExpand(prk, info) {
    const key = await crypto.subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const input = concat(new TextEncoder().encode(info), new Uint8Array([1]));
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, input));
}

async function stretch(masterKey) {
    return [await hkdfExpand(masterKey, "enc"), await hkdfExpand(masterKey, "mac")];
}

// A user key or organization key is 64 bytes: the AES half followed by the HMAC half.
async function splitKey(key) {
    if (key.length === 32) {
        return stretch(key);
    }
    if (key.length === 64) {
        return [key.slice(0, 32), key.slice(32)];
    }
    throw new Error(`Unexpected key length ${key.length}`);
}

// EncString type 2: 2.iv|ciphertext|mac
async function decryptSymmetric(encString, encKey, macKey) {
    const [kind, rest] = [encString.slice(0, encString.indexOf(".")), encString.slice(encString.indexOf(".") + 1)];
    if (kind !== "2") {
        throw new Error(`Expected a symmetrically encrypted value, got type ${kind}`);
    }

    const [iv, ciphertext, mac] = rest.split("|").map(fromBase64);

    const macCryptoKey = await crypto.subtle.importKey("raw", macKey, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    if (!await crypto.subtle.verify("HMAC", macCryptoKey, mac, concat(iv, ciphertext))) {
        throw new Error("The stored value does not match its signature. Wrong master password?");
    }

    const aesKey = await crypto.subtle.importKey("raw", encKey, { name: "AES-CBC" }, false, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: iv }, aesKey, ciphertext));
}

// EncString type 4 or 6: RSA-OAEP with SHA-1. Type 6 carries an extra signature we do not need.
async function decryptAsymmetric(encString, privateKey) {
    const kind = encString.slice(0, encString.indexOf("."));
    if (kind !== "4" && kind !== "6") {
        throw new Error(`Expected an RSA encrypted value, got type ${kind}`);
    }

    const data = fromBase64(encString.slice(encString.indexOf(".") + 1).split("|")[0]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, data));
}

async function encryptAsymmetric(plain, publicKeyB64) {
    const publicKey = await crypto.subtle.importKey(
        "spki", fromBase64(publicKeyB64), { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
    const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, plain);
    return "4." + toBase64(encrypted);
}

async function importPrivateKey(pkcs8) {
    return crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-1" }, false, ["decrypt"]);
}

// --------------------------------------------------------------------------- api

async function api(method, path, body, options) {
    const settings = options || {};
    const headers = {};
    if (session && !settings.anonymous) {
        headers["Authorization"] = `Bearer ${session.token}`;
    }

    let payload = null;
    if (body !== undefined && body !== null) {
        if (settings.form) {
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            payload = new URLSearchParams(body).toString();
        } else {
            headers["Content-Type"] = "application/json";
            payload = JSON.stringify(body);
        }
    }

    const response = await fetch(BASE_URL + path, { method: method, headers: headers, body: payload });
    const text = await response.text();
    let parsed = null;
    try {
        parsed = text ? JSON.parse(text) : null;
    } catch (e) {
        parsed = { message: text.slice(0, 200) };
    }

    if (!response.ok) {
        throw new Error((parsed && (parsed.message || parsed.ErrorModel?.Message)) || `HTTP ${response.status}`);
    }
    return parsed;
}

function deviceIdentifier() {
    let identifier = localStorage.getItem(DEVICE_IDENTIFIER_KEY);
    if (!identifier) {
        identifier = crypto.randomUUID();
        localStorage.setItem(DEVICE_IDENTIFIER_KEY, identifier);
    }
    return identifier;
}

// --------------------------------------------------------------------------- flow

async function signIn(email, password) {
    const prelogin = await api("POST", "/identity/accounts/prelogin", { email: email }, { anonymous: true });
    if (prelogin.kdf !== 0) {
        throw new Error("This account uses Argon2, which this page does not implement. Use APPROVE_DEVICE from the command line.");
    }

    const encoder = new TextEncoder();
    const masterKey = await pbkdf2(encoder.encode(password), encoder.encode(email.trim().toLowerCase()), prelogin.kdfIterations);
    const passwordHash = toBase64(await pbkdf2(masterKey, encoder.encode(password), 1));

    const token = await api("POST", "/identity/connect/token", {
        grant_type: "password",
        client_id: "web",
        username: email,
        password: passwordHash,
        scope: "api offline_access",
        deviceIdentifier: deviceIdentifier(),
        deviceName: "Vaultwarden admin",
        deviceType: 9,
    }, { anonymous: true, form: true });

    if (token.TwoFactorProviders || token.TwoFactorProviders2) {
        throw new Error("Two-step login is active for this account, which this page does not implement.");
    }

    session = { token: token.access_token };

    const sync = await api("GET", "/api/sync?excludeDomains=true");
    const profile = sync.profile;
    const userKey = await decryptSymmetric(profile.key, ...await stretch(masterKey));
    const privateKey = await importPrivateKey(await decryptSymmetric(profile.privateKey, ...await splitKey(userKey)));

    session = { token: token.access_token, profile: profile, privateKey: privateKey };
}

async function loadRequests() {
    requests = [];
    for (const org of session.profile.organizations) {
        let pending;
        try {
            pending = await api("GET", `/api/organizations/${org.id}/auth-requests`);
        } catch (e) {
            continue; // not an administrator of this one
        }
        for (const request of pending.data) {
            request.organization = org;
            requests.push(request);
        }
    }
}

async function memberUserKey(request) {
    const org = request.organization;
    const orgKey = await decryptAsymmetric(org.key, session.privateKey);

    const details = await api(
        "GET", `/api/organizations/${org.id}/users/${request.organizationUserId}/reset-password-details`);
    if (!details.resetPasswordKey) {
        throw new Error("This member is not enrolled in account recovery, so nobody can hand out their key.");
    }

    const orgPrivateKey = await importPrivateKey(await decryptSymmetric(details.encryptedPrivateKey, ...await splitKey(orgKey)));
    return decryptAsymmetric(details.resetPasswordKey, orgPrivateKey);
}

async function answer(request, approved) {
    const path = `/api/organizations/${request.organization.id}/auth-requests/${request.id}`;

    if (!approved) {
        await api("POST", path, { requestApproved: false });
        setStatus(`Denied the request from ${request.email}.`, "secondary");
        return;
    }

    const encryptedUserKey = await encryptAsymmetric(await memberUserKey(request), request.publicKey);
    await api("POST", path, { requestApproved: true, encryptedUserKey: encryptedUserKey });
    setStatus(`Approved. ${request.email} can open their vault on that device now.`, "success");
}

// --------------------------------------------------------------------------- rendering

function renderRequests() {
    const tbody = element("approval-rows");
    tbody.innerHTML = "";

    element("approval-empty").classList.toggle("d-none", requests.length > 0);
    element("approval-table").classList.toggle("d-none", requests.length === 0);

    requests.forEach((request, index) => {
        const row = document.createElement("tr");

        const cell = (text) => {
            const td = document.createElement("td");
            td.textContent = text;
            return td;
        };

        row.appendChild(cell(request.email));
        row.appendChild(cell(request.organization.name));
        row.appendChild(cell(request.requestDeviceType));
        row.appendChild(cell(request.requestIpAddress));
        row.appendChild(cell(new Date(request.creationDate).toLocaleString()));

        const actions = document.createElement("td");
        for (const [label, style, approved] of [["Approve", "btn-primary", true], ["Deny", "btn-outline-secondary", false]]) {
            const button = document.createElement("button");
            button.type = "button";
            button.className = `btn btn-sm ${style} me-1`;
            button.textContent = label;
            button.addEventListener("click", () => void handleAnswer(index, approved, button));
            actions.appendChild(button);
        }
        row.appendChild(actions);

        tbody.appendChild(row);
    });
}

function busy(on) {
    document.querySelectorAll("#approval-rows button, #approval-reload").forEach(b => { b.disabled = on; });
}

async function handleAnswer(index, approved, button) {
    busy(true);
    button.textContent = approved ? "Approving..." : "Denying...";
    try {
        await answer(requests[index], approved);
        await refresh();
    } catch (e) {
        setStatus(e.message, "danger");
    } finally {
        busy(false);
    }
}

async function refresh() {
    await loadRequests();
    renderRequests();
}

// --------------------------------------------------------------------------- wiring

document.addEventListener("DOMContentLoaded", () => {
    element("approval-signin").addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = element("approval-signin-button");
        button.disabled = true;
        setStatus("Signing in and unlocking the keys...", "info");

        try {
            await signIn(element("approval-email").value.trim(), element("approval-password").value);
            element("approval-password").value = "";
            element("approval-signin").classList.add("d-none");
            element("approval-list").classList.remove("d-none");
            element("approval-signed-in-as").textContent = session.profile.email;
            await refresh();
            setStatus("", null);
        } catch (e) {
            session = null;
            setStatus(e.message, "danger");
        } finally {
            button.disabled = false;
        }
    });

    element("approval-reload").addEventListener("click", async () => {
        busy(true);
        try {
            await refresh();
        } catch (e) {
            setStatus(e.message, "danger");
        } finally {
            busy(false);
        }
    });
});
