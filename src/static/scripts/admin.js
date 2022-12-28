"use strict";

function getBaseUrl() {
    // If the base URL is `https://vaultwarden.example.com/base/path/`,
    // `window.location.href` should have one of the following forms:
    //
    // - `https://vaultwarden.example.com/base/path/`
    // - `https://vaultwarden.example.com/base/path/#/some/route[?queryParam=...]`
    //
    // We want to get to just `https://vaultwarden.example.com/base/path`.
    const baseUrl = window.location.href;
    const adminPos = baseUrl.indexOf("/admin");
    return baseUrl.substring(0, adminPos != -1 ? adminPos : baseUrl.length);
}
const BASE_URL = getBaseUrl();

function reload() {
    // Reload the page by setting the exact same href
    // Using window.location.reload() could cause a repost.
    window.location = window.location.href;
}

function msg(text, reload_page = true) {
    text && alert(text);
    reload_page && reload();
}

function _post(url, successMsg, errMsg, body, reload_page = true) {
    fetch(url, {
        method: "POST",
        body: body,
        mode: "same-origin",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" }
    }).then( resp => {
        if (resp.ok) { msg(successMsg, reload_page); return Promise.reject({error: false}); }
        const respStatus = resp.status;
        const respStatusText = resp.statusText;
        return resp.text();
    }).then( respText => {
        try {
            const respJson = JSON.parse(respText);
            return respJson ? respJson.ErrorModel.Message : "Unknown error";
        } catch (e) {
            return Promise.reject({body:respStatus + " - " + respStatusText, error: true});
        }
    }).then( apiMsg => {
        msg(errMsg + "\n" + apiMsg, reload_page);
    }).catch( e => {
        if (e.error === false) { return true; }
        else { msg(errMsg + "\n" + e.body, reload_page); }
    });
}

// onLoad events
document.addEventListener("DOMContentLoaded", (/*event*/) => {
    // get current URL path and assign "active" class to the correct nav-item
    const pathname = window.location.pathname;
    if (pathname === "") return;
    const navItem = document.querySelectorAll(`.navbar-nav .nav-item a[href="${pathname}"]`);
    if (navItem.length === 1) {
        navItem[0].className = navItem[0].className + " active";
        navItem[0].setAttribute("aria-current", "page");
    }
});