"use strict";
/* global BASE_URL */

document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("server-warning");
    const feedback = document.getElementById("server-update-status");
    const pollingInterval = 3000;
    let timer = null;
    let stopped = false;
    let updating = false;
    let pending = false;
    let unavailableSince = null;
    // Keep the existing version badge usable for the configured image channel.
    button.classList.remove("d-none");

    async function request(path, method = "GET") {
        const response = await fetch(`${BASE_URL}/admin/updates/${path}`, {
            method,
            headers: { "Accept": "application/json", "Content-Type": "application/json" },
            cache: "no-store",
            signal: AbortSignal.timeout(15000),
        });
        if (response.status === 401) {
            stopped = true;
            throw new Error("Sign in again to check the update result.");
        }
        if (!response.ok) {
            throw new Error("Cannot reach the updater. Retrying automatically…");
        }
        return await response.json();
    }

    function scheduleRefresh() {
        clearTimeout(timer);
        if (!stopped) {
            timer = setTimeout(refresh, pollingInterval);
        }
    }

    async function refresh() {
        if (pending || stopped) {
            return;
        }
        pending = true;
        try {
            const state = await request("status");
            unavailableSince = null;
            button.disabled = state.busy || state.recovery_required;
            button.textContent = state.busy ? "Updating…" : "Update";
            if (state.busy) {
                updating = true;
                feedback.textContent = "";
            } else if (state.recovery_required) {
                feedback.textContent = "Update needs attention on the server. Contact the administrator.";
            } else if (updating && state.result === "updated") {
                stopped = true;
                window.location.reload();
            } else {
                updating = false;
                feedback.textContent = state.result === "updated" ? "" : state.message;
            }
        } catch (error) {
            button.disabled = true;
            button.textContent = updating ? "Updating…" : "Update";
            // A short outage is expected while the container restarts.
            if (unavailableSince === null) {
                unavailableSince = Date.now();
            }
            const expectedRestart = updating && !stopped && Date.now() - unavailableSince < 60000;
            feedback.textContent = expectedRestart ? "" : error.message;
        } finally {
            pending = false;
            scheduleRefresh();
        }
    }

    button.addEventListener("click", async () => {
        if (pending || button.disabled) {
            return;
        }
        clearTimeout(timer);
        pending = true;
        updating = true;
        button.disabled = true;
        button.textContent = "Updating…";
        feedback.textContent = "";
        try {
            await request("start", "POST");
        } catch (error) {
            // Do not retry a mutation: it may have been accepted before the connection dropped.
            feedback.textContent = error.message;
        } finally {
            pending = false;
            scheduleRefresh();
        }
    });
    window.addEventListener("pagehide", () => {
        stopped = true;
        clearTimeout(timer);
    });
    // This runner owns error reporting and polling.
    refresh();
});
