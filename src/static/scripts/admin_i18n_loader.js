"use strict";

(function loadAdminI18n() {
    const normalizeLocale = raw => String(raw || "").trim().replace(/_/g, "-").toLowerCase() || "en";

    const localeCandidates = locale => {
        const normalized = normalizeLocale(locale);
        const candidates = [normalized];

        const sep = normalized.indexOf("-");
        if (sep > 0) {
            const lang = normalized.slice(0, sep);
            if (lang && !candidates.includes(lang)) {
                candidates.push(lang);
            }
        }

        if (!candidates.includes("en")) {
            candidates.push("en");
        }

        return candidates;
    };

    const localeFromHtml = document.documentElement.getAttribute("lang");
    const locales = localeCandidates(localeFromHtml || "en");

    const pathname = window.location.pathname || "";
    const adminPos = pathname.indexOf("/admin");
    const basePath = adminPos !== -1 ? pathname.substring(0, adminPos) : "";

    window.VW_ADMIN_I18N = window.VW_ADMIN_I18N || {};
    window.VW_ADMIN_I18N_READY = (async () => {
        for (const locale of locales) {
            const url = `${basePath}/vw_static/locales/${locale}/admin_ui.json`;
            try {
                const resp = await fetch(url, {
                    method: "GET",
                    credentials: "same-origin",
                    cache: "no-cache"
                });

                if (!resp.ok) {
                    continue;
                }

                window.VW_ADMIN_I18N = await resp.json();
                return;
            } catch (_e) {
                // Try next locale candidate.
            }
        }
    })();
})();
