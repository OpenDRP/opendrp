/**
 * Product identity shown in the UI.
 *
 * The version is injected at build time (`VITE_APP_VERSION`) so the displayed
 * value cannot drift from the deployed artifact; the fallback keeps local dev
 * builds working.
 */
export const APP_NAME = "OpenDRP";
export const APP_TAGLINE = "Digital Risk Protection Platform";
export const APP_VERSION: string = import.meta.env.VITE_APP_VERSION || "0.1.0";
export const APP_TITLE = `${APP_NAME} — ${APP_TAGLINE}`;
