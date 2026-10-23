/**
 * Product identity shown in the UI.
 *
 * The version is injected at build time (`VITE_APP_VERSION`) so the displayed
 * value cannot drift from the deployed artifact. A host `npm run dev` or
 * `npm run build` sets nothing, so the fallback is the package's own version
 * rather than a copy of it: `scripts/check_version_consistency.py` holds that
 * field to the release, and a literal here was one release behind before
 * anything noticed.
 */
import { version as packageVersion } from "../../package.json";

export const APP_NAME = "OpenDRP";
export const APP_TAGLINE = "Digital Risk Protection Platform";
export const APP_VERSION: string = import.meta.env.VITE_APP_VERSION || packageVersion;
export const APP_TITLE = `${APP_NAME} — ${APP_TAGLINE}`;
