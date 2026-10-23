/**
 * What the UI says it is, when no build injected a version.
 *
 * `VITE_APP_VERSION` is set by the image build, which is why a deployment is
 * right to trust it. A host `npm run dev` or `npm run build` sets nothing, and
 * the fallback used to be a literal — `"0.2.0"` while the tree was 0.2.1 — so
 * the packaged app and the built-from-source app disagreed about which release
 * they were. Reading the version from the package metadata removes the copy:
 * `scripts/check_version_consistency.py` already holds that field to the
 * release, so the fallback cannot drift on its own.
 */

import { describe, expect, it } from "vitest";

import packageJson from "../../package.json";
import { APP_VERSION } from "./appMeta";

describe("appMeta", () => {
  it("falls back to the version the package declares", () => {
    expect(APP_VERSION).toBe(packageJson.version);
  });
});
