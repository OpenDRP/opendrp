/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

/**
 * Whether a Rollup warning is about a cycle that includes the application's source.
 *
 * Cycles inside a dependency are not ours to fix — `recharts` pulls in a `d3`
 * package that has one, and failing the release over it would only teach whoever
 * hits it to turn the check off. A cycle that includes a file under our own `src/`
 * is a defect in this codebase, and it is the one that ships silently: Vite keeps
 * Rollup's `CIRCULAR_DEPENDENCY` on its ignore list, so nothing else reports it.
 */
function isAppModuleCycle(warning: { ids?: string[] }): boolean {
  return (warning.ids ?? []).some((id) => {
    const normalised = id.replace(/\\/g, "/");
    if (normalised.includes("/node_modules/")) return false;
    return /(^|\/)src\//.test(normalised);
  });
}

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: { "/api": { target: "http://localhost:8000", changeOrigin: true } },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    target: "es2022",
    rollupOptions: {
      output: {
        manualChunks: {
          react: ["react", "react-dom", "react-router-dom"],
          vendor: ["axios", "zustand", "recharts"],
          ui: [
            "lucide-react",
            "@radix-ui/react-dialog",
            "@radix-ui/react-dropdown-menu",
            "@radix-ui/react-tabs",
            "@radix-ui/react-select",
            "@radix-ui/react-toast",
          ],
        },
      },
      /**
       * A cycle between two of our own modules fails the production build.
       *
       * Vite silences Rollup's `CIRCULAR_DEPENDENCY` warning (it is on Vite's own
       * ignore list), and every other tool in the loop tolerates a cycle: the dev
       * server and Vitest run a real ES module graph, which evaluates a dependency
       * before its dependant, so the order is always correct. The production bundle
       * is one flat file whose order, inside a cycle, is whatever Rollup picked — and
       * a module that runs too early can reach a binding that does not exist yet.
       * That failure is invisible, because the module that would report it catches
       * its own errors: `store/auth.ts` swallowing a `ReferenceError` looked exactly
       * like "this browser has no session", and every reload showed the sign-in form
       * while the cookie was perfectly valid. So the only place worth failing is the
       * build that produces the artifact — here, and in the image build that runs
       * this config — with a message that names the modules involved.
       */
      onwarn(warning, warn) {
        if (warning.code === "CIRCULAR_DEPENDENCY" && isAppModuleCycle(warning)) {
          throw new Error(
            `[opendrp] circular import between application modules: ${warning.message}\n` +
              "A cycle makes the order of the bundled modules arbitrary, and a module " +
              "body that runs before its dependency is initialized throws on first use " +
              "(see frontend/src/lib/session-bridge.ts). Import one way only — the " +
              "shared piece belongs in a third module that imports neither side.",
          );
        }
        // Everything else keeps Vite's own handling, including its hard failure
        // for an import it cannot resolve.
        warn(warning);
      },
    },
  },
  test: {
    environment: "jsdom",
    isolate: true,
    clearMocks: true,
    setupFiles: ["./src/test-setup.ts"],
  },
});
