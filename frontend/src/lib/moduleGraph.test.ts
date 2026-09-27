import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { collectModuleGraph, findCycles, importCyclesIn, type ModuleNode } from "@/lib/moduleGraph";

/** The source directory, whichever directory the suite was started from. */
const SRC =
  [resolve(process.cwd(), "src"), resolve(process.cwd(), "frontend/src")].find((dir) =>
    existsSync(resolve(dir, "main.tsx")),
  ) ?? resolve(process.cwd(), "src");

/**
 * The guard the production bundle cannot provide for itself.
 *
 * A cycle between two of our modules does not fail typechecking, the test suite or
 * the dev server — all of them run a real ES module graph, which evaluates a
 * dependency before its dependant. It only breaks the *bundled* artifact, where
 * Rollup flattens the graph and, inside a cycle, chooses the order; a module placed
 * before its dependency then throws the first time it touches it, and if the module
 * that does so swallows its own errors, the app silently concludes it has no
 * session. That is not hypothetical: it was the reload bug this file exists to keep
 * closed (`src/lib/session-bridge.ts` has the full account).
 *
 * `vite.config.ts` fails the build on such a cycle, which is the check that guards
 * what actually ships. This test states the same invariant in the source itself, so
 * it is visible to whoever reads the code — and it fails with the cycle spelled out
 * rather than as a bundler error at release time.
 */
describe("frontend module graph", () => {
  it("reports no import cycle between the application's own modules", () => {
    const cycles = importCyclesIn(SRC);

    expect(
      cycles,
      cycles.length
        ? `Cyclic imports found:\n${cycles.map((c) => `  ${c.join(" -> ")} -> ${c[0]}`).join("\n")}`
        : "",
    ).toEqual([]);
  });

  it("finds a cycle when there is one, including a module importing itself", () => {
    const nodes: ModuleNode[] = [
      { id: "/app/a", imports: ["/app/b"] },
      { id: "/app/b", imports: ["/app/c"] },
      { id: "/app/c", imports: ["/app/a"] },
      { id: "/app/self", imports: ["/app/self"] },
      { id: "/app/leaf", imports: [] },
    ];

    const cycles = findCycles(nodes);

    expect(cycles).toContainEqual(["/app/a", "/app/b", "/app/c"]);
    expect(cycles).toContainEqual(["/app/self"]);
    // A module that imports nothing is never part of a cycle, and a shared
    // dependency reached twice is not reported as one.
    expect(cycles.some((cycle) => cycle.includes("/app/leaf"))).toBe(false);
  });

  it("reports one cycle once, however many paths reach it", () => {
    const nodes: ModuleNode[] = [
      { id: "/app/entry-one", imports: ["/app/x"] },
      { id: "/app/entry-two", imports: ["/app/y"] },
      { id: "/app/x", imports: ["/app/y"] },
      { id: "/app/y", imports: ["/app/x"] },
    ];

    expect(findCycles(nodes)).toEqual([["/app/x", "/app/y"]]);
  });

  it("reads the real graph, not only the files it was told about", () => {
    const graph = collectModuleGraph(SRC);
    const ids = graph.map((node) => node.id);

    // The session bridge is the leaf the cycle fix rests on: it must be in the
    // graph and must import nothing of ours. If somebody adds an import to it, the
    // direction the whole arrangement depends on is gone.
    const bridge = graph.find((node) => node.id.endsWith("/lib/session-bridge.ts"));
    expect(bridge).toBeDefined();
    expect(bridge?.imports).toEqual([]);

    // And a sanely non-empty sample, so a walker that silently found nothing
    // cannot pass this file.
    expect(ids.length).toBeGreaterThan(40);
    expect(ids.some((id) => id.endsWith("/store/auth.ts"))).toBe(true);
    expect(ids.some((id) => id.endsWith("/lib/api.ts"))).toBe(true);
  });

  it("keeps the API client out of the session store's imports", async () => {
    // The specific edge that caused the reload bug, asserted by name: the API
    // client reaches the store through the bridge, never by importing it.
    const { readFileSync } = await import("node:fs");
    const bridge = readFileSync(`${SRC}/lib/session-bridge.ts`, "utf8");
    const api = readFileSync(`${SRC}/lib/api.ts`, "utf8");

    expect(bridge).not.toMatch(/^\s*import\s+(?!type)/m);
    expect(api).not.toMatch(/from\s+["']@\/store\//);
  });
});
