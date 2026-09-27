import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

/**
 * The frontend's own import graph, and the cycles in it.
 *
 * Why this exists at all: a cycle between two modules is legal ESM, and every tool
 * in the ordinary loop tolerates it. The dev server and Vitest run a real module
 * graph, which evaluates a dependency before the module that imports it, so the
 * order is always correct. The production bundle is a different program — Rollup
 * flattens the graph into one file and, inside a cycle, picks the order, and Vite
 * silences the `CIRCULAR_DEPENDENCY` warning that would have named it. So the first
 * symptom of `store/auth.ts` importing `lib/api.ts` while `lib/api.ts` imported the
 * store was a sign-in form on every reload, with a perfectly valid session cookie,
 * because the store's module body ran before the API client's and the call it made
 * threw on a binding that did not exist yet.
 *
 * `vite.config.ts` fails the production build on a cycle that includes `src/` (that
 * is the check which protects the artifact); this walker is the other half, and it
 * is what lets a test state the invariant in a form that does not depend on the
 * build tooling at all. `session-bridge.ts` — the shared module that broke the cycle
 * — carries the longer explanation of the failure.
 */
export type ModuleNode = {
  /** Absolute path, without extension, exactly as imports resolve to it. */
  id: string;
  /** Absolute ids this module imports, for the ones inside the project. */
  imports: string[];
};

/**
 * Import statements that are evaluated at runtime: `import x from "y"`,
 * `export … from "y"`, a bare `import "y"`, and `import("y")`.
 *
 * Type-only imports are read too and then dropped, because they are erased before
 * anything is bundled and so cannot affect the order of the modules that run. What
 * this graph describes is evaluation order, which is the only thing that makes a
 * cycle dangerous.
 */
const FROM_STATEMENTS = /(?:^|\n)\s*(import|export)\s+([\s\S]*?)\s*from\s*["']([^"']+)["']/g;
const SIDE_EFFECT_IMPORTS = /(?:^|\n)\s*import\s*["']([^"']+)["']/g;
const DYNAMIC_IMPORTS = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;

/** Whether an `import`/`export` clause names types only, and is therefore erased. */
function isTypeOnlyClause(clause: string): boolean {
  const trimmed = clause.trim();
  if (/^type\b/.test(trimmed)) return true;
  const named = trimmed.match(/^\{([\s\S]*)\}$/);
  if (!named) return false;
  const specifiers = named[1]
    .split(",")
    .map((specifier) => specifier.trim())
    .filter(Boolean);
  return specifiers.length > 0 && specifiers.every((specifier) => /^type\s/.test(specifier));
}

const SKIPPED_DIRS = new Set(["node_modules", "dist", "coverage", ".vite"]);
const RESOLUTION_SUFFIXES = ["", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx"];

/** Whether a file takes part in the application's own graph. */
export function isAppModule(file: string): boolean {
  const normalised = file.replace(/\\/g, "/");
  if (!/\.(ts|tsx)$/.test(normalised)) return false;
  if (normalised.endsWith(".d.ts")) return false;
  // Tests are not bundled, so a cycle through one cannot break a release.
  if (/\.test\.(ts|tsx)$/.test(normalised)) return false;
  return true;
}

function resolveImport(fromFile: string, specifier: string, srcDir: string): string | null {
  let base: string;
  if (specifier.startsWith("@/")) base = join(srcDir, specifier.slice(2));
  else if (specifier.startsWith(".")) base = resolve(dirname(fromFile), specifier);
  else return null; // a package, a CSS file, an asset: not part of this graph

  for (const suffix of RESOLUTION_SUFFIXES) {
    const candidate = `${base}${suffix}`;
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  return null;
}

function collectFiles(dir: string, into: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) collectFiles(join(dir, entry.name), into);
    } else if (isAppModule(entry.name)) {
      into.push(join(dir, entry.name));
    }
  }
  return into;
}

/** Read the import graph of a project's `src` directory. */
export function collectModuleGraph(srcDir: string): ModuleNode[] {
  const root = resolve(srcDir);
  return collectFiles(root).map((file) => {
    const source = readFileSync(file, "utf8");
    const specifiers = new Set<string>();

    for (const match of source.matchAll(FROM_STATEMENTS)) {
      if (isTypeOnlyClause(match[2])) continue;
      specifiers.add(match[3]);
    }
    for (const pattern of [SIDE_EFFECT_IMPORTS, DYNAMIC_IMPORTS]) {
      for (const match of source.matchAll(pattern)) specifiers.add(match[1]);
    }

    const imports = new Set<string>();
    for (const specifier of specifiers) {
      const resolved = resolveImport(file, specifier, root);
      if (resolved) imports.add(resolve(resolved).replace(/\\/g, "/"));
    }
    return { id: resolve(file).replace(/\\/g, "/"), imports: [...imports] };
  });
}

/**
 * Every cycle in a graph, each reported once.
 *
 * A depth-first walk that reports an edge pointing back at a module currently on
 * the stack; the cycle is that suffix of the stack. Cycles that contain the same
 * modules are deduplicated, so a graph with two entry points into one cycle is
 * reported once.
 */
export function findCycles(nodes: ModuleNode[]): string[][] {
  const importsOf = new Map(nodes.map((node) => [node.id, node.imports]));
  const state = new Map<string, "open" | "done">();
  const stack: string[] = [];
  const cycles: string[][] = [];
  const seen = new Set<string>();

  const visit = (id: string): void => {
    state.set(id, "open");
    stack.push(id);
    for (const next of importsOf.get(id) ?? []) {
      if (!importsOf.has(next)) continue;
      const nextState = state.get(next);
      if (nextState === "open") {
        const cycle = stack.slice(stack.indexOf(next));
        const key = [...cycle].sort().join(" -> ");
        if (!seen.has(key)) {
          seen.add(key);
          cycles.push(cycle);
        }
      } else if (nextState === undefined) {
        visit(next);
      }
    }
    stack.pop();
    state.set(id, "done");
  };

  for (const node of nodes) {
    if (state.get(node.id) === undefined) visit(node.id);
  }
  return cycles;
}

/** The cycles in `src`, as readable project-relative paths. */
export function importCyclesIn(srcDir: string): string[][] {
  const root = resolve(srcDir);
  return findCycles(collectModuleGraph(root)).map((cycle) =>
    cycle.map((id) => relative(root, id).replace(/\\/g, "/")),
  );
}
