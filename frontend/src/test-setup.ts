import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterEach } from "vitest";

// `findBy*` and `waitFor` default to one second, which is a developer's budget on
// an idle machine, not a runner's while the other test files are in flight. Three
// seconds is still short enough that a genuinely absent element fails with the
// element's own message rather than as a test timeout, and it is well under the
// five-second per-test budget, so a slow wait cannot swallow the assertions after
// it. This changes how long a wait waits; no assertion is relaxed.
configure({ asyncUtilTimeout: 3000 });

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

if (!globalThis.ResizeObserver) {
  globalThis.ResizeObserver = ResizeObserverMock as typeof ResizeObserver;
}

afterEach(() => {
  cleanup();
});
