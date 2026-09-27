import { beforeEach, describe, expect, it, vi } from "vitest";

const { renderMock, createRootMock, restoreSessionMock } = vi.hoisted(() => {
  const renderMock = vi.fn();
  return {
    renderMock,
    createRootMock: vi.fn(() => ({ render: renderMock })),
    restoreSessionMock: vi.fn(),
  };
});

vi.mock("react-dom/client", () => ({ createRoot: createRootMock }));
vi.mock("@/App", () => ({ default: () => <div>Application shell</div> }));
// The boot asks the API for the session and nothing else here; the request itself
// is covered where it lives (src/lib/api.test.ts).
vi.mock("@/lib/api", () => ({ endpoints: {}, restoreSession: restoreSessionMock }));

beforeEach(() => {
  vi.resetModules();
  document.body.innerHTML = '<div id="root"></div>';
  localStorage.clear();
  createRootMock.mockClear();
  renderMock.mockReset();
  restoreSessionMock.mockReset().mockResolvedValue(null);
});

describe("application bootstrap", () => {
  it("mounts the application into the root element", async () => {
    await import("@/main");

    expect(createRootMock).toHaveBeenCalledWith(document.getElementById("root"));
    expect(renderMock).toHaveBeenCalledOnce();
    expect(renderMock.mock.calls[0][0]).toBeTruthy();
  });

  /**
   * The reload contract, at the level where it used to break.
   *
   * A reload must ask the API whether this browser has a session, *before* anything
   * is rendered, and it must do so on its own rather than as a side effect of a
   * module body. The version that shipped this question from a `persist`
   * rehydration callback asked it while the module graph was still being evaluated,
   * which is how a cycle between the store and the API client turned every reload
   * into a sign-in form: the call threw on a binding that did not exist yet, and the
   * catch around it looked exactly like "no session".
   */
  it("asks the API for the session before the first render", async () => {
    const order: string[] = [];
    restoreSessionMock.mockImplementation(async () => {
      order.push("ask");
      return null;
    });
    renderMock.mockImplementation(() => order.push("render"));

    await import("@/main");

    const { useAuthStore } = await import("@/store/auth");

    expect(order[0]).toBe("ask");
    expect(restoreSessionMock).toHaveBeenCalledTimes(1);
    // The answer is adopted rather than assumed: rendering waits on `isHydrated`,
    // and this is what releases it.
    await vi.waitFor(() => expect(useAuthStore.getState().isHydrated).toBe(true));
  });

  /**
   * The session lives in an HttpOnly cookie and in memory, and nowhere else.
   *
   * This is asserted at the boot because a store that persists itself would put
   * an e-mail address and a role in a browser the operator cannot clear from the
   * server, and the boot is the one place that would do it.
   */
  it("keeps nothing about the session in browser storage", async () => {
    restoreSessionMock.mockResolvedValue({
      access_token: "a",
      refresh_token: "r",
      token_type: "bearer",
      user: { id: "1", email: "admin@example.com", role: "admin" },
    });

    await import("@/main");

    const { useAuthStore } = await import("@/store/auth");
    await vi.waitFor(() => expect(useAuthStore.getState().isHydrated).toBe(true));

    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
