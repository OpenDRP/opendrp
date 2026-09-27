import { beforeEach, describe, expect, it, vi } from "vitest";
import type { User } from "@/types/api";

const { loginMock, restoreSessionMock } = vi.hoisted(() => ({
  loginMock: vi.fn(),
  restoreSessionMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: { login: loginMock },
  // The store never fetches the session itself: the request lives in the API
  // client, where it is single-flight (see lib/api.ts), and this mock stands in
  // for that function. What the store does with the answer is what is tested here.
  restoreSession: restoreSessionMock,
}));

import { useAuthStore } from "@/store/auth";
import { sessionAdopt, sessionClear, sessionPresent, sessionToken } from "@/lib/session-bridge";

const user: User = {
  id: "user-1",
  email: "admin@example.com",
  full_name: "Admin User",
  role: "admin",
  is_active: true,
  rate_limit_minutes: 0,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

const tokenResponse = {
  access_token: "access-token",
  token_type: "bearer" as const,
  expires_in: 900,
  user,
};

describe("auth store", () => {
  beforeEach(() => {
    loginMock.mockReset();
    restoreSessionMock.mockReset();
    localStorage.clear();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({ isHydrated: false });
  });

  it("stores the access session in memory and returns the user", async () => {
    loginMock.mockResolvedValue(tokenResponse);

    const result = await useAuthStore.getState().login(" admin@example.com ", "Password123!");
    const state = useAuthStore.getState();

    expect(result).toEqual(user);
    expect(loginMock).toHaveBeenCalledWith(" admin@example.com ", "Password123!");
    expect(state.user).toEqual(user);
    expect(state.token).toBe("access-token");
    expect(state.expiresAt).toBeGreaterThan(Date.now());
  });

  /**
   * The session is an HttpOnly cookie the browser holds, and the access token is
   * memory-only: there is nothing about it worth writing to `localStorage`, and a
   * copy there is only ever something to disagree with the server about. A signed-in
   * app must leave browser storage untouched.
   */
  it("keeps nothing about the session in browser storage", async () => {
    loginMock.mockResolvedValue(tokenResponse);

    await useAuthStore.getState().login(user.email, "Password123!");

    expect(localStorage.length).toBe(0);
  });

  /**
   * The boot question is asked on every load, whatever the browser remembers —
   * the cookie is the session of record and only the API can say whether it is
   * still valid.
   */
  it("asks the API for a session on every load and adopts a session it is given", async () => {
    restoreSessionMock.mockResolvedValue(tokenResponse);

    await useAuthStore.getState().restoreSession();

    expect(restoreSessionMock).toHaveBeenCalledTimes(1);
    const state = useAuthStore.getState();
    expect(state.isHydrated).toBe(true);
  });

  /**
   * The other half of the same answer: the API refused the cookie, so no user and
   * no token may survive. Keeping the user would let protected screens render a
   * page of failed requests on the way to the sign-in form.
   */
  it("drops the whole belief in the session when the API refuses the cookie", async () => {
    restoreSessionMock.mockResolvedValue(null);
    useAuthStore.setState({ user, token: "stale-token" });

    await useAuthStore.getState().restoreSession();
    const state = useAuthStore.getState();

    expect(state.user).toBeNull();
    expect(state.token).toBeNull();
    expect(state.expiresAt).toBeNull();
    expect(state.isHydrated).toBe(true);
  });

  /**
   * The API client cannot import this store — that import is what made the two
   * modules a cycle, and inside a cycle the bundle may run the store's module body
   * before the API client's, which is how a reload came to decide "no session"
   * without asking the server. It reaches the session through the bridge instead,
   * so the bridge has to be a working description of what this store holds.
   */
  it("publishes the session to the API client through the bridge", () => {
    expect(sessionPresent()).toBe(false);
    expect(sessionToken()).toBeNull();

    sessionAdopt(tokenResponse);

    expect(sessionToken()).toBe("access-token");
    expect(sessionPresent()).toBe(true);
    expect(useAuthStore.getState().user).toEqual(user);

    sessionClear();

    expect(sessionPresent()).toBe(false);
    expect(useAuthStore.getState().token).toBeNull();
  });

  it("clearAuth ends the session in memory", () => {
    useAuthStore.setState({ user, token: "token", expiresAt: Date.now() + 1000 });

    useAuthStore.getState().clearAuth();
    const state = useAuthStore.getState();

    expect(state.user).toBeNull();
    expect(state.token).toBeNull();
    expect(state.expiresAt).toBeNull();
  });
});
