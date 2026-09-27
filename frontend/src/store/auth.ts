import { create } from "zustand";
import { endpoints, restoreSession as askApiForSession } from "@/lib/api";
import { registerSession } from "@/lib/session-bridge";
import type { TokenResponse, User } from "@/types/api";

type AuthState = {
  user: User | null;
  token: string | null;
  expiresAt: number | null;
  isHydrated: boolean;
  login: (email: string, password: string, totpCode?: string, recoveryCode?: string) => Promise<User>;
  /** Adopt a session the API minted outside the sign-in flow (a password change
   *  rotates the session, so the client has to take the new one or keep sending a
   *  token whose refresh cookie the server just revoked). */
  setSession: (data: TokenResponse) => void;
  logout: () => void;
  clearAuth: () => void;
  setUser: (user: User) => void;
  setToken: (token: string | null) => void;
  setExpiresAt: (expiresAt: number | null) => void;
  /** Ask the API whether this browser still has a session, and adopt the answer.
   *  Called once per load, from `main.tsx` — see the note on the store below. */
  restoreSession: () => Promise<void>;
};

/**
 * Where the session lives while a tab is open: in memory, plus an HttpOnly cookie
 * the browser holds and this code cannot read.
 *
 * Nothing is persisted to `localStorage`, on purpose. An earlier version kept a
 * copy of the signed-in user there and let it decide whether to ask the server for
 * the session — which made a browser-side note the switch for a server-side
 * cookie, and broke every reload where the note was missing, cleared or unreadable.
 * The cookie is the only session of record, so on every load the app asks the API
 * (`restoreSession`, called from `main.tsx`) and believes the answer. The access
 * token is deliberately memory-only as well: it must never be readable from
 * browser storage, where a script injection could lift it.
 */
export const useAuthStore = create<AuthState>()((set, get) => ({
  user: null,
  token: null,
  expiresAt: null,
  isHydrated: false,

  login: async (email: string, password: string, totpCode?: string, recoveryCode?: string) => {
    const data = recoveryCode
      ? await endpoints.login(email, password, undefined, recoveryCode)
      : totpCode
        ? await endpoints.login(email, password, totpCode)
        : await endpoints.login(email, password);
    set({
      user: data.user,
      token: data.access_token,
      expiresAt: Date.now() + data.expires_in * 1000 - 60_000,
    });
    return data.user;
  },

  setSession: (data: TokenResponse) => {
    set({
      user: data.user,
      token: data.access_token,
      expiresAt: Date.now() + data.expires_in * 1000 - 60_000,
    });
  },

  clearAuth: () => set({ user: null, token: null, expiresAt: null }),

  logout: () => {
    get().clearAuth();
  },

  setUser: (user: User) => set({ user }),
  setToken: (token: string | null) => set({ token }),
  setExpiresAt: (expiresAt: number | null) => set({ expiresAt }),

  /**
   * The boot question, and only that.
   *
   * The API client owns the call: it is the single-flight one (`lib/api.ts`), so a
   * reload and a request retrying a `401` cannot present the same rotating refresh
   * token twice. What is left here is what the answer means for this store — either
   * there is a session, or this browser has none and must stop believing it does,
   * because keeping a user around after the server refused the session renders a
   * screen of failed requests and *then* the sign-in form.
   *
   * This runs on every load, so it must never announce a sign-out: a browser that
   * never signed in is not a browser whose session expired.
   */
  restoreSession: async () => {
    const session = await askApiForSession();
    set(
      session
        ? { isHydrated: true }
        : { user: null, token: null, expiresAt: null, isHydrated: true },
    );
  },
}));

/**
 * Let the API client reach this session.
 *
 * It cannot import the store — that is the import which made the two modules a
 * cycle, and inside a cycle the bundle is free to run the store's module body
 * before the API client's, which is how a reload ended up deciding "no session"
 * without ever asking. This registration runs while this module is evaluated, so
 * the bridge is pointed at the store before anything can issue a request.
 * The dependency direction is store → api → bridge, one way only, and
 * `src/lib/moduleGraph.test.ts` fails if that ever stops being true.
 */
registerSession({
  token: () => useAuthStore.getState().token,
  present: () => useAuthStore.getState().user !== null,
  adopt: (data) => useAuthStore.getState().setSession(data),
  clear: () => useAuthStore.getState().clearAuth(),
});

export const useIsAdmin = () => useAuthStore((s) => s.user?.role === "admin");

export const useIsAnalystPlus = () => {
  const r = useAuthStore((s) => s.user?.role);
  return r === "admin" || r === "analyst";
};

export const useIsAuthenticated = () => useAuthStore((s) => !!s.token && !!s.user);
