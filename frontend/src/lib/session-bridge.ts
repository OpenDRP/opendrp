import type { TokenResponse } from "@/types/api";

/**
 * The one channel between the API client and the session store.
 *
 * `lib/api.ts` needs four things from `store/auth.ts`: the access token to attach
 * to every request, whether a session is believed to exist at all, somewhere to
 * put a session the API just minted, and an audience for "the session is gone".
 * Importing the store to get them makes the two modules import each other — and
 * in a production bundle a cycle is not a style question. Rollup flattens the
 * graph into a single file and, inside a cycle, is free to place the store's
 * module body before the one that defines the API client object: the store's own
 * code then reaches a binding that does not exist yet, throws, and the app
 * concludes it has no session *without asking the server anything*. That is a
 * silent failure, because the store action that does the asking catches its own
 * errors. Vite hides the only warning that would have named it, so the discovery
 * is a sign-in form that reappears on every reload.
 *
 * This module imports nothing but a type — erased at compile time — so it is a
 * leaf of the graph and is evaluated before both of them. The dependency
 * direction becomes store → api → bridge: one way, no cycle.
 *
 * It is deliberately a plain registry rather than a store of its own: the session
 * lives in the cookie and in the auth store, and a second copy here would be one
 * more thing to keep in step.
 */
export type SessionOwner = {
  /** The access token for the next request, or `null` when there is none. */
  token: () => string | null;
  /** Whether a session is believed to exist. The refresh token is HttpOnly and
   *  invisible to this code, so this is the client-side signal that a cookie
   *  worth presenting may be there — the API decides whether it still is. */
  present: () => boolean;
  /** Adopt a session the API minted: a sign-in, a password change, a refresh. */
  adopt: (data: TokenResponse) => void;
  /** Forget the session in this browser. */
  clear: () => void;
};

let owner: SessionOwner | null = null;

/**
 * Point the bridge at the store. Called while the store's module body runs, which
 * is before anything in the application can issue a request.
 */
export function registerSession(next: SessionOwner): void {
  owner = next;
}

export function sessionToken(): string | null {
  return owner?.token() ?? null;
}

export function sessionPresent(): boolean {
  return owner?.present() ?? false;
}

export function sessionAdopt(data: TokenResponse): void {
  owner?.adopt(data);
}

export function sessionClear(): void {
  owner?.clear();
}
