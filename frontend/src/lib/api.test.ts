import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AxiosRequestConfig, AxiosResponse } from "axios";

import {
  api,
  flattenErrorDetail,
  isMfaRequiredError,
  isOnboardingRequiredError,
  restoreSession,
} from "@/lib/api";
import { useAuthStore } from "@/store/auth";

function response<T>(config: AxiosRequestConfig, data: T, status = 200): AxiosResponse<T> {
  return {
    data,
    status,
    statusText: status === 200 ? "OK" : "Unauthorized",
    headers: {},
    config: config as AxiosResponse<T>["config"],
  };
}

describe("frontend API boundary", () => {
  const originalAdapter = api.defaults.adapter;

  beforeEach(() => {
    localStorage.clear();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({ isHydrated: true });
    vi.restoreAllMocks();
  });

  afterEach(() => {
    api.defaults.adapter = originalAdapter;
  });

  it("flattens string, validation-array, object, and empty error details", () => {
    expect(flattenErrorDetail("invalid credentials")).toBe("invalid credentials");
    expect(
      flattenErrorDetail([{ msg: "email is invalid" }, { msg: "password is required" }]),
    ).toBe("email is invalid; password is required");
    expect(flattenErrorDetail({ reason: "locked", retry_after: 30 })).toBe("locked; 30");
    expect(flattenErrorDetail(null)).toBe("");
  });

  it("adds bearer and CSRF headers only to authenticated state-changing requests", async () => {
    useAuthStore.setState({ token: "access-token", user: null });
    Object.defineProperty(document, "cookie", {
      configurable: true,
      value: "opendrp_csrf=csrf-token",
    });

    let captured: AxiosRequestConfig | undefined;
    api.defaults.adapter = async (config) => {
      captured = config;
      return response(config, { ok: true });
    };

    await api.post("/assets", { asset_value: "example.com" });

    expect(captured?.headers?.Authorization).toBe("Bearer access-token");
    expect(captured?.headers?.["X-CSRF-Token"]).toBe("csrf-token");
  });

  it("does not trust a persisted token when only user metadata is stored", async () => {
    localStorage.setItem(
      "opendrp-auth-storage",
      JSON.stringify({ state: { user: { id: "u1" }, token: "must-not-be-used" } }),
    );

    let captured: AxiosRequestConfig | undefined;
    api.defaults.adapter = async (config) => {
      captured = config;
      return response(config, { ok: true });
    };

    await api.get("/dashboard/stats");

    expect(captured?.headers?.Authorization).toBeUndefined();
  });

  it("refreshes through the HttpOnly cookie session when the access token expires", async () => {
    const user = { id: "u1", email: "viewer@example.com", role: "viewer", is_active: true } as never;
    useAuthStore.setState({ user, token: "stale-token" });
    let calls = 0;

    api.defaults.adapter = async (config) => {
      calls += 1;
      if (calls === 1) {
        throw {
          config,
          response: response(config, { detail: "expired" }, 401),
          isAxiosError: true,
        };
      }
      if (String(config.url).includes("/auth/refresh")) {
        return response(config, {
          access_token: "refreshed-token",
          expires_in: 900,
          token_type: "bearer",
          user,
        });
      }
      return response(config, { ok: true });
    };

    await expect(api.get("/dashboard/stats")).resolves.toMatchObject({ data: { ok: true } });
    expect(useAuthStore.getState().token).toBe("refreshed-token");
    expect(calls).toBe(3);
  });

  it("clears auth and emits unauthorized for an auth endpoint 401", async () => {
    useAuthStore.setState({ user: { id: "u1" } as never, token: "stale-token" });
    const unauthorized = vi.fn();
    window.addEventListener("auth:unauthorized", unauthorized);

    api.defaults.adapter = async (config) => {
      throw {
        config,
        response: response(config, { detail: "invalid" }, 401),
        isAxiosError: true,
      };
    };

    await expect(api.post("/auth/login", {})).rejects.toBeDefined();

    expect(useAuthStore.getState().token).toBeNull();
    expect(unauthorized).toHaveBeenCalledTimes(1);
    window.removeEventListener("auth:unauthorized", unauthorized);
  });

  it("recognizes a required-second-factor 403 and not a plain permission 403", () => {
    expect(
      isMfaRequiredError({
        response: {
          status: 403,
          data: { detail: "Second factor required (mfa_required): this deployment requires administrators to enable MFA." },
        },
      }),
    ).toBe(true);

    // A role-based refusal is a different situation: the account cannot fix it
    // by enrolling, so the client must not react to it at all.
    expect(isMfaRequiredError({ response: { status: 403, data: { detail: "Admin role required" } } })).toBe(false);
    expect(isMfaRequiredError({ response: { status: 401, data: { detail: "mfa_required" } } })).toBe(false);
    expect(isMfaRequiredError(undefined)).toBe(false);
  });

  it("recognizes a credential-onboarding 403 and not a plain permission 403", () => {
    expect(
      isOnboardingRequiredError({
        response: {
          status: 403,
          data: {
            detail:
              "Credential onboarding required (onboarding_required): this account must set a password of your own before the rest of the platform is available.",
          },
        },
      }),
    ).toBe(true);

    // The two 403 gates are distinct: a role refusal the account cannot fix, and
    // the admin second-factor policy, which the client handles separately.
    expect(
      isOnboardingRequiredError({ response: { status: 403, data: { detail: "Admin role required" } } }),
    ).toBe(false);
    expect(
      isOnboardingRequiredError({ response: { status: 403, data: { detail: "mfa_required" } } }),
    ).toBe(false);
    expect(isOnboardingRequiredError({ response: { status: 401, data: { detail: "onboarding_required" } } })).toBe(false);
    expect(isOnboardingRequiredError(undefined)).toBe(false);
  });

  it("announces a pending credential step without clearing the session", async () => {
    useAuthStore.setState({ user: { id: "u1" } as never, token: "valid-token" });
    const onboardingRequired = vi.fn();
    const unauthorized = vi.fn();
    window.addEventListener("auth:onboarding-required", onboardingRequired);
    window.addEventListener("auth:unauthorized", unauthorized);

    api.defaults.adapter = async (config) => {
      throw {
        config,
        response: response(
          config,
          { detail: "Credential onboarding required (onboarding_required)" },
          403,
        ),
        isAxiosError: true,
      };
    };

    await expect(api.get("/assets")).rejects.toBeDefined();

    expect(onboardingRequired).toHaveBeenCalledTimes(1);
    // Same reasoning as the second-factor gate: the session is valid and only
    // needs a credential replaced, so it must survive the refusal.
    expect(unauthorized).not.toHaveBeenCalled();
    expect(useAuthStore.getState().token).toBe("valid-token");

    window.removeEventListener("auth:onboarding-required", onboardingRequired);
    window.removeEventListener("auth:unauthorized", unauthorized);
  });

  it("announces a required second factor without clearing the session", async () => {
    useAuthStore.setState({ user: { id: "u1" } as never, token: "valid-token" });
    const mfaRequired = vi.fn();
    const unauthorized = vi.fn();
    window.addEventListener("auth:mfa-required", mfaRequired);
    window.addEventListener("auth:unauthorized", unauthorized);

    api.defaults.adapter = async (config) => {
      throw {
        config,
        response: response(config, { detail: "Second factor required (mfa_required)" }, 403),
        isAxiosError: true,
      };
    };

    await expect(api.get("/users")).rejects.toBeDefined();

    expect(mfaRequired).toHaveBeenCalledTimes(1);
    // The account is signed in and merely not yet allowed, so the token must
    // survive: signing it out would send the operator to a page that cannot
    // help and make them sign in again to reach the one that can.
    expect(unauthorized).not.toHaveBeenCalled();
    expect(useAuthStore.getState().token).toBe("valid-token");

    window.removeEventListener("auth:mfa-required", mfaRequired);
    window.removeEventListener("auth:unauthorized", unauthorized);
  });

  /**
   * The boot-time restore is the only request whose 401 is an answer rather than
   * a failure: every anonymous visitor gets one. It still drops any local belief
   * in a session — it just does not announce a sign-out, because a browser that
   * never signed in is not one whose session expired, and the announcement would
   * both say so and navigate away from the page that was requested.
   */
  it("takes a refused boot restore quietly and still forgets the session", async () => {
    useAuthStore.setState({ user: { id: "u1" } as never, token: "stale-token" });
    const unauthorized = vi.fn();
    window.addEventListener("auth:unauthorized", unauthorized);

    api.defaults.adapter = async (config) => {
      throw {
        config,
        response: response(config, { detail: "Refresh token is required" }, 401),
        isAxiosError: true,
      };
    };

    // The refusal is an answer, not a failure: every anonymous visitor gets one.
    await expect(restoreSession()).resolves.toBeNull();

    expect(unauthorized).not.toHaveBeenCalled();
    expect(useAuthStore.getState().token).toBeNull();
    expect(useAuthStore.getState().user).toBeNull();
    window.removeEventListener("auth:unauthorized", unauthorized);
  });

  it("adopts the session it restored, so the store and the requests agree", async () => {
    const user = { id: "u1", email: "admin@example.com", role: "admin" } as never;

    api.defaults.adapter = async (config) =>
      response(config, {
        access_token: "restored-token",
        expires_in: 900,
        token_type: "bearer",
        user,
      });

    await expect(restoreSession()).resolves.toMatchObject({ access_token: "restored-token" });

    expect(useAuthStore.getState().token).toBe("restored-token");
    expect(useAuthStore.getState().user).toEqual(user);
    expect(useAuthStore.getState().isHydrated).toBe(true);
  });

  /**
   * The refresh token is rotated on every use, so a second presentation of the same
   * one is indistinguishable from a stolen token being replayed — the API revokes
   * the whole family, which signs the operator out of the tab that was working. Two
   * callers can overlap (the reload in `main.tsx`, and a request retrying a `401`),
   * and they must end up sharing one request rather than racing each other.
   */
  it("asks for a restored session once even when two callers overlap", async () => {
    let refreshCalls = 0;
    api.defaults.adapter = async (config) => {
      if (String(config.url).includes("/auth/refresh")) {
        refreshCalls += 1;
        return response(config, {
          access_token: `token-${refreshCalls}`,
          expires_in: 900,
          token_type: "bearer",
          user: { id: "u1" } as never,
        });
      }
      return response(config, { ok: true });
    };

    const [first, second] = await Promise.all([restoreSession(), restoreSession()]);

    expect(refreshCalls).toBe(1);
    expect(first?.access_token).toBe("token-1");
    expect(second?.access_token).toBe("token-1");
    expect(useAuthStore.getState().token).toBe("token-1");
  });
});
