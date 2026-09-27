import { describe, expect, it } from "vitest";
import { describeApiError } from "@/lib/api";

describe("describeApiError", () => {
  it("flattens a validation-error list into a readable string", () => {
    const message = describeApiError({
      response: {
        status: 422,
        data: {
          detail: [
            { msg: "email is invalid", loc: ["body", "email"] },
            { msg: "password is too short", loc: ["body", "password"] },
          ],
        },
      },
    });

    expect(typeof message).toBe("string");
    expect(message).toBe("email is invalid; password is too short");
  });

  it("prefers the server message for a string detail", () => {
    expect(
      describeApiError({ response: { status: 429, data: { detail: "Try again in 15 minutes." } } }),
    ).toBe("Try again in 15 minutes.");
  });

  it("explains common statuses when the server sends no detail", () => {
    expect(describeApiError({ response: { status: 401 } })).toMatch(/session has expired/i);
    expect(describeApiError({ response: { status: 403 } })).toMatch(/permission/i);
    expect(describeApiError({ response: { status: 429 } })).toMatch(/rate limit/i);
    expect(describeApiError({ response: { status: 503 } })).toMatch(/server reported an error/i);
  });

  it("falls back to the transport message and then to the caller default", () => {
    expect(describeApiError(new Error("Network Error"))).toBe("Network Error");
    expect(describeApiError(undefined, "Custom fallback")).toBe("Custom fallback");
  });
});
