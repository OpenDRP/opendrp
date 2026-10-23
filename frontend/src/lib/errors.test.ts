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

  it("names the condition behind a 503 rather than calling it a server error", () => {
    // The two codes the API sends with a 503 are answers an operator can act on:
    // a query that was stopped on purpose while the database was busy, and a
    // deadline. Rendering them as "server error" sends the operator to wait for
    // an outage that is not happening.
    expect(
      describeApiError({ response: { status: 503, data: { code: "database_busy" } } }),
    ).toMatch(/database stopped this query/i);
    expect(
      describeApiError({
        response: { status: 503, data: { code: "query_deadline_exceeded" } },
      }),
    ).toMatch(/time budget/i);
    // The code is decisive even when a detail arrives with it: `database_busy`
    // names a condition the client recognises, and the sentence it maps to tells
    // the operator what to do about it.
    expect(
      describeApiError({
        response: { status: 503, data: { code: "database_busy", detail: "canceling statement due to statement timeout" } },
      }),
    ).toMatch(/database stopped this query/i);
  });

  it("quotes the correlation id so a screenshot can find the server record", async () => {
    expect(
      describeApiError({
        response: { status: 500, headers: { "x-request-id": "web-abc123" } },
      }),
    ).toBe("The server reported an error. Please retry shortly. (Reference: web-abc123)");

    // A failure that never reached the API still has the id the request carried.
    expect(
      describeApiError({ message: "Network Error", config: { headers: { "X-Request-ID": "web-offline" } } }),
    ).toBe("Network Error (Reference: web-offline)");
    // And an error with no identifier at all does not grow an empty suffix.
    expect(describeApiError({ message: "Network Error" })).toBe("Network Error");
  });

  it("falls back to the transport message and then to the caller default", () => {
    expect(describeApiError(new Error("Network Error"))).toBe("Network Error");
    expect(describeApiError(undefined, "Custom fallback")).toBe("Custom fallback");
  });
});
