import { describe, expect, it } from "vitest";
import {
  fieldErrorsFromApiError,
  KEYWORD_MAX_LENGTH,
  promotedAssetType,
  validateAssetValue,
} from "@/lib/assetValidation";

describe("validateAssetValue", () => {
  it("accepts the values the API accepts", () => {
    expect(validateAssetValue("domain", "example.com")).toBeNull();
    expect(validateAssetValue("domain", "Example.COM.")).toBeNull();
    // IDNA: a Unicode domain is valid input, not a typo.
    expect(validateAssetValue("domain", "münchen.de")).toBeNull();
    expect(validateAssetValue("ip_address", "10.0.0.1")).toBeNull();
    expect(validateAssetValue("ip_address", "2001:db8::1")).toBeNull();
    expect(validateAssetValue("email_account", "analyst@example.com")).toBeNull();
    expect(validateAssetValue("keyword_title", "My official portal")).toBeNull();
  });

  it("names the reason for each type", () => {
    expect(validateAssetValue("domain", "not a domain!!")).toBe("Invalid domain format");
    expect(validateAssetValue("domain", "")).toBe("Invalid domain format");
    expect(validateAssetValue("ip_address", "999.999.999.999")).toBe(
      "Invalid IP address format",
    );
    expect(validateAssetValue("email_account", "no-at-sign")).toBe("Invalid email format");
    expect(validateAssetValue("keyword_domain", "   ")).toBe("Keyword cannot be empty");
  });

  it("mirrors the keyword rules the connector query grammars need", () => {
    expect(validateAssetValue("keyword_domain", 'quote"inside')).toMatch(/quotes/);
    expect(validateAssetValue("keyword_domain", "back\\slash")).toMatch(/backslashes/);
    expect(validateAssetValue("keyword_title", "x".repeat(KEYWORD_MAX_LENGTH + 1))).toMatch(
      /at most 200/,
    );
    expect(validateAssetValue("keyword_title", "x".repeat(KEYWORD_MAX_LENGTH))).toBeNull();
  });

  it("leaves types it does not know to the server", () => {
    // Deliberately loose: a client rule that is stricter than the API would
    // refuse input the platform accepts.
    expect(validateAssetValue("something_else", "anything")).toBeNull();
  });
});

describe("promotedAssetType", () => {
  it("matches the type the promotion routes assign", () => {
    expect(promotedAssetType("203.0.113.9")).toBe("ip_address");
    expect(promotedAssetType("2001:db8::1")).toBe("ip_address");
    expect(promotedAssetType("host.example.com")).toBe("domain");
  });
});

describe("fieldErrorsFromApiError", () => {
  it("maps a FastAPI 422 back to the fields it names", () => {
    const error = {
      response: {
        status: 422,
        data: {
          detail: [
            { loc: ["body", "asset_value"], msg: "Invalid domain format", type: "value_error" },
            { loc: ["body", "criticality"], msg: "Input should be 'low', 'medium', 'high' or 'critical'", type: "literal_error" },
          ],
        },
      },
    };
    expect(fieldErrorsFromApiError(error)).toEqual({
      asset_value: "Invalid domain format",
      criticality: "Input should be 'low', 'medium', 'high' or 'critical'",
    });
  });

  it("returns nothing for errors that name no field", () => {
    expect(fieldErrorsFromApiError(new Error("network down"))).toEqual({});
    expect(
      fieldErrorsFromApiError({ response: { data: { detail: "Asset not found" } } }),
    ).toEqual({});
  });
});
