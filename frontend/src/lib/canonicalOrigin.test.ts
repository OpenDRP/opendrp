import { describe, expect, it } from "vitest";
import { canonicalNavigationUrl } from "@/lib/canonicalOrigin";

describe("canonicalNavigationUrl", () => {
  const location = {
    origin: "http://localhost",
    pathname: "/phishing",
    search: "?page=2",
    hash: "#jobs",
  } as Location;

  it("moves a port-80 page to the configured local UI origin", () => {
    expect(canonicalNavigationUrl(location, "http://localhost:3000")).toBe(
      "http://localhost:3000/phishing?page=2#jobs",
    );
  });

  it("does not navigate when already canonical or when unset", () => {
    expect(canonicalNavigationUrl({ ...location, origin: "http://localhost:3000" }, "http://localhost:3000")).toBeNull();
    expect(canonicalNavigationUrl(location, "")).toBeNull();
  });

  it("rejects credentials and path-bearing canonical origins", () => {
    expect(canonicalNavigationUrl(location, "http://user:pass@localhost:3000")).toBeNull();
    expect(canonicalNavigationUrl(location, "http://localhost:3000/app")).toBeNull();
  });
});
