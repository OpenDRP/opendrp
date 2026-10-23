import { afterEach, describe, expect, it } from "vitest";
import type { AxiosRequestConfig } from "axios";

import { api } from "@/lib/api";
import { fetchConnectorModules, issueConnectorToken, revokeConnectorToken } from "@/lib/connectors";
import { updateFindingStatus } from "@/lib/findings";
import {
  declaredModules,
  fetchModuleFindings,
  fetchModules,
  updateModule,
} from "@/lib/modules";

/**
 * The three registry helpers that the pages call but no page test reaches.
 *
 * The asset pages and the settings page mock these modules, so the paths they
 * write were never part of any assertion — and a path is the one thing here that
 * can be wrong without the component noticing. The connector-token helpers are
 * the sharpest case: the plaintext credential is returned exactly once, so a
 * mistyped route means an operator is told a token exists that they can never use.
 */

async function capture(call: () => Promise<unknown>): Promise<AxiosRequestConfig> {
  let captured: AxiosRequestConfig | undefined;
  const original = api.defaults.adapter;
  api.defaults.adapter = async (config) => {
    captured = config;
    return {
      data: {},
      status: 200,
      statusText: "OK",
      headers: {},
      config: config as never,
    };
  };
  try {
    await call();
  } finally {
    api.defaults.adapter = original;
  }
  if (!captured) throw new Error("the helper made no request");
  return captured;
}

const id = "b3d1c0de-0000-4000-8000-000000000001";

describe("connector registry helpers", () => {
  it("reads the module registry at the path the API serves it from", async () => {
    const sent = await capture(() => fetchConnectorModules());
    expect(sent.method).toBe("get");
    expect(sent.url).toBe("/connectors/modules");
  });

  it("issues a token with a POST to the connector's own route", async () => {
    const sent = await capture(() => issueConnectorToken(id));
    expect(sent.method).toBe("post");
    expect(sent.url).toBe(`/connectors/${id}/token`);
  });

  it("revokes a token with a DELETE on the same route", async () => {
    const sent = await capture(() => revokeConnectorToken(id));
    expect(sent.method).toBe("delete");
    expect(sent.url).toBe(`/connectors/${id}/token`);
  });
});

describe("generic finding helpers", () => {
  it("sends only the status, to the finding's encoded id", async () => {
    const sent = await capture(() => updateFindingStatus("finding/with space", "resolved"));
    expect(sent.method).toBe("patch");
    expect(sent.url).toBe("/findings/finding%2Fwith%20space");
    expect(JSON.parse(String(sent.data))).toEqual({ status: "resolved" });
  });
});

describe("module registry helpers", () => {
  it("reads every registered module, enabled or not", async () => {
    const sent = await capture(() => fetchModules());
    expect(sent.method).toBe("get");
    expect(sent.url).toBe("/modules");
  });

  it("pages generic findings by module, with the defaults the page relies on", async () => {
    const sent = await capture(() => fetchModuleFindings("brand_watcher"));
    expect(sent.url).toBe("/findings");
    expect(sent.params).toEqual({ module: "brand_watcher", page: 1, size: 20 });

    const second = await capture(() => fetchModuleFindings("brand_watcher", 3, 50));
    expect(second.params).toEqual({ module: "brand_watcher", page: 3, size: 50 });
  });

  it("patches a module with only the fields the operator changed", async () => {
    const sent = await capture(() => updateModule("module:brand", { enabled: false }));
    expect(sent.method).toBe("patch");
    expect(sent.url).toBe("/modules/module:brand");
    expect(JSON.parse(String(sent.data))).toEqual({ enabled: false });
  });

  it("renders only the modules the registry says are stored generically", () => {
    const declared = declaredModules([
      { id: "module:phishing", storage: "native" },
      { id: "module:brand", storage: "generic" },
    ] as never);
    expect(declared.map((module) => module.id)).toEqual(["module:brand"]);
    // A registry that has not loaded yet is not an error: the navigation simply
    // has no generic entries.
    expect(declaredModules(undefined)).toEqual([]);
  });
});
