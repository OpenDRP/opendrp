import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AssetDetailPage from "@/pages/AssetDetailPage";

const { findingsMock, getAssetMock, connectorModulesMock } = vi.hoisted(() => ({
  findingsMock: vi.fn(),
  getAssetMock: vi.fn(),
  connectorModulesMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: { assetFindings: findingsMock, getAsset: getAssetMock },
  describeApiError: (error: any) => String(error?.message ?? error ?? "Request failed"),
}));
// WI-20: what consumes the asset type comes from the connector registry.
vi.mock("@/lib/connectors", () => ({ fetchConnectorModules: connectorModulesMock }));

const asset = { id: "asset-1", asset_type: "domain", asset_value: "example.com", is_active: true };

// What `GET /assets/{id}` answers: the record the card shows, including the two
// fields the findings view never carried (AST-45).
const record = {
  ...asset,
  criticality: "high",
  normalized_value: "example.com",
  created_at: "2026-01-01T09:30:00Z",
  updated_at: "2026-02-03T18:45:00Z",
};

const counts = { phishing: 1, breaches: 2, dns: 0, exposure: 0, findings: 0, total: 3 };

const phishingRow = {
  id: "ph-1",
  module: "phishing",
  title: "look-alike.example",
  matched_asset: "example.com",
  source: "dnstwist",
  status: "active",
  observed_at: "2026-01-02T00:00:00Z",
};

const lastSeen = {
  phishing: "2026-01-02T00:00:00+00:00",
  breaches: "2024-01-01",
  dns: null,
  exposure: null,
  findings: null,
};

const connectorModules = {
  modules: {
    phishing: {
      label: "Phishing",
      enabled: true,
      asset_types: ["domain"],
      connectors: [{ name: "dnstwist", status: "enabled", asset_types: ["domain"] }],
    },
  },
};

function response(overrides: Record<string, unknown> = {}) {
  return {
    asset,
    counts,
    last_seen: lastSeen,
    module: "phishing",
    items: [phishingRow],
    total: 1,
    page: 1,
    size: 20,
    pages: 1,
    ...overrides,
  };
}

function renderPage(queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/assets/asset-1"]}>
        <Routes>
          <Route path="/assets/:id" element={<AssetDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AssetDetailPage", () => {
  beforeEach(() => {
    findingsMock.mockReset().mockResolvedValue(response());
    getAssetMock.mockReset().mockResolvedValue(record);
    connectorModulesMock.mockReset().mockResolvedValue(connectorModules);
  });

  it("shows the asset, every module tab with its counter, and the rows", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: "example.com" })).toBeInTheDocument();
    // The counters come from the response, so a module with nothing to show
    // still says so instead of looking untouched.
    for (const [label, count] of [
      ["Phishing", "1"],
      ["Breaches", "2"],
      ["DNS Security", "0"],
      ["Exposure", "0"],
      ["Other modules", "0"],
    ] as const) {
      expect(screen.getByRole("tab", { name: new RegExp(label) })).toHaveTextContent(count);
    }
    expect(await screen.findByText("look-alike.example")).toBeInTheDocument();
    // Scoped to the table: the connector registry card names the same connector
    // as the one that reported this row (WI-20).
    const table = screen.getByRole("table", { name: /findings for this asset/ });
    expect(within(table).getByText("dnstwist")).toBeInTheDocument();
    expect(findingsMock).toHaveBeenCalledWith("asset-1", { module: "phishing", page: 1, size: 20 });
    // AST-44/AST-45: the card reads the asset's own record once, and shows what
    // the findings endpoint never carried — criticality and both dates.
    expect(getAssetMock).toHaveBeenCalledTimes(1);
    expect(getAssetMock).toHaveBeenCalledWith("asset-1");
    expect(await screen.findByText("high")).toBeInTheDocument();
    expect(screen.getByText(/Created 2026-01-01 09:30:00/)).toBeInTheDocument();
    expect(screen.getByText(/Updated 2026-02-03 18:45:00/)).toBeInTheDocument();
  });

  it("does not re-read the asset record for every module tab (AWI-03)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("look-alike.example");

    await user.click(screen.getByRole("tab", { name: /Breaches/ }));
    await waitFor(() =>
      expect(findingsMock).toHaveBeenCalledWith("asset-1", expect.objectContaining({ module: "breaches" })),
    );

    // `asset.view` is one read per open; the tab asks a different question.
    expect(getAssetMock).toHaveBeenCalledTimes(1);
  });

  it("asks the backend for the module the operator opened and resets to page one", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("look-alike.example");


    await user.click(screen.getByRole("tab", { name: /Breaches/ }));

    await waitFor(() =>
      expect(findingsMock).toHaveBeenCalledWith("asset-1", {
        module: "breaches",
        page: 1,
        size: 20,
      }),
    );
  });

  it("says a module has nothing rather than showing an empty table", async () => {
    const user = userEvent.setup();
    findingsMock.mockImplementation((_id: string, params: { module: string }) =>
      Promise.resolve(
        response({
          module: params.module,
          items: params.module === "phishing" ? [phishingRow] : [],
          total: params.module === "phishing" ? 1 : 0,
          pages: params.module === "phishing" ? 1 : 0,
        }),
      ),
    );
    renderPage();
    await screen.findByRole("heading", { name: "example.com" });

    await user.click(screen.getByRole("tab", { name: /DNS Security/ }));

    expect(
      await screen.findByText("No DNS observation is about this asset."),
    ).toBeInTheDocument();
  });

  it("reports a failed load instead of an empty asset", async () => {
    findingsMock.mockRejectedValue(new Error("network down"));
    renderPage();

    expect(await screen.findByText("network down")).toBeInTheDocument();
    expect(screen.queryByText(/No phishing findings/)).not.toBeInTheDocument();
  });

  it("retries the same read after a failure and then shows the rows", async () => {
    // The failed read is an answer about the moment, not about the asset: the
    // retry has to ask again and, when the second answer arrives, replace the
    // error with what the module actually holds.
    findingsMock.mockRejectedValueOnce(new Error("network down"));
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Try again" }));

    expect(await screen.findByText("look-alike.example")).toBeInTheDocument();
    expect(screen.queryByText("network down")).not.toBeInTheDocument();
    expect(findingsMock).toHaveBeenCalledTimes(2);
  });

  it("re-reads the open module when the operator refreshes", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("look-alike.example");
    await user.click(screen.getByRole("tab", { name: /Breaches/ }));
    await waitFor(() =>
      expect(findingsMock).toHaveBeenCalledWith("asset-1", expect.objectContaining({ module: "breaches" })),
    );
    const before = findingsMock.mock.calls.length;

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    await waitFor(() => expect(findingsMock.mock.calls.length).toBe(before + 1));
    // The refresh repeats the open module at the page the operator is on rather
    // than falling back to the first tab.
    expect(findingsMock).toHaveBeenLastCalledWith("asset-1", expect.objectContaining({ module: "breaches" }));
  });

  it("says when the module the operator is reading last saw the asset (WI-20)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByRole("heading", { name: "example.com" });
    expect(screen.getByText(/Phishing: last seen 2026-01-02 00:00:00/)).toBeInTheDocument();

    // A module that never reported anything says so rather than showing a blank.
    await user.click(screen.getByRole("tab", { name: /DNS Security/ }));
    expect(await screen.findByText(/DNS Security: last seen never/)).toBeInTheDocument();
  });

  it("names what consumes the asset type (WI-20)", async () => {
    renderPage();
    await screen.findByRole("heading", { name: "example.com" });
    expect(await screen.findByText("Monitored by")).toBeInTheDocument();
    expect(screen.getByText(/Monitored by modules Phishing; connectors dnstwist/)).toBeInTheDocument();
  });

  it("says when no enabled module consumes the type, so the row is only recorded (WI-20)", async () => {
    findingsMock.mockResolvedValue(
      response({ asset: { ...asset, asset_type: "ip_address", asset_value: "203.0.113.9" } }),
    );
    getAssetMock.mockResolvedValue({
      ...record,
      asset_type: "ip_address",
      asset_value: "203.0.113.9",
    });
    renderPage();

    expect(
      await screen.findByText(/No enabled module consumes this type of asset/),
    ).toBeInTheDocument();
  });

  it("links back to the inventory", async () => {
    renderPage();
    const back = await screen.findByRole("link", { name: /All assets/ });
    expect(back).toHaveAttribute("href", "/assets");
    expect(within(back).getByText("All assets")).toBeInTheDocument();
  });

  /**
   * The asset's own record is a second read, and it is the one that carries
   * criticality, both dates and the "monitored by" card. When it failed the page
   * still rendered — heading "Asset", no badge, no dates — and said nothing, so a
   * refusal (a deleted asset, a narrowed role, a transport error) looked like an
   * asset nobody had ever filled in. The findings table could succeed at the same
   * time, which is exactly when the silence was most misleading.
   */
  it("says the asset record could not be read instead of showing a nameless asset", async () => {
    getAssetMock.mockRejectedValue(new Error("asset record unavailable"));
    renderPage();

    // The findings are a different read, and they still answer: the page is usable.
    expect(await screen.findByText("look-alike.example")).toBeInTheDocument();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("asset record unavailable");
  });

  /**
   * The record used to be cached for the life of the tab (`staleTime: Infinity`
   * with `refetchOnMount: false`) and nothing invalidated it, so an edit made on
   * the inventory page — a criticality, the value itself — was visible in the list
   * and invisible here after navigating back. One read per open is the intent;
   * reading nothing again is not.
   */
  it("re-reads the record when the asset is opened again", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const first = renderPage(client);
    expect(await screen.findByText("high")).toBeInTheDocument();
    first.unmount();

    getAssetMock.mockResolvedValue({ ...record, criticality: "critical" });
    renderPage(client);

    expect(await screen.findByText("critical")).toBeInTheDocument();
    expect(getAssetMock).toHaveBeenCalledTimes(2);
  });
});
