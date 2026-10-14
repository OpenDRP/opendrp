import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import AssetsPage from "@/pages/AssetsPage";
import { useAuthStore } from "@/store/auth";

const {
  listMock,
  createMock,
  updateMock,
  deleteMock,
  findingsMock,
  exportMock,
  importMock,
  importCsvMock,
  connectorModulesMock,
  toastMock,
} = vi.hoisted(() => ({
  listMock: vi.fn(),
  createMock: vi.fn(),
  updateMock: vi.fn(),
  deleteMock: vi.fn(),
  findingsMock: vi.fn(),
  exportMock: vi.fn(),
  importMock: vi.fn(),
  importCsvMock: vi.fn(),
  connectorModulesMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listAssets: listMock,
    createAsset: createMock,
    updateAsset: updateMock,
    deleteAsset: deleteMock,
    assetFindings: findingsMock,
    exportAssets: exportMock,
    importAssets: importMock,
    importAssetsCsv: importCsvMock,
  },
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
}));
vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));
// The connector registry declares which modules consume which asset type (WI-20),
// so the page reads it instead of guessing from a hardcoded table.
vi.mock("@/lib/connectors", () => ({ fetchConnectorModules: connectorModulesMock }));
vi.mock("@/components/ui/select", () => ({
  // A native select stands in for the Radix one: the contract the page relies on
  // is `value` + `onValueChange`, and a test that drove Radix's own keyboard
  // handling would be testing the component library rather than this page.
  Select: ({ value, onValueChange, children }: any) => {
    // The page always renders `<SelectTrigger aria-label=…>` then the options,
    // so the stand-in can carry the same accessible name and options.
    const parts = Array.isArray(children) ? children : [children];
    const label = parts[0]?.props?.["aria-label"];
    const options = parts[parts.length - 1]?.props?.children;
    return (
      <select aria-label={label} value={value} onChange={(event) => onValueChange(event.target.value)}>
        {Array.isArray(options) ? options : null}
      </select>
    );
  },
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: any) => <>{children}</>,
  SelectItem: ({ value, children }: any) => <option value={value}>{children}</option>,
}));
vi.mock("@/components/DataTable", () => ({
  PaginatedDataTable: ({ columns, rows }: any) => (
    <div>{rows.map((row: any) => <div key={row.id}>{columns.map((column: any) => <span key={column.key}>{column.render ? column.render(row) : row[column.key]}</span>)}</div>)}</div>
  ),
}));
vi.mock("@/components/ui/confirm-dialog", () => ({
  // `confirmDisabled` is part of the contract the page relies on (WI-23), so the
  // stand-in honours it: a test that clicked through it would be testing a
  // dialog that cannot exist in the browser.
  ConfirmDialog: ({ open, title, children, onConfirm, onCancel, confirmDisabled }: any) => open ? (
    <div role="dialog"><h2>{title}</h2>{children}<button onClick={onCancel}>Cancel confirmation</button><button onClick={onConfirm} disabled={confirmDisabled}>Confirm action</button></div>
  ) : null,
}));

const asset = {
  id: "asset-1",
  asset_type: "domain",
  asset_value: "example.com",
  criticality: "high",
  is_active: true,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
  // WI-20: the backend sends each list row its involvement summary.
  findings: {
    total: 3,
    phishing: 1,
    breaches: 1,
    dns: 0,
    exposure: 0,
    findings: 1,
    last_seen: { phishing: "2026-01-02T00:00:00+00:00", breaches: "2024-01-01" },
  },
};

/** A registry that declares domain as consumed, and ip_address as nobody's. */
const connectorModules = {
  modules: {
    phishing: {
      label: "Phishing",
      enabled: true,
      asset_types: ["domain"],
      connectors: [{ name: "dnstwist", status: "enabled", asset_types: ["domain"] }],
    },
    breaches: {
      label: "Breaches",
      enabled: true,
      asset_types: ["domain", "email_account"],
      connectors: [],
    },
    retired: {
      label: "Retired",
      enabled: false,
      asset_types: ["ip_address"],
      connectors: [],
    },
  },
};

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  // The value column links to the asset's own page (WI-12), so the page needs a
  // router in scope.
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AssetsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AssetsPage", () => {
  beforeEach(() => {
    listMock.mockReset().mockResolvedValue({ items: [asset], total: 1, page: 1, size: 20, pages: 1 });
    createMock.mockReset().mockResolvedValue(asset);
    updateMock.mockReset().mockResolvedValue(asset);
    deleteMock.mockReset().mockResolvedValue({});
    findingsMock.mockReset().mockResolvedValue({ counts: { total: 0, phishing: 0, breaches: 0, dns: 0, exposure: 0, findings: 0 }, items: [], page: 1, size: 1, pages: 0 });
    exportMock.mockReset().mockResolvedValue(new Blob(["asset_type,asset_value\n"], { type: "text/csv" }));
    importMock.mockReset();
    connectorModulesMock.mockReset().mockResolvedValue(connectorModules);
    importCsvMock.mockReset().mockResolvedValue({
      dry_run: false,
      created: 1,
      duplicate: 1,
      invalid: 1,
      rows: [
        { line: 2, outcome: "created", asset_type: "domain", asset_value: "csv-one.example", detail: null },
        { line: 3, outcome: "duplicate", asset_type: "domain", asset_value: "example.com", detail: "This value is already monitored" },
        { line: 4, outcome: "invalid", asset_type: "domain", asset_value: "broken!", detail: "Invalid domain format" },
      ],
    });
    toastMock.mockReset();
    useAuthStore.getState().clearAuth();
    useAuthStore.setState({
      user: { id: "admin-1", email: "admin@example.com", role: "admin", is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      token: "access-token",
      isHydrated: true,
    });
  });

  it("loads assets and validates an empty create form", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("example.com")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Add asset" }));
    const dialog = screen.getByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(createMock).not.toHaveBeenCalled();
    expect(toastMock).toHaveBeenCalledWith(expect.objectContaining({ variant: "destructive", title: "Validation" }));
  });

  it("renders one value per row even for a row that still carries a differing normalized_value", async () => {
    // Rows written before `create_asset` stored the canonical form in
    // `asset_value` can still carry a differing `normalized_value`. The table
    // shows the stored value once instead of a second "↳ normalized" line that
    // the API never keeps in sync (WI-07 / AST-26).
    listMock.mockResolvedValue({ items: [{ ...asset, asset_value: "Example.COM", normalized_value: "example.com" }], total: 1, page: 1, size: 20, pages: 1 });
    renderPage();
    expect(await screen.findByText("Example.COM")).toBeInTheDocument();
    expect(screen.queryByText(/↳/)).not.toBeInTheDocument();
    expect(screen.queryByText("example.com")).not.toBeInTheDocument();
  });

  it("promises exactly what the cascade does: findings go, source observations stay", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Delete asset" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/phishing, breach and generic findings/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Source observations are kept/)).toBeInTheDocument();
  });

  it("creates an asset and deletes related findings with cascade", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Add asset" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Value"), "new.example.com");
    await user.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(createMock).toHaveBeenCalledWith({ asset_type: "domain", asset_value: "new.example.com", criticality: "medium" }));

    await user.click(screen.getByRole("button", { name: "Delete asset" }));
    const deleteDialog = screen.getByRole("dialog");
    await user.click(within(deleteDialog).getByRole("checkbox"));
    // The cascade is confirmed by typing the value (WI-23).
    await user.type(
      within(deleteDialog).getByLabelText(/Type the asset value/),
      "example.com",
    );
    await user.click(within(deleteDialog).getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(deleteMock).toHaveBeenCalledWith("asset-1", true));
  });

  it("asks for the value before a cascade delete and explains why (WI-23)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Delete asset" }));
    const dialog = screen.getByRole("dialog");

    // Without the cascade, deleting stays a single confirmation: re-adding an
    // asset recreates it, so nothing here is irrecoverable.
    expect(within(dialog).getByRole("button", { name: "Confirm action" })).toBeEnabled();

    await user.click(within(dialog).getByRole("checkbox"));
    const confirm = within(dialog).getByRole("button", { name: "Confirm action" });
    expect(confirm).toBeDisabled();
    expect(within(dialog).getByText(/This part cannot be undone/)).toBeInTheDocument();

    const typed = within(dialog).getByLabelText(/Type the asset value/);
    await user.type(typed, "example.co");
    expect(confirm).toBeDisabled();
    await user.type(typed, "m");
    expect(confirm).toBeEnabled();
  });

  it("keeps the delete dialog open with the reason when the delete fails (WI-21)", async () => {
    const user = userEvent.setup();
    deleteMock.mockRejectedValue(new Error("The database is busy"));
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Delete asset" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Confirm action" }));

    // The dialog is where the decision was made, so it is where the failure is
    // readable — and where the operator can retry it.
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("The database is busy");
  });

  it("refuses a value the API would refuse before sending it (WI-19)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Add asset" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Value"), "not a domain!!");
    await user.click(within(dialog).getByRole("button", { name: "Create" }));

    expect(createMock).not.toHaveBeenCalled();
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Invalid domain format");
    // Typing again clears the message rather than leaving a stale complaint.
    await user.type(within(dialog).getByLabelText("Value"), ".example");
    expect(within(dialog).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("exports the current filter as a file (WI-18)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Export" }));

    await waitFor(() =>
      expect(exportMock).toHaveBeenCalledWith(
        expect.objectContaining({ format: "csv", sort: "created_at", order: "desc" }),
      ),
    );
    expect(toastMock).toHaveBeenCalledWith(expect.objectContaining({ title: "Export ready" }));
  });

  it("previews an import and reports every line of the real one (WI-18)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Import" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Assets to import"), "asset_type,asset_value,{enter}domain,a.example,");

    await user.click(within(dialog).getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(importCsvMock).toHaveBeenCalledWith(expect.any(String), true));

    await user.click(within(dialog).getByRole("button", { name: "Import" }));
    await waitFor(() => expect(importCsvMock).toHaveBeenCalledWith(expect.any(String), false));

    const report = await within(dialog).findByRole("status", { name: "Import report" });
    expect(report).toHaveTextContent("1 to create, 1 already monitored, 1 rejected");
    expect(within(report).getByText("created")).toBeInTheDocument();
    expect(within(report).getByText("duplicate")).toBeInTheDocument();
    expect(within(report).getByText("invalid")).toBeInTheDocument();
  });

  it("reads pasted JSON as items rather than as CSV (WI-18)", async () => {
    const user = userEvent.setup();
    importMock.mockResolvedValue({ dry_run: true, created: 1, duplicate: 0, invalid: 0, rows: [] });
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Import" }));
    const dialog = screen.getByRole("dialog");
    // Pasted rather than typed: `user.type` reads braces as key descriptors, and
    // pasting is how JSON actually arrives in this box.
    const box = within(dialog).getByLabelText("Assets to import");
    await user.click(box);
    await user.paste('{"items": [{"asset_type": "domain", "asset_value": "json.example"}]}');
    await user.click(within(dialog).getByRole("button", { name: "Preview" }));
    await waitFor(() =>
      expect(importMock).toHaveBeenCalledWith([{ asset_type: "domain", asset_value: "json.example" }], true),
    );
    expect(importCsvMock).not.toHaveBeenCalled();
  });

  it("shows how much the platform holds about a row, and when it last saw it (WI-20)", async () => {
    renderPage();
    expect(await screen.findByText("3 found")).toBeInTheDocument();
    // The latest moment across modules, whichever kind of date it is.
    expect(screen.getByText(/last seen 2026-01-02 00:00:00/)).toBeInTheDocument();
    expect(
      screen.getByTitle(/3 related findings: phishing 1, breaches 1/),
    ).toBeInTheDocument();
  });

  it("says an asset nothing was reported about is not involved (WI-20)", async () => {
    listMock.mockResolvedValue({
      items: [{
        ...asset,
        findings: { total: 0, phishing: 0, breaches: 0, dns: 0, exposure: 0, findings: 0, last_seen: {} },
      }],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
    renderPage();
    expect(await screen.findByText("none found")).toBeInTheDocument();
    expect(screen.getByText("never seen")).toBeInTheDocument();
  });

  it("asks the server for the involvement filter instead of filtering one page (WI-20)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");

    await user.selectOptions(screen.getByLabelText("Filter by findings"), "with");

    await waitFor(() =>
      expect(listMock).toHaveBeenCalledWith(expect.objectContaining({ has_findings: true })),
    );
    await user.selectOptions(screen.getByLabelText("Filter by findings"), "without");
    await waitFor(() =>
      expect(listMock).toHaveBeenCalledWith(expect.objectContaining({ has_findings: false })),
    );
  });

  it("names what consumes the asset type, and flags one nothing consumes (WI-20)", async () => {
    renderPage();
    expect(await screen.findByText("example.com")).toBeInTheDocument();
    // The declaration is what decides whether the row is scanned, so it is shown
    // for the type rather than repeated per row.
    expect(screen.getByTitle(/Monitored by modules Phishing, Breaches/)).toBeInTheDocument();
    expect(screen.getByTitle(/connectors dnstwist/)).toBeInTheDocument();
    expect(screen.queryByText("not scanned")).not.toBeInTheDocument();

    listMock.mockResolvedValue({
      items: [{ ...asset, id: "asset-2", asset_type: "ip_address", asset_value: "203.0.113.9" }],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
    renderPage();
    expect(await screen.findByText("not scanned")).toBeInTheDocument();
    expect(
      screen.getByTitle(/No enabled module consumes this type of asset/),
    ).toBeInTheDocument();
  });

  it("says how many findings are linked before deleting (WI-14)", async () => {
    const user = userEvent.setup();
    findingsMock.mockResolvedValue({ counts: { total: 7, phishing: 3, breaches: 2, dns: 1, exposure: 1, findings: 0 }, items: [], page: 1, size: 1, pages: 7 });
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Delete asset" }));
    expect(await screen.findByText(/Involved in 7 findings/)).toBeInTheDocument();
    // The counts come from the same view the asset page shows, so the operator
    // reads the consequence instead of guessing it from a checkbox label.
    expect(findingsMock).toHaveBeenCalledWith("asset-1", { page: 1, size: 1 });
    expect(await screen.findByText(/Deleting the asset alone leaves all of them in place/)).toBeInTheDocument();
  });

  it("confirms deactivation and says monitoring stops without deleting evidence", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Deactivate asset" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Deactivate asset?")).toBeInTheDocument();
    expect(updateMock).not.toHaveBeenCalled();
    expect(within(dialog).getByText(/stops being scanned and drops out of breach, DNS and phishing matching/)).toBeInTheDocument();
    expect(within(dialog).getByText(/deactivation is not a delete/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(updateMock).toHaveBeenCalledWith("asset-1", { is_active: false }));
  });

  it("confirms activation and promises rescanning, not restored findings", async () => {
    const user = userEvent.setup();
    listMock.mockResolvedValue({ items: [{ ...asset, is_active: false }], total: 1, page: 1, size: 20, pages: 1 });
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Activate asset" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Activate asset?")).toBeInTheDocument();
    expect(within(dialog).getByText(/scanned again by every module/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Confirm action" }));
    await waitFor(() => expect(updateMock).toHaveBeenCalledWith("asset-1", { is_active: true }));
  });
});
