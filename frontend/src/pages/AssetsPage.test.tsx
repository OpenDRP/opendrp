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
  bulkMock,
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
  bulkMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  // Only the transport is replaced: `describeApiError` is the real one, because
  // the sentence the operator reads for a refused query is the behaviour under
  // test rather than a stand-in for it.
  return {
    ...actual,
    endpoints: {
      listAssets: listMock,
      createAsset: createMock,
      updateAsset: updateMock,
      deleteAsset: deleteMock,
      assetFindings: findingsMock,
      exportAssets: exportMock,
      importAssets: importMock,
      importAssetsCsv: importCsvMock,
      bulkAssets: bulkMock,
    },
  };
});
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
  // The stand-in keeps the contracts the page depends on: a sortable header
  // reports the field it names, and a checkbox reports the same ids the server
  // would receive (AWI-04, AWI-11). Rendering the real table here would test
  // column resizing instead of what the page asks the API for.
  PaginatedDataTable: ({
    columns,
    rows,
    selectable = false,
    selectedIds = [],
    onSelectedChange,
    onSortChange,
    sort,
    getRowId,
    getRowLabel,
    loading,
    emptyText,
    isError = false,
    errorDescription,
    onRetry,
  }: any) => isError && rows.length === 0 ? (
    // The real table replaces an empty error result with the failure itself
    // rather than the "nothing monitored" line, so the stand-in does too.
    <div role="alert">
      <span>{errorDescription}</span>
      {onRetry && <button onClick={onRetry}>Try again</button>}
    </div>
  ) : (
    <div>
      <div>
        {selectable && (
          <input
            type="checkbox"
            aria-label="Select all rows on this page"
            checked={rows.length > 0 && rows.every((row: any) => selectedIds.includes(getRowId?.(row) ?? row.id))}
            onChange={() => onSelectedChange?.(rows.map((row: any) => getRowId?.(row) ?? row.id))}
          />
        )}
        {columns.map((column: any) =>
          column.sortable ? (
            <button
              key={column.key}
              onClick={() =>
                onSortChange?.({
                  field: column.key,
                  direction: sort?.field === column.key && sort.direction === "asc" ? "desc" : "asc",
                })
              }
            >
              {column.title}
            </button>
          ) : (
            <span key={column.key}>{column.title}</span>
          ),
        )}
      </div>
      {loading && <span>Loading assets…</span>}
      {!loading && rows.length === 0 && emptyText && <span>{emptyText}</span>}
      {rows.map((row: any) => {
        const id = getRowId?.(row) ?? row.id;
        return (
          <div key={id}>
            {selectable && (
              <input
                type="checkbox"
                aria-label={`Select ${getRowLabel?.(row) ?? id}`}
                checked={selectedIds.includes(id)}
                onChange={() =>
                  onSelectedChange?.(
                    selectedIds.includes(id)
                      ? selectedIds.filter((selected: string) => selected !== id)
                      : [...selectedIds, id],
                  )
                }
              />
            )}
            {columns.map((column: any) => (
              <span key={column.key}>{column.render ? column.render(row) : row[column.key]}</span>
            ))}
          </div>
        );
      })}
    </div>
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

function renderPage(initialEntries: string[] = ["/assets"]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  // The value column links to the asset's own page (WI-12), so the page needs a
  // router in scope.
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
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
    bulkMock.mockReset().mockResolvedValue({
      operation: "deactivate",
      requested: 2,
      applied: 2,
      missing: [],
      cascade_findings: false,
      findings_deleted: {},
    });
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

  it("explains a database_busy refusal and retries the same read", async () => {
    // The API answers a query it stopped on purpose with a 503 and a code. The
    // operator sees the sentence that tells them what to do, and the retry
    // repeats the read rather than staying on a page that cannot succeed.
    const user = userEvent.setup();
    listMock.mockRejectedValueOnce({ response: { status: 503, data: { code: "database_busy" } } });

    renderPage();

    expect(
      await screen.findByText(/The database stopped this query because it took too long/),
    ).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("example.com")).toBeInTheDocument();
    expect(listMock).toHaveBeenCalledTimes(2);
  });

  it("says when the import report is truncated, and where the rest lives", async () => {
    const user = userEvent.setup();
    const rows = Array.from({ length: 150 }, (_, index) => ({
      line: index + 2,
      outcome: "created" as const,
      asset_type: "domain",
      asset_value: `host-${index}.example`,
      detail: null,
    }));
    importCsvMock
      .mockResolvedValueOnce({ dry_run: true, created: 150, duplicate: 0, invalid: 0, rows: [] })
      .mockResolvedValueOnce({ dry_run: false, created: 150, duplicate: 0, invalid: 0, rows });

    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("button", { name: "Import" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText("Assets to import"), "asset_type,asset_value,{enter}domain,a.example,");
    await user.click(within(dialog).getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(importCsvMock).toHaveBeenCalledWith(expect.any(String), true));
    await user.click(within(dialog).getByRole("button", { name: "Import" }));

    // The page renders a bounded list; the sentence is what tells the operator
    // that they are not looking at the whole report.
    expect(await within(dialog).findByText(/Showing the first 100 of 150 lines/)).toBeInTheDocument();
    expect(within(dialog).getByText(/the audit trail holds the full report/)).toBeInTheDocument();
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

  it("shows the skeleton, not an empty inventory, while the first request is unanswered (AWI-01)", async () => {
    // A placeholder row set makes React Query report `isPlaceholderData` with
    // `isLoading` already false. Reading only `isLoading` showed "No assets yet"
    // — a conclusion about the inventory drawn from a request that had not
    // finished.
    listMock.mockReturnValue(new Promise(() => {}));
    renderPage();
    expect(await screen.findByText("Loading assets…")).toBeInTheDocument();
    expect(screen.queryByText(/No assets yet/)).not.toBeInTheDocument();
  });

  it("sends the ordering the header names and resets to page one (AWI-04)", async () => {
    const user = userEvent.setup();
    renderPage(["/assets?page=3"]);
    await screen.findByText("example.com");

    // The server's default is created_at desc; clicking the same header asks
    // ascending, and the page number must not survive a reorder.
    await user.click(screen.getByRole("button", { name: "Created" }));
    await waitFor(() =>
      expect(listMock).toHaveBeenCalledWith(
        expect.objectContaining({ sort: "created_at", order: "asc", page: 1 }),
      ),
    );
    await user.click(screen.getByRole("button", { name: "Value" }));
    await waitFor(() =>
      expect(listMock).toHaveBeenCalledWith(
        expect.objectContaining({ sort: "asset_value", order: "asc", page: 1 }),
      ),
    );
  });

  it("reads the ordering from the address, so a shared link keeps it (AWI-04)", async () => {
    renderPage(["/assets?sort=criticality&order=desc"]);
    await screen.findByText("example.com");
    expect(listMock).toHaveBeenCalledWith(
      expect.objectContaining({ sort: "criticality", order: "desc" }),
    );
  });

  it("ignores a sort field the server would refuse (AWI-04)", async () => {
    renderPage(["/assets?sort=password&order=asc"]);
    await screen.findByText("example.com");
    // An unknown field is not forwarded, and its paired direction means nothing
    // without the field: the whole ordering falls back to the server default.
    expect(listMock).toHaveBeenCalledWith(
      expect.objectContaining({ sort: "created_at", order: "desc" }),
    );
  });

  it("applies one batch action to the ticked rows (AWI-11)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");

    // Nothing is offered before something is selected: a batch action with an
    // empty set is a button that can only fail.
    expect(screen.queryByRole("region", { name: "Batch actions" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("checkbox", { name: "Select example.com" }));
    const panel = screen.getByRole("region", { name: "Batch actions" });
    expect(within(panel).getByText("1 selected")).toBeInTheDocument();

    await user.click(within(panel).getByRole("button", { name: "Deactivate" }));
    await waitFor(() =>
      expect(bulkMock).toHaveBeenCalledWith({ ids: ["asset-1"], operation: "deactivate" }),
    );
  });

  it("makes a batch delete name DELETE before it sends anything (AWI-11)", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("checkbox", { name: "Select example.com" }));
    await user.click(screen.getByRole("button", { name: "Delete" }));

    const dialog = screen.getByRole("dialog");
    // The cascade itself is off by default; the warning says what it would do.
    expect(within(dialog).getByText(/phishing, breach and generic/)).toBeInTheDocument();
    const confirm = within(dialog).getByRole("button", { name: "Confirm action" });
    expect(confirm).toBeDisabled();

    await user.type(within(dialog).getByLabelText(/Type DELETE/), "delete");
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() =>
      expect(bulkMock).toHaveBeenCalledWith({
        ids: ["asset-1"],
        operation: "delete",
        cascade_findings: false,
      }),
    );
  });

  /**
   * The batch route takes ids, so the ids may only be the rows the operator can
   * see now (AST-42). A filter change is a different result set: keeping the ticks
   * would let one click change an asset that is no longer on screen, chosen under
   * a filter the operator was no longer looking at.
   */
  it("drops a selection when the result set changes", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("example.com");
    await user.click(screen.getByRole("checkbox", { name: "Select example.com" }));
    expect(screen.getByRole("region", { name: "Batch actions" })).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("Search value..."), "other");

    await waitFor(() =>
      expect(screen.queryByRole("region", { name: "Batch actions" })).not.toBeInTheDocument(),
    );
    expect(bulkMock).not.toHaveBeenCalled();
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
