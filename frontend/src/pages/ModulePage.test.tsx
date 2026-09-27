import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ModulePage from "@/pages/ModulePage";
import type { ModuleFinding, RegistryModule } from "@/types/api";

const { fetchModulesMock, fetchModuleFindingsMock, updateFindingStatusMock, analyst } =
  vi.hoisted(() => ({
    fetchModulesMock: vi.fn(),
    fetchModuleFindingsMock: vi.fn(),
    updateFindingStatusMock: vi.fn(),
    analyst: { value: false },
  }));

vi.mock("@/lib/modules", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/modules")>()),
  fetchModules: fetchModulesMock,
  fetchModuleFindings: fetchModuleFindingsMock,
}));

vi.mock("@/lib/findings", () => ({ updateFindingStatus: updateFindingStatusMock }));
vi.mock("@/store/auth", () => ({ useIsAnalystPlus: () => analyst.value }));

const codeLeak: RegistryModule = {
  id: "code_leak",
  label: "Code leaks",
  description: "Secrets exposed in public repositories.",
  finding_kind: "code_leak",
  asset_types: ["domain"],
  fields: {
    repository: { type: "str", required: true, label: "Repository" },
    secret_kind: { type: "str", required: true, label: "Secret type" },
    is_public: { type: "bool", label: "Public repo" },
    tags: { type: "list_str", label: "Tags" },
  },
  dedup_fields: ["repository", "secret_kind"],
  title_field: "repository",
  storage: "generic",
  enabled: true,
  builtin: false,
};

function finding(overrides: Partial<ModuleFinding> = {}): ModuleFinding {
  return {
    id: "finding-1",
    module: "code_leak",
    finding_kind: "code_leak",
    connector_name: "leakwatch",
    title: "github.com/acme/app",
    matched_asset: "acme.com",
    status: "active",
    payload: {
      repository: "github.com/acme/app",
      secret_kind: "aws_access_key",
      is_public: true,
      tags: ["prod", "backend"],
      attributes: { commit: "abc123" },
    },
    created_at: "2026-02-01T10:00:00Z",
    ...overrides,
  };
}

function renderPage(moduleId = "code_leak") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/modules/${moduleId}`]}>
        <Routes>
          <Route path="/modules/:moduleId" element={<ModulePage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ModulePage", () => {
  beforeEach(() => {
    analyst.value = false;
    updateFindingStatusMock.mockReset();
    fetchModulesMock.mockReset().mockResolvedValue({
      modules: [codeLeak],
      generated_at: "2026-01-01T00:00:00Z",
    });
    fetchModuleFindingsMock.mockReset().mockResolvedValue({
      items: [finding()],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });
  });

  it("renders columns from the module's own declaration", async () => {
    renderPage();

    // The headline column is the declared title field, and each declared field
    // becomes its own column under its declared label.
    expect(await screen.findByText("Repository")).toBeInTheDocument();
    expect(screen.getByText("Secret type")).toBeInTheDocument();
    expect(screen.getByText("Public repo")).toBeInTheDocument();
    expect(screen.getByText("Tags")).toBeInTheDocument();
    expect(screen.getByText("Matched asset")).toBeInTheDocument();

    // Values are rendered from the payload, including lists and booleans.
    expect(await screen.findByText("github.com/acme/app")).toBeInTheDocument();
    expect(screen.getByText("aws_access_key")).toBeInTheDocument();
    expect(screen.getByText("Yes")).toBeInTheDocument();
    expect(screen.getByText("prod, backend")).toBeInTheDocument();
    // The source's own payload is shown as one column, never guessed at.
    expect(screen.getByText(/commit: abc123/)).toBeInTheDocument();
    expect(screen.getByText("code_leak")).toBeInTheDocument();
  });

  it("explains that a table-backed module has its own page", async () => {
    fetchModulesMock.mockResolvedValue({
      modules: [{ ...codeLeak, id: "phishing", label: "Phishing", storage: "table", builtin: true }],
      generated_at: "2026-01-01T00:00:00Z",
    });
    fetchModuleFindingsMock.mockClear();
    renderPage("phishing");

    expect(await screen.findByText(/has its own page/)).toBeInTheDocument();
    expect(fetchModuleFindingsMock).not.toHaveBeenCalled();
  });

  it("says so when the module is not registered", async () => {
    fetchModulesMock.mockResolvedValue({ modules: [], generated_at: "2026-01-01T00:00:00Z" });
    renderPage("ghost");

    expect(await screen.findByText(/No module called/)).toBeInTheDocument();
    expect(fetchModuleFindingsMock).not.toHaveBeenCalled();
  });

  it("shows an error instead of an empty table when findings fail to load", async () => {
    fetchModuleFindingsMock.mockRejectedValue(new Error("boom"));
    renderPage();

    expect(
      await screen.findByText(/could not be loaded, which is not the same as there being none/),
    ).toBeInTheDocument();
  });

  it("reports the dedup fields and UTC for the time column", async () => {
    renderPage();
    expect(await screen.findByText(/deduplicated on Repository, Secret type/)).toBeInTheDocument();
    expect(screen.getByText("Detected (UTC)")).toBeInTheDocument();
  });

  it("shows a viewer the status as a badge, not as a control", async () => {
    analyst.value = false;
    renderPage();

    expect(await screen.findByText("Active")).toBeInTheDocument();
    // Triaging is a write: a viewer must not be offered it at all.
    expect(screen.queryByLabelText(/Triage status for/)).not.toBeInTheDocument();
  });

  it("lets an analyst move a finding through triage", async () => {
    analyst.value = true;
    updateFindingStatusMock.mockResolvedValue(finding({ status: "resolved" }));
    renderPage();

    const control = await screen.findByLabelText("Triage status for github.com/acme/app");
    expect(control).toHaveValue("active");

    fireEvent.change(control, { target: { value: "resolved" } });

    await waitFor(() =>
      expect(updateFindingStatusMock).toHaveBeenCalledWith("finding-1", "resolved"),
    );
  });

  it("offers exactly the three triage states the core accepts", async () => {
    analyst.value = true;
    renderPage();

    const control = await screen.findByLabelText("Triage status for github.com/acme/app");
    const values = Array.from(control.querySelectorAll("option")).map((o) => o.value);
    // Anything else is rejected by the API, so it must not be offered.
    expect(values).toEqual(["active", "investigating", "resolved"]);
  });
});
