import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import ExposurePage from "@/pages/ExposurePage";
import { useAuthStore } from "@/store/auth";

const mocks = vi.hoisted(() => ({ list: vi.fn(), scan: vi.fn(), triage: vi.fn(), promote: vi.fn(), toast: vi.fn() }));
vi.mock("@/lib/api", () => ({ endpoints: { listExposure: mocks.list, scanModule: mocks.scan, updateExposure: mocks.triage, promoteExposureObservation: mocks.promote }, describeApiError: (error: Error) => error.message }));
vi.mock("@/components/ui/use-toast", () => ({ useToast: () => ({ toast: mocks.toast }) }));

beforeEach(() => {
  mocks.list.mockReset().mockResolvedValue({ items: [{ id: "observation-1", subject: "www.example.com", matched_asset: "example.com", source: "netlas", status: "observed", first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-02T00:00:00Z", observed_at: null, payload: { port: 443, transport: "tcp", protocol: "https" } }], total: 1 });
  mocks.scan.mockReset().mockResolvedValue({ status: "scheduled", job_ids: ["source-job"], sources: [{ connector: "exposure-netlas", status: "queued" }, { connector: "exposure-shodan-endpoints", status: "disabled" }] });
  mocks.triage.mockReset().mockResolvedValue({ id: "observation-1", status: "investigating" });
  mocks.promote.mockReset().mockResolvedValue({ already_exists: false, asset: { asset_value: "www.example.com" }, source: "netlas" });
  mocks.toast.mockReset();
  useAuthStore.setState({ user: { id: "analyst", email: "analyst@example.com", role: "analyst", is_active: true, rate_limit_minutes: 0, created_at: "", updated_at: "" }, isHydrated: true });
});

function page() {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ExposurePage /></QueryClientProvider>);
}

it("renders provider-observed services and queues a registry scan", async () => {
  page();
  expect(await screen.findByText("www.example.com")).toBeInTheDocument();
  expect(screen.getByText("443/tcp · https")).toBeInTheDocument();
  expect(screen.getByText(/not verified vulnerabilities/i)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Add www.example.com to Assets" }));
  await userEvent.click(screen.getByRole("button", { name: "Add to Assets" }));
  await waitFor(() => expect(mocks.promote).toHaveBeenCalledWith("observation-1"));
  await userEvent.click(screen.getByRole("button", { name: "Rescan" }));
  await waitFor(() => expect(mocks.scan).toHaveBeenCalledWith("exposure"));
  await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ description: expect.stringContaining("exposure-shodan-endpoints: disabled") })));
});

it("names the provider the promoted asset came from (WI-13)", async () => {
  page();
  expect(await screen.findByText("www.example.com")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Add www.example.com to Assets" }));
  await userEvent.click(screen.getByRole("button", { name: "Add to Assets" }));
  // ``matched_asset`` alone cannot tell an operator which provider observed the
  // host that became this asset; the source is what makes the promotion
  // traceable without opening the audit page.
  await waitFor(() =>
    expect(mocks.toast).toHaveBeenCalledWith(
      expect.objectContaining({ description: expect.stringContaining("from the netlas observation") }),
    ),
  );
});

it("confirms promotion and warns that provider evidence is not proof of ownership (WI-14)", async () => {
  page();
  expect(await screen.findByText("www.example.com")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Add www.example.com to Assets" }));
  const dialog = screen.getByRole("dialog");
  // Promoting is a configuration change, so it is never one click away: the
  // dialog names the asset that will exist and says what the evidence does not
  // establish. Exposure observations are the case where that matters most,
  // because provider data about shared hosting can name a host the operator
  // does not own.
  expect(mocks.promote).not.toHaveBeenCalled();
  expect(dialog).toHaveTextContent("Add to Assets?");
  expect(dialog).toHaveTextContent("asset of type domain with criticality medium");
  expect(dialog).toHaveTextContent(/does not prove ownership/);
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(mocks.promote).not.toHaveBeenCalled();
});

it("explains blocked sources when no connector could start", async () => {
  mocks.scan.mockRejectedValue({
    response: {
      status: 409,
      data: {
        detail: {
          status: "blocked",
          job_ids: [],
          sources: [
            // Connector names follow the ``<module>-<provider>-<task>``
            // template the registry uses; the toast must not print a raw object
            // for any of them.
            { connector: "exposure-netlas", status: "disabled" },
            { connector: "exposure-netlas-endpoints", status: "account_policy_unapproved" },
            { connector: "exposure-shodan-endpoints", status: "offline" },
          ],
        },
      },
    },
  });
  page();
  await userEvent.click(await screen.findByRole("button", { name: "Rescan" }));
  await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({
    title: "Scan not started",
    description: "No scans started: exposure-netlas: disabled; exposure-netlas-endpoints: account policy unapproved; exposure-shodan-endpoints: offline",
  })));
  expect(mocks.toast.mock.calls.some(([toast]) => JSON.stringify(toast).includes("[object Object]"))).toBe(false);
});

it("filters by source and prevents viewer scans", async () => {
  useAuthStore.setState({ user: { ...useAuthStore.getState().user!, role: "viewer" } });
  page();
  await screen.findByText("www.example.com");
  expect(screen.queryByRole("button", { name: "Rescan" })).not.toBeInTheDocument();
  await userEvent.selectOptions(screen.getByLabelText("Exposure source"), "shodan");
  await waitFor(() => expect(mocks.list).toHaveBeenCalledWith({ page: 1, size: 20, source: "shodan" }));
});
