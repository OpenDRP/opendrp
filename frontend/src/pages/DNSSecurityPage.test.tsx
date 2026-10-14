import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import DNSSecurityPage from "@/pages/DNSSecurityPage";
import { useAuthStore } from "@/store/auth";

const mocks = vi.hoisted(() => ({ list: vi.fn(), scan: vi.fn(), cleanup: vi.fn(), health: vi.fn(), promote: vi.fn(), remove: vi.fn(), toast: vi.fn() }));
vi.mock("@/lib/api", () => ({
  endpoints: { listDNSObservations: mocks.list, scanDNSSecurity: mocks.scan, cleanOrphanDNSObservations: mocks.cleanup, connectorsHealth: mocks.health, promoteDNSObservation: mocks.promote, deleteDNSObservation: mocks.remove },
  describeApiError: (error: Error) => error.message,
}));
vi.mock("@/hooks/useModuleJobTypes", () => ({ useModuleJobTypes: () => ["dns.resolver"] }));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));

function renderPage(role: "admin" | "analyst" | "viewer" = "admin") {
  useAuthStore.setState({ user: { id: "user-1", email: "user@example.com", role, is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01", updated_at: "2026-01-01" }, token: "test", isHydrated: true });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><DNSSecurityPage /></QueryClientProvider>);
}

describe("DNSSecurityPage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.list.mockResolvedValue({ items: [], total: 0, page: 1, size: 20, pages: 0 });
    mocks.health.mockResolvedValue({ items: [{ name: "dns-resolver", connector_type: "dns", status: "enabled", health: "healthy" }] });
    mocks.scan.mockResolvedValue({ status: "scheduled", job_ids: ["job-1"], offline_connectors: [] });
    mocks.cleanup.mockResolvedValue({ deleted: 2 });
  });

  it("uses a primary Rescan button and reports queued rather than started jobs", async () => {
    const user = userEvent.setup();
    renderPage();
    const button = screen.getByRole("button", { name: "Rescan" });
    expect(button).toHaveClass("bg-primary");
    await user.click(button);
    await waitFor(() => expect(mocks.scan).toHaveBeenCalledTimes(1));
    expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ description: expect.stringContaining("1 source job(s) queued") }));
  });

  it("disables rescanning when DNS workers have never registered", async () => {
    mocks.health.mockResolvedValue({ items: [{ name: "dns-resolver", connector_type: "dns", status: "enabled", health: "unknown" }] });
    renderPage();
    expect(await screen.findByText("DNS workers are not running.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rescan" })).toBeDisabled();
    expect(mocks.scan).not.toHaveBeenCalled();
  });

  it("confirms cleanup before calling the API", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: "Clean orphans" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(mocks.cleanup).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Clean entries" }));
    await waitFor(() => expect(mocks.cleanup).toHaveBeenCalledTimes(1));
    expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Orphan DNS entries cleaned", description: "2 entries deleted." }));
  });

  it("hides destructive cleanup for analysts and all writes for viewers", () => {
    const page = renderPage("analyst");
    expect(screen.queryByRole("button", { name: "Clean orphans" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rescan" })).toBeInTheDocument();
    page.unmount();
    renderPage("viewer");
    expect(screen.queryByRole("button", { name: "Rescan" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Clean orphans" })).not.toBeInTheDocument();
  });

  it("shows wildcard evidence without permitting concrete asset promotion", async () => {
    mocks.list.mockResolvedValue({ items: [{ id: "cert-1", subject: "prod.egov.kz", observation_type: "certificate", record_type: null, value: "egov.kz", source: "ctlogs", status: "historical", expires_at: null, metadata: { wildcard: true } }], total: 1, page: 1, size: 20, pages: 1 });
    renderPage();
    expect(await screen.findByText("*.prod.egov.kz")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cannot add wildcard prod.egov.kz" })).toBeDisabled();
  });

  it("keeps actions together and uses the shortened cleanup label", () => {
    renderPage();
    const refresh = screen.getByRole("button", { name: "Refresh" });
    const toolbar = refresh.parentElement!;
    expect(toolbar).toHaveClass("shrink-0", "flex-nowrap");
    expect(within(toolbar).getByRole("button", { name: "Clean orphans" })).toBeInTheDocument();
    expect(within(toolbar).getByRole("button", { name: "Rescan" })).toBeInTheDocument();
  });

  it("places asset controls beside each target and disables existing assets", async () => {
    mocks.list.mockResolvedValue({ items: [{ id: "dns-1", subject: "example.com", observation_type: "dns_record", record_type: "AAAA", value: "2001:db8::1", source: "resolver", status: "current", metadata: {}, subject_in_assets: true, value_asset_target: "2001:db8::1", value_in_assets: false }], total: 1, page: 1, size: 20, pages: 1 });
    mocks.promote.mockResolvedValue({ already_exists: false, asset: { asset_value: "2001:db8::1" } });
    const user = userEvent.setup();
    renderPage();
    const domain = await screen.findByText("example.com");
    expect(within(domain.closest("td")!).getByRole("button", { name: "example.com already in Assets" })).toBeDisabled();
    const ip = screen.getByText("2001:db8::1");
    await user.click(within(ip.closest("td")!).getByRole("button", { name: "Add 2001:db8::1 to Assets" }));
    await user.click(screen.getByRole("button", { name: "Add to Assets" }));
    await waitFor(() => expect(mocks.promote).toHaveBeenCalledWith("dns-1", "2001:db8::1"));
    expect(screen.getByRole("columnheader", { name: "Actions Resize Actions column" })).toBeInTheDocument();
  });

  it("names the observation source when it promotes an asset (WI-13)", async () => {
    mocks.list.mockResolvedValue({ items: [{ id: "dns-1", subject: "example.com", observation_type: "dns_record", record_type: "A", value: "203.0.113.9", source: "ctlogs", status: "current", metadata: {}, subject_in_assets: false, value_asset_target: "203.0.113.9", value_in_assets: false }], total: 1, page: 1, size: 20, pages: 1 });
    mocks.promote.mockResolvedValue({ already_exists: false, asset: { asset_value: "203.0.113.9" }, source: "ctlogs" });
    const user = userEvent.setup();
    renderPage();
    const target = await screen.findByText("203.0.113.9");
    await user.click(within(target.closest("td")!).getByRole("button", { name: "Add 203.0.113.9 to Assets" }));
    await user.click(screen.getByRole("button", { name: "Add to Assets" }));
    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: expect.stringContaining("from the ctlogs observation") }),
      ),
    );
  });

  it("says an existing asset is already monitored", async () => {
    mocks.list.mockResolvedValue({ items: [{ id: "dns-1", subject: "example.com", observation_type: "dns_record", record_type: "A", value: "203.0.113.9", source: "ctlogs", status: "current", metadata: {}, subject_in_assets: false, value_asset_target: "203.0.113.9", value_in_assets: false }], total: 1, page: 1, size: 20, pages: 1 });
    mocks.promote.mockResolvedValue({ already_exists: true, asset: { asset_value: "203.0.113.9" }, source: "ctlogs" });
    const user = userEvent.setup();
    renderPage();
    const target = await screen.findByText("203.0.113.9");
    await user.click(within(target.closest("td")!).getByRole("button", { name: "Add 203.0.113.9 to Assets" }));
    await user.click(screen.getByRole("button", { name: "Add to Assets" }));
    await waitFor(() =>
      expect(mocks.toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: expect.stringContaining("already monitored") }),
      ),
    );
  });

  it("confirms member deletion and does not expose writes to viewers", async () => {
    mocks.list.mockResolvedValue({ items: [{ id: "dns-1", subject: "example.com", observation_type: "dns_record", record_type: "A", value: "203.0.113.1", source: "resolver", status: "current", metadata: {} }], total: 1, page: 1, size: 20, pages: 1 });
    mocks.remove.mockResolvedValue(undefined);
    const user = userEvent.setup();
    const page = renderPage();
    await user.click(await screen.findByRole("button", { name: "Delete DNS observation" }));
    expect(mocks.remove).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(mocks.remove).toHaveBeenCalledWith("dns-1", "203.0.113.1"));
    page.unmount();
    renderPage("viewer");
    await screen.findByText("203.0.113.1");
    expect(screen.queryByRole("button", { name: "Delete DNS observation" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /to Assets/ })).not.toBeInTheDocument();
  });

  it("confirms promotion with the type and criticality the asset will get (WI-14)", async () => {
    mocks.list.mockResolvedValue({ items: [{ id: "dns-1", subject: "example.com", observation_type: "dns_record", record_type: "A", value: "203.0.113.9", source: "ctlogs", status: "current", metadata: {}, subject_in_assets: false, value_asset_target: "203.0.113.9", value_in_assets: false }], total: 1, page: 1, size: 20, pages: 1 });
    const user = userEvent.setup();
    renderPage();
    const target = await screen.findByText("203.0.113.9");
    await user.click(within(target.closest("td")!).getByRole("button", { name: "Add 203.0.113.9 to Assets" }));
    const dialog = screen.getByRole("dialog");
    expect(mocks.promote).not.toHaveBeenCalled();
    expect(within(dialog).getByText("Add to Assets?")).toBeInTheDocument();
    expect(within(dialog).getByText(/203\.0\.113\.9/)).toBeInTheDocument();
    // An operator has to be able to see that "Add" creates an ip_address asset,
    // before the click, because a client-side label cannot be undone afterwards.
    expect(within(dialog).getByText(/asset of type ip_address with criticality medium/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(mocks.promote).not.toHaveBeenCalled();
  });

  it("renders both RRset members even when they share an observation ID", async () => {
    mocks.list.mockResolvedValue({ items: ["203.0.113.1", "203.0.113.2"].map(value => ({ id: "rrset", subject: "example.com", observation_type: "dns_record", record_type: "A", value, source: "resolver", metadata: {}, status: "current" })), total: 2, page: 1, size: 20, pages: 1 });
    renderPage();
    expect(await screen.findByText("203.0.113.1")).toBeInTheDocument();
    expect(screen.getByText("203.0.113.2")).toBeInTheDocument();
  });

  it("distinguishes domain expiry, passive certificates and cache TTL", async () => {
    const common = { subject: "example.com", source: "rdap", status: "current", metadata: {}, expires_at: "2034-11-13T09:08:33Z" };
    mocks.list.mockResolvedValue({ items: [{ ...common, id: "r", observation_type: "rdap", expiry_kind: "registration", expiry_monitor: { state: "stale", successful_at: "2026-01-01T00:00:00Z" } }, { ...common, id: "c", observation_type: "certificate_check", source: "ctlogs", expiry_kind: "certificate", expiry_monitor: { state: "failed", successful_at: null } }, { ...common, id: "d", observation_type: "dns_record", source: "resolver", expiry_kind: "dns_cache" }], total: 3, page: 1, size: 20, pages: 1 });
    renderPage();
    expect(await screen.findByText("Domain registration expiry")).toBeInTheDocument();
    expect(screen.getByText("Observed certificate expiry")).toBeInTheDocument();
    expect(screen.getByText("DNS cache validity (TTL)")).toBeInTheDocument();
    expect(screen.getByText("stale")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(screen.getByText("Passive CT evidence; use by the service is not verified.")).toBeInTheDocument();
    expect(screen.getByText("Cache lifetime only; no expiry alert.")).toBeInTheDocument();
  });

  it("renders expiry and verification times in UTC and says so (WI-24)", async () => {
    // 09:08:33Z stays 09:08:33 even in a UTC+6 browser session, and the stored
    // instant is what the audit trail and the expiry thresholds are stated in.
    mocks.list.mockResolvedValue({ items: [{ id: "r", subject: "example.com", observation_type: "rdap", record_type: null, value: "", source: "rdap", status: "current", metadata: {}, expires_at: "2034-11-13T09:08:33Z", expiry_kind: "registration", expiry_monitor: { state: "ok", successful_at: "2026-01-01T00:00:00Z" } }], total: 1, page: 1, size: 20, pages: 1 });
    renderPage();
    expect(await screen.findByText("2034-11-13 09:08:33")).toBeInTheDocument();
    expect(screen.getByText(/Last successful check: 2026-01-01 00:00:00/)).toBeInTheDocument();
    expect(screen.getByText(/All times are UTC/)).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Validity \/ Expiry \(UTC\)/ })).toBeInTheDocument();
  });

  it("announces a failed load instead of silently showing nothing", async () => {
    mocks.list.mockRejectedValue(new Error("boom"));
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be loaded/i);
  });

  it("surfaces a server-side offline refusal", async () => {
    mocks.scan.mockRejectedValue(new Error("No online connector is available"));
    const user = userEvent.setup();
    renderPage();
    await user.click(screen.getByRole("button", { name: "Rescan" }));
    await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: "destructive", description: "No online connector is available" })));
  });
});
