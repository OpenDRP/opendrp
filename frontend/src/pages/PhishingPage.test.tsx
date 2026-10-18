import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PhishingPage from "@/pages/PhishingPage";
import { useAuthStore } from "@/store/auth";

const mocks = vi.hoisted(() => ({
  list: vi.fn(),
  toast: vi.fn(),
  evidence: vi.fn(),
  promote: vi.fn(),
}));
vi.mock("@/lib/api", () => ({
  endpoints: {
    listPhishing: mocks.list,
    phishingEvidence: mocks.evidence,
    updatePhishingThreat: vi.fn(),
    deletePhishingThreat: vi.fn(),
    cleanOrphanPhishing: vi.fn(),
    scanModule: vi.fn(),
    promotePhishingAsset: mocks.promote,
  },
  describeApiError: (error: Error) => error.message,
}));
vi.mock("@/hooks/useModuleJobTypes", () => ({ useModuleJobTypes: () => ["phishing.dnstwist"] }));
vi.mock("@/components/JobsTable", () => ({ JobsTable: () => null }));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));
vi.mock("@/lib/scanPolling", () => ({
  summarizeScanJobs: () => ({ pending: 0, succeeded: 0, failed: 0 }),
  waitForScanJobs: async () => [],
}));

const young = {
  id: "threat-young",
  phishing_domain: "paypa1-login.example",
  matched_asset: "paypal.com",
  detection_source: "dnstwist",
  domain_created_at: "2026-10-03T00:00:00Z",
  domain_age_days: 12,
  confidence: 55,
  signals: { young_domain: 25 },
  alert_band: "digest",
  status: "active",
  created_at: "2026-10-15T00:00:00Z",
  updated_at: "2026-10-15T00:00:00Z",
} as const;

const unresolved = {
  ...young,
  id: "threat-unresolved",
  phishing_domain: "secure-chase.example",
  domain_created_at: undefined,
  domain_age_days: null,
};

function renderPage(role: "admin" | "analyst" | "viewer" = "analyst") {
  useAuthStore.setState({
    user: { id: "user-1", email: "user@example.com", role, is_active: true, rate_limit_minutes: 0, created_at: "2026-01-01", updated_at: "2026-01-01" },
    token: "test",
    isHydrated: true,
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}><PhishingPage /></QueryClientProvider>);
}

describe("PhishingPage age of a registration (WI-05)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.list.mockResolvedValue({ items: [young, unresolved], total: 2, page: 1, size: 20, pages: 1 });
    mocks.evidence.mockResolvedValue({ items: [] });
  });

  it("shows the age the server computed and says unknown when nobody resolved it", async () => {
    renderPage();
    expect(await screen.findByText("12 d")).toBeInTheDocument();
    // A candidate whose registration date no source answered is not "0 d": the
    // reader has to be able to tell an unresolved date from a brand-new domain.
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: /Age/ })).toBeInTheDocument();
  });

  it("takes a look-alike under monitoring from its row (AWI-13)", async () => {
    const user = userEvent.setup();
    mocks.promote.mockResolvedValue({ already_exists: false, asset: { id: "asset-1" } });
    renderPage("analyst");
    await screen.findByText("paypa1-login.example");

    await user.click(
      screen.getAllByRole("button", { name: "Monitor this look-alike domain" })[0],
    );

    await waitFor(() => expect(mocks.promote).toHaveBeenCalledWith("threat-young"));
    expect(mocks.toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Domain added" }),
    );
  });

  it("keeps the newest finding first until the operator asks otherwise", async () => {
    renderPage();
    await waitFor(() =>
      expect(mocks.list).toHaveBeenLastCalledWith(
        expect.objectContaining({ sort: "created_at", order: "desc" }),
      ),
    );
  });
});

/**
 * W2.5: what the source evidence says.
 *
 * A row that *found* a name and a row that describes one the platform already had
 * used to render identically (a source and a timestamp), so an operator could not tell
 * a certificate claiming the brand from a registration record about a known candidate.
 */
describe("PhishingPage source evidence", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.list.mockResolvedValue({ items: [young], total: 1, page: 1, size: 20, pages: 1 });
    mocks.evidence.mockResolvedValue({
      items: [
        {
          source: "netlas",
          matched_asset: "paypal.com",
          observed_at: "2026-10-14T09:00:00Z",
          first_seen_at: "2026-10-15T00:00:00Z",
          last_seen_at: "2026-10-15T00:00:00Z",
          fields: { capability: "certificate_brand", verdict: "candidate_not_verified" },
        },
        {
          source: "netlas",
          matched_asset: "paypal.com",
          observed_at: null,
          first_seen_at: "2026-10-15T00:00:00Z",
          last_seen_at: "2026-10-15T00:00:00Z",
          fields: {
            capability: "mx",
            registrar: "Fixture Registrar",
            created: "2026-10-01T00:00:00Z",
            mail_capable: false,
          },
        },
      ],
    });
  });

  it("names the question each row answers, its verdict and when the provider saw it", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("12 d");
    await user.click(screen.getAllByRole("button", { name: "Signals" })[0]);

    expect(await screen.findByText(/Certificate claims the brand/)).toBeInTheDocument();
    expect(screen.getByText(/Not verified yet/)).toBeInTheDocument();
    expect(screen.getByText(/Registration record|Mail records/)).toBeInTheDocument();
    expect(screen.getByText(/registrar: Fixture Registrar/)).toBeInTheDocument();
    // A negative mail answer is an answer: the row says so instead of looking blank.
    expect(screen.getByText(/no mail records/)).toBeInTheDocument();
    // The provider's own time is reported as observed, and the platform's as first seen.
    expect(screen.getByText(/observed: 2026-10-14 09:00:00/)).toBeInTheDocument();
  });
});

describe("PhishingPage sources column (WI-30)", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.evidence.mockResolvedValue({ items: [] });
  });

  it("shows how many independent sources reported a candidate, and which", async () => {
    mocks.list.mockResolvedValue({
      items: [{ ...young, id: "threat-reported", sources: ["dnstwist", "netlas"], source_count: 2 }],
      total: 1,
      page: 1,
      size: 20,
      pages: 1,
    });

    renderPage();

    expect(await screen.findByRole("columnheader", { name: /Sources/ })).toBeInTheDocument();
    // The count *and* the names: two providers agreeing is the corroboration the
    // score pays for, and one connector seen twice is not that.
    expect(await screen.findByText("2 (dnstwist, netlas)")).toBeInTheDocument();
  });

  it("says not recorded rather than naming the connector that found the candidate", async () => {
    // No evidence rows recorded: the detection source is who *found* the name, which
    // is a different fact from who reported it, and the column must not conflate them.
    mocks.list.mockResolvedValue({ items: [young], total: 1, page: 1, size: 20, pages: 1 });

    renderPage();

    expect(await screen.findByText("not recorded")).toBeInTheDocument();
    expect(screen.queryByText("1 (dnstwist)")).not.toBeInTheDocument();
  });
});
