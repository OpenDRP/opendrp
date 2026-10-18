import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import DashboardPage from "@/pages/DashboardPage";

const { overviewMock, chartProps } = vi.hoisted(() => ({
  overviewMock: vi.fn(),
  // Recharts is stubbed, but the stub records the props it was handed, so a
  // changed `type="linear"`, `dataKey` or axis formatter fails a test instead of
  // merely rendering differently (DSH-10). A stubbed chart that swallows its
  // configuration allowed `monotone` and `v.slice(5)` to live here unnoticed.
  chartProps: [] as { component: string; props: Record<string, any> }[],
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    dashboardOverview: overviewMock,
  },
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
}));

vi.mock("recharts", () => {
  const stub = (component: string) => {
    const Stub = ({ children, ...props }: any) => {
      chartProps.push({ component, props });
      return <div>{children}</div>;
    };
    Stub.displayName = `Recharts${component}`;
    return Stub;
  };
  return {
    BarChart: stub("BarChart"),
    Bar: stub("Bar"),
    XAxis: stub("XAxis"),
    YAxis: stub("YAxis"),
    CartesianGrid: stub("CartesianGrid"),
    Tooltip: stub("Tooltip"),
    ResponsiveContainer: stub("ResponsiveContainer"),
    LineChart: stub("LineChart"),
    Line: stub("Line"),
    Legend: stub("Legend"),
    PieChart: stub("PieChart"),
    Pie: stub("Pie"),
    Cell: stub("Cell"),
  };
});

function chart(name: string) {
  return chartProps.filter((entry) => entry.component === name).map((entry) => entry.props);
}

const emptyTimeline = Array.from({ length: 30 }, (_, index) => ({
  date: `2026-01-${String(index + 1).padStart(2, "0")}`,
  phishing: 0,
  breaches: 0,
}));

const stats = {
  kpi: {
    total_assets: 12,
    total_phishing: 3,
    total_breaches: 4,
    active_threats_7d: 2,
    new_breach_incidents_7d: 5,
    breach: {
      window_days: 7,
      total_findings: 4,
      findings_by_exposure_kind: { breach: 3, paste: 1, stealer_log: 0 },
      active_findings_7d: 2,
      new_incidents_7d: 5,
      catalogue_incidents: 40,
      undated_incidents: 1,
      catalogue_sources: 1,
      catalogue_synced_at: "2026-01-01T00:00:00Z",
      captions: {
        total_findings: "findings stored from the configured breach sources",
        active_findings_7d: "findings active or under investigation, created in the last 7 days",
        new_incidents_7d: "incidents the configured sources added to their own catalogues in the last 7 days",
        findings_by_exposure_kind: "stored findings by class of exposure (an account compromised, a paste, a stealer log)",
      },
    },
  },
  timeline: [
    { date: "2026-01-01", phishing: 1, breaches: 2 },
    { date: "2026-01-30", phishing: 0, breaches: 0 },
  ],
  timeline_series: [
    { key: "phishing", label: "Phishing", module_id: "phishing" },
    { key: "breaches", label: "Credential breaches", module_id: "breaches" },
  ],
  timeline_excluded: [
    { module_id: "dns", label: "DNS Security", reason: "current_state_observations" },
    { module_id: "exposure", label: "Exposure", reason: "current_state_observations" },
  ],
  timeline_comparison: {
    phishing: { current: 1, previous: 4 },
    breaches: { current: 2, previous: 0 },
  },
  phishing_by_source: [{ source: "dnstwist", count: 3 }],
  assets_by_criticality: [{ criticality: "critical", count: 2 }],
  platform: {
    database: "ok",
    redis: "ok",
    audit_degraded: false,
    connectors: {
      enabled: 1,
      disabled: 0,
      silent: 0,
      longest_silence: { name: "hibp", seconds: 42 },
    },
    oldest_running_job_seconds: 720,
    deliveries: {
      counts: { pending: 1, delivering: 0, sent: 4, failed: 0, cancelled: 0, ambiguous: 0 },
      stuck: 0,
      waiting_recipients: 2,
    },
  },
};

const emptyStats = {
  ...stats,
  kpi: { ...stats.kpi, total_assets: 0, total_phishing: 0, total_breaches: 0 },
  timeline: emptyTimeline,
  timeline_comparison: {
    phishing: { current: 0, previous: 3 },
    breaches: { current: 0, previous: 0 },
  },
  phishing_by_source: [],
  assets_by_criticality: [],
};

const connectorsFixture = {
  items: [{ name: "hibp", connector_type: "breaches", health: "healthy", status: "enabled" }],
  generated_at: "2026-01-01T00:00:00Z",
};

const alertsFixture = {
  items: [{
    channel: "telegram", label: "Telegram", enabled: true, configured: true,
    health: "degraded", message: "Partial delivery", probe_state: "ok",
    checked_at: "2026-01-01T00:00:00Z", from_cache: true,
    delivery: {
      counts: { pending: 2, delivering: 0, sent: 5, failed: 1, cancelled: 0, ambiguous: 0 },
      oldest_unresolved_at: "2026-01-01T00:00:00Z",
      oldest_unresolved_age_seconds: 900,
      retrying: 1,
      stuck: 0,
      degraded_reason: null,
    },
  }],
  delivery_queue: { waiting_recipients: 3 },
  generated_at: "2026-01-01T00:00:00Z",
};

/** The single response the page reads now (DHP-10).
 *
 * Each test overrides only the section it is about, so an assertion about the
 * summary cannot depend on the health fixtures, or the other way round.
 */
function overviewResponse({
  summary = stats,
  connectors = connectorsFixture,
  channels = alertsFixture,
}: { summary?: any; connectors?: any; channels?: any } = {}) {
  return { summary, connectors, channels, generated_at: "2026-01-01T00:00:00Z" };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <DashboardPage />
    </QueryClientProvider>,
  );
}

describe("DashboardPage", () => {
  beforeEach(() => {
    chartProps.length = 0;
    overviewMock.mockReset().mockResolvedValue(overviewResponse());
  });

  it("renders KPI and health data", async () => {
    renderPage();
    expect(await screen.findByText("Dashboard")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());
    expect(screen.getByText("Connectors Health")).toBeInTheDocument();
    expect(screen.getByText("hibp")).toBeInTheDocument();
    expect(screen.getByText("Partial delivery")).toBeInTheDocument();
    // A cached probe keeps its own time and says that it is cached, rather than
    // reading as "just checked" on every page load.
    expect(screen.getByText(/probe completed/)).toBeInTheDocument();
    expect(screen.getByText(/cached/)).toBeInTheDocument();
    // A green probe is not a delivery guarantee: the queue is printed beside it.
    expect(
      screen.getByText(/Delivery queue: 2 pending · 1 retrying · 0 sending · 0 ambiguous · 1 failed · oldest 15 min/),
    ).toBeInTheDocument();
    expect(screen.getByText(/3 recipients waiting on a hold or a retry window/)).toBeInTheDocument();
    expect(screen.getByText("Findings by module — last 30 days")).toBeInTheDocument();
  });

  it("puts platform self-diagnostics on the first screen, from the overview query", async () => {
    renderPage();
    expect(await screen.findByText("Platform status")).toBeInTheDocument();
    expect(screen.getByText("PostgreSQL: ok · Redis: ok")).toBeInTheDocument();
    expect(screen.getByText("intact")).toBeInTheDocument();
    expect(screen.getByText(/longest silence: hibp — 42 s/)).toBeInTheDocument();
    expect(screen.getByText("12 min")).toBeInTheDocument();
    expect(screen.getByText("1 pending · 0 ambiguous · 0 failed")).toBeInTheDocument();
    expect(screen.getByText(/2 recipients waiting/)).toBeInTheDocument();
    // The block is part of the one call the page makes.
    expect(overviewMock).toHaveBeenCalledTimes(1);
  });

  it("shows a degraded audit trail and a stuck queue without another request", async () => {
    overviewMock.mockReset().mockResolvedValue(
      overviewResponse({
        summary: {
          ...stats,
          platform: {
            ...stats.platform,
            redis: "error",
            audit_degraded: true,
            deliveries: {
              counts: { pending: 0, delivering: 0, sent: 0, failed: 1, cancelled: 0, ambiguous: 2 },
              stuck: 1,
              waiting_recipients: 0,
            },
          },
        },
      }),
    );
    renderPage();

    expect(await screen.findByText("degraded — audit writes are failing")).toBeInTheDocument();
    expect(screen.getByText("PostgreSQL: ok · Redis: error")).toBeInTheDocument();
    expect(screen.getByText(/1 stuck/)).toBeInTheDocument();
    // One request for the summary, the connectors and the channels.
    expect(overviewMock).toHaveBeenCalledTimes(1);
  });

  it("answers \"how many findings\" and \"how many new incidents\" separately", async () => {
    // Four stored breach findings and five incidents the sources added in the same
    // window are different facts, and the card prints the server's own wording for
    // each, so the same figure means the same thing in the report (WI-16).
    renderPage();
    expect(await screen.findByText("New breach incidents (7d)")).toBeInTheDocument();
    // The label renders while the query is still in flight, so the value is awaited.
    await waitFor(() => expect(screen.getByText("5")).toBeInTheDocument());
    expect(
      screen.getByText(/incidents the configured sources added to their own catalogues/),
    ).toBeInTheDocument();
    expect(screen.getByText(/findings stored from the configured breach sources/)).toBeInTheDocument();
    // The findings total is split by class of exposure in the card that carries it.
    expect(screen.getByText("3 breach of an account · 1 paste · 0 stealer log")).toBeInTheDocument();
  });

  it("refreshes the whole dashboard with one request", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());
    await user.click(screen.getAllByRole("button", { name: "Refresh" })[0]);
    // Every Refresh button on the page, including the ones inside the health
    // sections, re-reads the single overview: there is nothing left to fetch
    // separately, and a section refresh must not resurrect the three-request load.
    await waitFor(() => expect(overviewMock).toHaveBeenCalledTimes(2));
  });

  it("shows a skeleton, not an empty chart, while the statistics are in flight", async () => {
    // The failure this locks down: the cards used to test the *length* of the
    // series, which is zero before the answer arrives, so the most-opened page
    // asserted "No findings recorded in the last 30 days" during its first paint.
    overviewMock.mockReset().mockReturnValue(new Promise(() => {}));
    renderPage();

    expect(await screen.findByText("Dashboard")).toBeInTheDocument();
    expect(screen.getAllByTestId("chart-loading")).toHaveLength(3);
    // No card may speak about the data before the data exists.
    expect(screen.queryAllByText(/No .*(yet|recorded)/)).toHaveLength(0);
    expect(screen.queryByText(/No findings recorded/)).not.toBeInTheDocument();
    expect(screen.queryByText(/No assets yet/)).not.toBeInTheDocument();
    expect(screen.queryByText(/No phishing findings yet/)).not.toBeInTheDocument();
    // No chart is drawn over an empty series either.
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("states emptiness by the series' total, so a zeroed 30-day calendar is empty", async () => {
    overviewMock.mockReset().mockResolvedValue(overviewResponse({ summary: emptyStats }));
    renderPage();

    // The server always returns 30 calendar days, so the timeline's empty state
    // can never be reached by looking at the array length.
    expect(await screen.findByText("No findings recorded in the last 30 days.")).toBeInTheDocument();
    expect(screen.getByText("No assets yet.")).toBeInTheDocument();
    expect(screen.getByText("No phishing findings yet.")).toBeInTheDocument();
    expect(screen.queryAllByTestId("chart-loading")).toHaveLength(0);
    expect(chartProps.filter((entry) => entry.component === "Line")).toHaveLength(0);
    // There is no total to print, so no total is printed.
    expect(screen.queryByText(/^Window:/)).not.toBeInTheDocument();
  });

  it("draws daily counters without interpolating between them", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());

    const lines = chart("Line");
    expect(lines.map((props) => [props.dataKey, props.type])).toEqual([
      ["phishing", "linear"],
      ["breaches", "linear"],
    ]);
    // A smoothed line invents values between two measured days.
    expect(lines.every((props) => props.type !== "monotone")).toBe(true);
  });

  it("names the window with its year and UTC, and describes each chart for a screen reader", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());

    expect(screen.getByText(/Window: 2026-01-01 … 2026-01-30 \(UTC\)/)).toBeInTheDocument();
    expect(
      screen.getByRole("img", {
        name: /Findings per day by module, 2026-01-01 … 2026-01-30, UTC — Phishing, Credential breaches/,
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /Active assets by criticality/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /Phishing findings by detection source/ }),
    ).toBeInTheDocument();
    // The visible totals are the text equivalent of the drawn series: the
    // numbers are summed over the whole window, not read off the last point.
    expect(screen.getByText(/Phishing 1 · Credential breaches 2/)).toBeInTheDocument();
    // The same series over the 30 days before the window (U-4).
    expect(screen.getByText(/Previous 30 days: Phishing 4 · Credential breaches 0/)).toBeInTheDocument();
    expect(screen.getByText(/Total 2 active assets · 2 critical/)).toBeInTheDocument();
    expect(screen.getByText(/Total 3 findings · 3 Domain look-alike/)).toBeInTheDocument();
  });

  it("names the row by what it contains, and says what it leaves out", async () => {
    // The card's caption is the series list, not a claim about "threats": the
    // row is built from the registry, and the modules it excludes say so.
    renderPage();
    expect(
      await screen.findByText(
        /Stored findings by day \(UTC\) from the modules that record them: Phishing, Credential breaches\./,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Not in this series: DNS Security \(current-state observations, not dated findings\), Exposure/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/Threat Timeline/)).not.toBeInTheDocument();
  });

  it("draws a module the page has never heard of, straight from the registry", async () => {
    // DHP-11 acceptance: a declared module changes the row without a frontend
    // change. Everything the chart needs — key, label, previous total — is in
    // the response, so this test adds a module only to the payload.
    overviewMock.mockReset().mockResolvedValue(
      overviewResponse({
        summary: {
          ...stats,
          timeline: [
            { date: "2026-01-01", phishing: 1, breaches: 2, brand_abuse: 3 },
            { date: "2026-01-30", phishing: 0, breaches: 0, brand_abuse: 1 },
          ],
          timeline_series: [
            ...stats.timeline_series,
            { key: "brand_abuse", label: "Brand abuse", module_id: "brand_abuse" },
          ],
          timeline_comparison: {
            ...stats.timeline_comparison,
            brand_abuse: { current: 4, previous: 2 },
          },
        },
      }),
    );
    renderPage();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());

    expect(chart("Line").map((props) => [props.dataKey, props.name])).toEqual([
      ["phishing", "Phishing"],
      ["breaches", "Credential breaches"],
      ["brand_abuse", "Brand abuse"],
    ]);
    expect(screen.getByText(/Brand abuse 4/)).toBeInTheDocument();
    expect(
      screen.getByText(/Previous 30 days: Phishing 4 · Credential breaches 0 · Brand abuse 2/),
    ).toBeInTheDocument();
  });

  it("counts active assets, not assets some module monitors", async () => {
    // The KPI is `count(assets) where is_active`; "monitored" promised coverage
    // that the number never measured (DSH-11).
    renderPage();
    expect(await screen.findByText("Active assets")).toBeInTheDocument();
    expect(screen.queryByText("Monitored assets")).not.toBeInTheDocument();
  });

  it("shows each health field the API sends instead of leaving it invisible", async () => {
    const connectorsPayload = {
      items: [
        {
          name: "shodan",
          connector_type: "phishing",
          health: "failed",
          status: "enabled",
          online: true,
          last_seen_at: "2026-01-01T00:00:00Z",
          last_error: null,
          blocked_reason: "provider_account_missing",
          quota_remaining: 10,
          quota_budget: 100,
          quota_reason: null,
          credentials_configured: true,
          credential_state: "invalid",
          provider_error: "invalid_credentials",
          checked_at: "2026-01-01T00:00:00Z",
          last_success_at: "2025-12-31T18:00:00Z",
          last_success_age_seconds: 21600,
          readiness: null,
        },
      ],
      generated_at: "2026-01-01T00:00:00Z",
    };
    const channelsPayload = {
      items: [
        {
          channel: "email",
          label: "Email / SMTP",
          enabled: true,
          configured: false,
          health: "degraded",
          message: "SMTP settings are incomplete",
          probe_state: "skipped",
          checked_at: null,
          from_cache: false,
          delivery: {
            counts: { pending: 0, delivering: 0, sent: 0, failed: 0, cancelled: 0, ambiguous: 2 },
            oldest_unresolved_at: "2025-12-31T23:30:00Z",
            oldest_unresolved_age_seconds: 1800,
            retrying: 0,
            stuck: 2,
            degraded_reason: "delivery_stuck",
          },
        },
      ],
      delivery_queue: { waiting_recipients: 0 },
      generated_at: "2026-01-01T00:00:00Z",
    };
    overviewMock.mockReset().mockResolvedValue(
      overviewResponse({ connectors: connectorsPayload, channels: channelsPayload }),
    );
    renderPage();

    // `online` is not the badge restated: this worker failed its last scan and
    // is still alive, which is the difference the DNS page's Rescan depends on.
    expect(await screen.findByText(/last seen 2026-01-01 00:00:00/)).toBeInTheDocument();
    expect(screen.getByText("online")).toBeInTheDocument();
    expect(screen.getByText(/Scans are blocked: no provider account is bound/)).toBeInTheDocument();
    expect(screen.getByText(/10 of 100 requests left today/)).toBeInTheDocument();
    // Readiness explains a refusal the badge cannot: the worker is alive and
    // "failed", but the reason is a rejected key, not a broken container.
    expect(screen.getByText(/Credentials: rejected by the provider/)).toBeInTheDocument();
    expect(screen.getByText(/the provider rejected the API key/)).toBeInTheDocument();
    // "Worker alive" and "collection worked" are printed as separate facts.
    expect(
      screen.getByText(/Last successful collection: 2025-12-31 18:00:00 \(6 h ago\)/),
    ).toBeInTheDocument();
    // `configured` explains a `not_configured` badge instead of leaving it to prose.
    expect(screen.getByText(/Channel configuration: incomplete/)).toBeInTheDocument();
    expect(screen.getByText(/not probed, channel disabled/)).toBeInTheDocument();
    expect(
      screen.getByText(/Delivery queue: 0 pending · 0 retrying · 0 sending · 2 ambiguous · 0 failed · oldest 30 min/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/2 deliveries have been unresolved longer than the recipient-hold window/),
    ).toBeInTheDocument();
    // `generated_at` is the freshness marker for both sections.
    expect(screen.getAllByText(/Data as of 2026-01-01 00:00:00/)).toHaveLength(2);
  });

  it("shows nothing administrator-only when the API nulls those fields", async () => {
    overviewMock.mockReset().mockResolvedValue(
      overviewResponse({
        connectors: {
          items: [
            {
              name: "shodan",
              connector_type: "phishing",
              health: "degraded",
              status: "enabled",
              online: false,
          last_seen_at: "2025-12-31T00:00:00Z",
          last_error: null,
          blocked_reason: null,
          quota_remaining: null,
          quota_budget: null,
          quota_reason: null,
          credentials_configured: false,
          credential_state: "unknown",
          provider_error: null,
          checked_at: null,
          last_success_at: null,
          last_success_age_seconds: null,
              readiness: null,
            },
          ],
          generated_at: "2026-01-01T00:00:00Z",
        },
      }),
    );
    renderPage();

    expect(await screen.findByText(/last seen 2025-12-31 00:00:00/)).toBeInTheDocument();
    expect(screen.getByText("offline")).toBeInTheDocument();
    expect(screen.queryByText(/Scans are blocked/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Provider quota/)).not.toBeInTheDocument();
    // Nothing was declared about the key, and nothing was ever collected: both
    // are stated rather than left blank.
    expect(screen.getByText(/Credentials: not checked yet/)).toBeInTheDocument();
    expect(screen.getByText(/no key visible to the worker/)).toBeInTheDocument();
    expect(screen.getByText(/Last successful collection: never/)).toBeInTheDocument();
  });
});
