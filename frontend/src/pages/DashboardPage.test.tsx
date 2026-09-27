import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import DashboardPage from "@/pages/DashboardPage";

const { statsMock, connectorsMock, alertsMock } = vi.hoisted(() => ({
  statsMock: vi.fn(),
  connectorsMock: vi.fn(),
  alertsMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    dashboardStats: statsMock,
    connectorsHealth: connectorsMock,
    alertChannelsHealth: alertsMock,
  },
  describeApiError: (error: any) => String(error?.message ?? error ?? ""),
}));

vi.mock("recharts", () => {
  const Component = ({ children }: any) => <div>{children}</div>;
  return {
    BarChart: Component,
    Bar: Component,
    XAxis: Component,
    YAxis: Component,
    CartesianGrid: Component,
    Tooltip: Component,
    ResponsiveContainer: Component,
    LineChart: Component,
    Line: Component,
    Legend: Component,
    PieChart: Component,
    Pie: Component,
    Cell: Component,
  };
});

const stats = {
  kpi: { total_assets: 12, total_phishing: 3, total_breaches: 4, active_threats_7d: 2 },
  timeline: [{ date: "2026-01-01", phishing: 1, breaches: 2 }],
  phishing_by_source: [{ source: "dnstwist", count: 3 }],
  assets_by_criticality: [{ criticality: "critical", count: 2 }],
};

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
    statsMock.mockReset().mockResolvedValue(stats);
    connectorsMock.mockReset().mockResolvedValue({
      items: [{ name: "hibp", connector_type: "breaches", health: "healthy", status: "enabled" }],
      generated_at: "2026-01-01T00:00:00Z",
    });
    alertsMock.mockReset().mockResolvedValue({
      items: [{ channel: "telegram", label: "Telegram", enabled: true, configured: true, health: "degraded", message: "Partial delivery", last_checked_at: "2026-01-01T00:00:00Z" }],
      generated_at: "2026-01-01T00:00:00Z",
    });
  });

  it("renders KPI and health data", async () => {
    renderPage();
    expect(await screen.findByText("Dashboard")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());
    expect(screen.getByText("Connectors Health")).toBeInTheDocument();
    expect(screen.getByText("hibp")).toBeInTheDocument();
    expect(screen.getByText("Partial delivery")).toBeInTheDocument();
    expect(screen.getByText("Threat Timeline — Last 30 days")).toBeInTheDocument();
  });

  it("refreshes all dashboard data", async () => {
    const user = userEvent.setup();
    renderPage();
    await waitFor(() => expect(screen.getByText("12")).toBeInTheDocument());
    await user.click(screen.getAllByRole("button", { name: "Refresh" })[0]);
    await waitFor(() => {
      expect(statsMock).toHaveBeenCalledTimes(2);
      expect(connectorsMock).toHaveBeenCalledTimes(2);
      expect(alertsMock).toHaveBeenCalledTimes(2);
    });
  });
});
