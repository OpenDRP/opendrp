import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, PieChart, Pie, Cell,
} from "recharts";
import {
  ListTree, ShieldAlert, AlertTriangle, Activity, RefreshCw, CheckCircle2,
  XCircle, AlertOctagon, Settings, Mail, Send, Plug,
} from "lucide-react";
import { endpoints } from "@/lib/api";
import { formatNumber } from "@/lib/utils";
import { detectionSourceLabel } from "@/lib/labels";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import type {
  AlertChannelHealth, AlertChannelsHealthResponse, ConnectorHealth,
  ConnectorHealthResponse, DashboardStats, HealthState,
} from "@/types/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ErrorState } from "@/components/ui/error-state";

const COLORS: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

const tones: Record<HealthState, string> = {
  healthy: "bg-green-500/15 text-green-500 border-green-500/30",
  degraded: "bg-amber-500/15 text-amber-500 border-amber-500/30",
  failed: "bg-red-500/15 text-red-500 border-red-500/30",
  disabled: "bg-gray-500/15 text-gray-500 border-gray-500/30",
  not_configured: "bg-gray-500/15 text-gray-500 border-gray-500/30",
  unknown: "bg-slate-500/15 text-slate-500 border-slate-500/30",
};

const healthLabels: Record<HealthState, string> = {
  healthy: "Healthy",
  degraded: "Degraded",
  failed: "Failed",
  disabled: "Disabled",
  not_configured: "Not configured",
  unknown: "Unknown",
};

const icons: Record<HealthState, typeof CheckCircle2> = {
  healthy: CheckCircle2,
  degraded: AlertOctagon,
  failed: XCircle,
  disabled: Settings,
  not_configured: Settings,
  unknown: Settings,
};

function HealthBadge({ health }: { health: HealthState }) {
  const Icon = icons[health];
  return (
    <Badge variant="outline" className={tones[health]}>
      <Icon className="w-3 h-3 mr-1" />
      <span>{healthLabels[health]}</span>
    </Badge>
  );
}

function HealthCard({ item, icon: Icon }: { item: ConnectorHealth | AlertChannelHealth; icon: typeof Plug }) {
  const isConnector = "name" in item;
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${tones[item.health]}`}>
              <Icon className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <CardTitle className="text-base truncate">{isConnector ? item.name : item.label}</CardTitle>
              <CardDescription className="text-xs truncate">{isConnector ? item.connector_type : item.channel}</CardDescription>
            </div>
          </div>
          <HealthBadge health={item.health} />
        </div>
      </CardHeader>
      <CardContent className="text-sm space-y-1.5">
        {"message" in item && <div className="text-muted-foreground">{item.message}</div>}
        {"last_error" in item && item.last_error && (
          <div className="text-red-600 dark:text-red-400 text-xs">{item.last_error}</div>
        )}
        {"latency_ms" in item && item.latency_ms != null && (
          <div className="text-xs text-muted-foreground">
            Latency: <span className="font-mono text-foreground">{item.latency_ms} ms</span>
          </div>
        )}
        {"last_seen_at" in item && item.last_seen_at && (
          <div className="text-xs text-muted-foreground">
            Last heartbeat: <span className="font-mono text-foreground">{formatDateTime(item.last_seen_at)}</span>
          </div>
        )}
        {"last_checked_at" in item && (
          <div className="text-xs text-muted-foreground">
            Last checked: <span className="font-mono text-foreground">{formatDateTime(item.last_checked_at)}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function HealthSection({
  title, description, loading, error, items, onRefresh, refreshing, type,
}: {
  title: string;
  description: string;
  loading: boolean;
  error: boolean;
  items: (ConnectorHealth | AlertChannelHealth)[];
  onRefresh: () => void;
  refreshing: boolean;
  type: "connector" | "alert";
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{title}</h2>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh} disabled={refreshing}>
          <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${refreshing ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      ) : error ? (
        <ErrorState
          title={`${title} unavailable`}
          description={
            type === "connector"
              ? "Connector health could not be retrieved. Scan activity may be running without being reported here."
              : "Alert channel health could not be retrieved, so delivery status is unknown."
          }
          onRetry={onRefresh}
        />
      ) : items.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            {type === "connector"
              ? "No connectors are registered yet. Start a connector container and it will register itself."
              : "No alert channels are configured yet. Configure them in Settings to be notified about new findings."}
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {items.map((item, index) => (
            <HealthCard
              key={"name" in item ? `${item.connector_type}:${item.name}` : item.channel || index}
              item={item}
              icon={type === "connector" ? Plug : "channel" in item && item.channel === "telegram" ? Send : Mail}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function DashboardPage() {
  const stats = useQuery<DashboardStats>({
    queryKey: ["dashboard-stats"],
    queryFn: endpoints.dashboardStats,
    staleTime: 30_000,
  });
  const connectors = useQuery<ConnectorHealthResponse>({
    queryKey: ["connectors-health"],
    queryFn: endpoints.connectorsHealth,
    staleTime: 60_000,
  });
  const alerts = useQuery<AlertChannelsHealthResponse>({
    queryKey: ["alert-channels-health"],
    queryFn: endpoints.alertChannelsHealth,
    staleTime: 60_000,
  });

  const { data, isLoading, isError, refetch, isFetching } = stats;
  const kpis = [
    { label: "Monitored assets", value: data?.kpi.total_assets ?? 0, icon: ListTree, tone: "text-green-500", bg: "bg-green-500/10" },
    { label: "Phishing findings", value: data?.kpi.total_phishing ?? 0, icon: ShieldAlert, tone: "text-orange-500", bg: "bg-orange-500/10" },
    { label: "Breach matches", value: data?.kpi.total_breaches ?? 0, icon: AlertTriangle, tone: "text-red-500", bg: "bg-red-500/10" },
    { label: "Active threats (7d)", value: data?.kpi.active_threats_7d ?? 0, icon: Activity, tone: "text-blue-500", bg: "bg-blue-500/10" },
  ];

  const refreshAll = () => {
    refetch();
    connectors.refetch();
    alerts.refetch();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Overview of assets, threats and exposure across your digital footprint. {TIME_ZONE_HINT}.
          </p>
        </div>
        <Button
          variant="outline"
          onClick={refreshAll}
          disabled={isFetching || connectors.isFetching || alerts.isFetching}
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {isError && (
        <ErrorState
          title="Summary statistics unavailable"
          description="The counters below could not be loaded, so they are hidden rather than shown as zero."
          onRetry={() => refetch()}
        />
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {kpis.map(({ label, value, icon: Icon, tone, bg }) => (
          <Card key={label}>
            <CardContent className="p-5">
              <div className={`w-10 h-10 rounded-xl ${bg} flex items-center justify-center`}>
                <Icon className={`w-5 h-5 ${tone}`} />
              </div>
              <div className="mt-4">
                {isLoading ? (
                  <Skeleton className="h-8 w-28 mb-2" />
                ) : isError ? (
                  <div className="text-3xl font-bold text-muted-foreground tracking-tight">—</div>
                ) : (
                  <div className="text-3xl font-bold text-foreground tracking-tight">{formatNumber(value)}</div>
                )}
                <div className="text-sm text-muted-foreground mt-1">{label}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <HealthSection
        title="Connectors Health"
        description="Health status reported by registered data-source connectors."
        loading={connectors.isLoading}
        error={connectors.isError}
        items={connectors.data?.items ?? []}
        onRefresh={() => connectors.refetch()}
        refreshing={connectors.isFetching}
        type="connector"
      />

      <HealthSection
        title="Alert Channels Health"
        description="Operational status of configured alert delivery channels."
        loading={alerts.isLoading}
        error={alerts.isError}
        items={alerts.data?.items ?? []}
        onRefresh={() => alerts.refetch()}
        refreshing={alerts.isFetching}
        type="alert"
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Threat Timeline — Last 30 days</CardTitle>
            <CardDescription>Phishing findings vs breach matches, by day (UTC)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              {isError ? (
                <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                  Timeline unavailable while summary statistics cannot be loaded.
                </div>
              ) : !data?.timeline?.length ? (
                <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                  No findings recorded in the last 30 days.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={data.timeline}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis dataKey="date" fontSize={11} tickFormatter={(v) => v.slice(5)} />
                    <YAxis fontSize={11} />
                    <Tooltip />
                    <Legend />
                    <Line type="monotone" dataKey="phishing" stroke="#f97316" name="Phishing" />
                    <Line type="monotone" dataKey="breaches" stroke="#ef4444" name="Breach matches" />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Assets by Criticality</CardTitle>
            <CardDescription>Monitored assets grouped by criticality</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              {isError ? (
                <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                  Asset breakdown unavailable.
                </div>
              ) : !data?.assets_by_criticality?.length ? (
                <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                  No assets yet.
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={data.assets_by_criticality} dataKey="count" nameKey="criticality" cx="50%" cy="50%" outerRadius={85}>
                      {data.assets_by_criticality.map((e) => (
                        <Cell key={e.criticality} fill={COLORS[e.criticality] || "#22c55e"} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Phishing Findings by Detection Source</CardTitle>
          <CardDescription>Sources reported by registered connectors</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-60">
            {isError ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                Detection sources unavailable.
              </div>
            ) : !data?.phishing_by_source?.length ? (
              <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                No phishing findings yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.phishing_by_source}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="source" fontSize={11} tickFormatter={(value) => detectionSourceLabel(String(value))} />
                  <YAxis fontSize={11} />
                  <Tooltip labelFormatter={(value) => detectionSourceLabel(String(value))} />
                  <Bar dataKey="count" fill="hsl(var(--primary))" name="Findings" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}