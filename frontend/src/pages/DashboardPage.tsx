import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, PieChart, Pie, Cell,
} from "recharts";
import {
  ListTree, ShieldAlert, AlertTriangle, Activity, RefreshCw, CheckCircle2,
  XCircle, AlertOctagon, Settings, Mail, Send, Plug, Globe,
} from "lucide-react";
import { endpoints } from "@/lib/api";
import { formatNumber } from "@/lib/utils";
import { detectionSourceLabel } from "@/lib/labels";
import { BREACH_EXPOSURE_KINDS, breachExposureKindLabel } from "@/lib/breach";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import type {
  AlertChannelHealth, AlertDeliverySummary, ConnectorHealth, DashboardOverview, HealthState,
  PlatformStatus,
} from "@/types/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ErrorState } from "@/components/ui/error-state";
import { ChartState } from "@/components/ui/chart-state";

const COLORS: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

/** A colour per timeline series, by position. The series come from the registry,
 * so a new module gets a colour without a frontend change; ordering is the
 * server's (module id), which keeps a series' colour stable between loads. */
const SERIES_COLORS = ["#f97316", "#ef4444", "#3b82f6", "#22c55e", "#a855f7"];

/** Why a declared module is not in the finding timeline, in operator words. */
const EXCLUDED_REASON_LABELS: Record<string, string> = {
  current_state_observations: "current-state observations, not dated findings",
  unsupported_storage: "storage this build cannot count",
};

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

/** Provider credential states, in operator words. `valid` is not printed: a
 * card that repeats "credentials fine" on every line trains people to skip it. */
const CREDENTIAL_STATE_LABELS: Record<string, string> = {
  invalid: "rejected by the provider",
  unsupported: "unsupported by this platform",
  unknown: "not checked yet",
};

/** The provider's last failure, from the closed list the API publishes. */
const PROVIDER_ERROR_LABELS: Record<string, string> = {
  invalid_credentials: "the provider rejected the API key",
  ip_restricted: "the provider refused this installation's address",
  access_denied: "the provider account is not allowed to do this",
  credits_exhausted: "the provider account has no credit left",
  rate_limited: "the provider is rate-limiting the key",
  provider_application_error: "the provider reported an internal error",
  provider_rejected_request: "the provider rejected the request",
  network_or_invalid_response: "the provider answer was unreadable",
};

/** What the probe itself did. Only `ok` is an observation of the channel;
 * `saturated` and `timeout` describe the probe, and `skipped` says nothing was
 * attempted because the channel is off. */
const PROBE_STATE_LABELS: Record<string, string> = {
  ok: "probe completed",
  saturated: "probe pool busy, so the channel was not observed",
  timeout: "probe timed out",
  skipped: "not probed, channel disabled",
};

/** The two codes the core uses to refuse a provider's scan, in operator words. */
const BLOCKED_REASON_LABELS: Record<string, string> = {
  provider_account_missing: "no provider account is bound to this connector",
  account_policy_unapproved: "the provider account's policy is not approved",
};

/** A closed-vocabulary code as words, for codes this build does not know yet. */
function humanizeCode(code: string): string {
  return code.replace(/_/g, " ");
}

function HealthBadge({ health }: { health: HealthState }) {
  const Icon = icons[health];
  return (
    <Badge variant="outline" className={tones[health]}>
      <Icon className="w-3 h-3 mr-1" />                <span>{healthLabels[health]}</span>
    </Badge>
  );
}

/** A duration an operator can read at a glance, from a second count. */
function ageLabel(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 120) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h`;
  return `${Math.floor(hours / 24)} d`;
}

/** The queue's own verdict, beside the probe's.
 *
 * A green probe means the installation can reach the provider; it does not mean
 * messages are leaving. This block is what keeps the badge from being read as a
 * delivery guarantee, and it prints only counts the server already publishes.
 */
function DeliverySummary({ delivery }: { delivery: AlertDeliverySummary }) {
  const { counts } = delivery;
  const unresolved =
    counts.pending + counts.delivering + counts.ambiguous + counts.failed;
  return (
    <div className="space-y-1">
      <div className="text-xs text-muted-foreground">
        {unresolved === 0
          ? "Delivery queue: empty"
          : `Delivery queue: ${formatNumber(counts.pending)} pending · ${formatNumber(delivery.retrying)} retrying · ${formatNumber(counts.delivering)} sending · ${formatNumber(counts.ambiguous)} ambiguous · ${formatNumber(counts.failed)} failed${
              delivery.oldest_unresolved_age_seconds != null
                ? ` · oldest ${ageLabel(delivery.oldest_unresolved_age_seconds)}`
                : ""
            }`}
      </div>
      {delivery.degraded_reason === "delivery_stuck" && (
        <div className="text-xs text-amber-600 dark:text-amber-400">
          {delivery.stuck === 1
            ? "1 delivery has been unresolved longer than the recipient-hold window, so the channel is degraded by its queue rather than by its probe."
            : `${formatNumber(delivery.stuck)} deliveries have been unresolved longer than the recipient-hold window, so the channel is degraded by its queue rather than by its probe.`}
        </div>
      )}
    </div>
  );
}

/** What the platform says about itself, on the first screen.
 *
 * Every number here is computed by `/dashboard/stats` from the same probes and
 * rules as `/ready` and the metrics endpoint — this block is why an operator
 * does not have to open three other pages to notice that audit writes are
 * failing or that the delivery queue has stopped moving.
 */
function PlatformStatusCard({ platform }: { platform: PlatformStatus }) {
  const dependenciesOk = platform.database === "ok" && platform.redis === "ok";
  const { counts, stuck, waiting_recipients } = platform.deliveries;
  const queueProblem = stuck > 0 || counts.ambiguous > 0 || counts.failed > 0;
  const longest = platform.connectors.longest_silence;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Platform status</CardTitle>
        <CardDescription>
          Same probes as <code>/ready</code> and the same rules as the metrics endpoint,
          computed while this page loads; nothing here costs another request.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 text-sm">
        <div>
          <div className="text-xs text-muted-foreground">Dependencies</div>
          <div className={dependenciesOk ? "text-green-600 dark:text-green-400" : "text-red-600 dark:text-red-400"}>
            {`PostgreSQL: ${platform.database} · Redis: ${platform.redis}`}
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Audit trail</div>
          {platform.audit_degraded ? (
            // The condition `/ready` answers 503 on. Being on the dashboard is the
            // point: a failing audit trail means mutations are unreviewable, and
            // that is not a fact to discover from a probe URL.
            <div role="status" className="text-red-600 dark:text-red-400">
              degraded — audit writes are failing
            </div>
          ) : (
            <div className="text-green-600 dark:text-green-400">intact</div>
          )}
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Connectors</div>
          <div>{`${platform.connectors.enabled} enabled · ${platform.connectors.disabled} disabled · ${platform.connectors.silent} silent`}</div>
          {longest && (
            <div className="text-xs text-muted-foreground">
              {longest.seconds === null
                ? `longest silence: ${longest.name} — never checked in`
                : `longest silence: ${longest.name} — ${ageLabel(longest.seconds)}`}
            </div>
          )}
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Oldest running job</div>
          <div>
            {platform.oldest_running_job_seconds === null
              ? "none running"
              : ageLabel(platform.oldest_running_job_seconds)}
          </div>
        </div>
        <div>
          <div className="text-xs text-muted-foreground">Delivery queue</div>
          <div className={queueProblem ? "text-amber-600 dark:text-amber-400" : ""}>
            {`${formatNumber(counts.pending)} pending · ${formatNumber(counts.ambiguous)} ambiguous · ${formatNumber(counts.failed)} failed`}
          </div>
          <div className="text-xs text-muted-foreground">
            {`${formatNumber(waiting_recipients)} recipient${waiting_recipients === 1 ? "" : "s"} waiting`}
            {stuck > 0 ? ` · ${formatNumber(stuck)} stuck` : ""}
          </div>
        </div>
      </CardContent>
    </Card>
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
        {"online" in item && (
          // ``online`` is liveness on its own: a connector whose last scan failed
          // is still online, and health cannot say that. The DNS page gates its
          // Rescan button on the same field, so the card explains it next to the
          // timestamp that decides it instead of leaving it API-only.
          <div className="text-xs text-muted-foreground">
            Heartbeat:{" "}
            <span className={item.online ? "text-green-600 dark:text-green-400" : "text-muted-foreground"}>
              {item.online ? "online" : "offline"}
            </span>
            {item.last_seen_at
              ? <span className="font-mono text-foreground"> · last seen {formatDateTime(item.last_seen_at)}</span>
              : " · never seen"}
          </div>
        )}
        {"credential_state" in item && item.credential_state !== "valid" && (
          // Readiness is a different fact from health: an online worker with a
          // rejected key is "failed", while an online worker nobody asked to
          // check it is "healthy" and `unknown` here. Hiding this left the
          // operator with a badge that could not explain a refused scan (D5).
          <div
            className={`text-xs ${
              item.credential_state === "invalid"
                ? "text-red-600 dark:text-red-400"
                : "text-amber-600 dark:text-amber-400"
            }`}
          >
            {`Credentials: ${CREDENTIAL_STATE_LABELS[item.credential_state] ?? humanizeCode(item.credential_state)}`}
            {item.credentials_configured ? "" : " · no key visible to the worker"}
            {item.provider_error
              ? ` — ${PROVIDER_ERROR_LABELS[item.provider_error] ?? humanizeCode(item.provider_error)}`
              : ""}
          </div>
        )}
        {"last_success_at" in item && (
          // "Worker alive" and "collection worked" are separate facts, and the
          // card is where they must not be collapsed into one green badge.
          <div className="text-xs text-muted-foreground">
            {item.last_success_at
              ? `Last successful collection: ${formatDateTime(item.last_success_at)}${
                  item.last_success_age_seconds != null
                    ? ` (${ageLabel(item.last_success_age_seconds)} ago)`
                    : ""
                }`
              : "Last successful collection: never"}
          </div>
        )}
        {"probe_state" in item && (
          // `checked_at` is when the probe ran, not when this response was
          // built: a cached answer keeps the earlier time, and `from_cache`
          // says so, rather than making every page load look freshly checked.
          <div className="text-xs text-muted-foreground">
            {PROBE_STATE_LABELS[item.probe_state] ?? humanizeCode(item.probe_state)}
            {item.checked_at ? (
              <>
                {" · "}
                <span className="font-mono text-foreground">{formatDateTime(item.checked_at)}</span>
              </>
            ) : null}
            {item.from_cache ? " · cached" : ""}
          </div>
        )}
        {"delivery" in item && <DeliverySummary delivery={item.delivery} />}
        {"configured" in item && (
          // Rendered in both directions: ``configured: false`` is what explains a
          // ``not_configured`` badge, and ``true`` tells the operator that a
          // failure came from the probe rather than from a missing setting.
          <div className={`text-xs ${item.configured ? "text-muted-foreground" : "text-amber-600 dark:text-amber-400"}`}>
            {item.configured
              ? "Channel configuration: complete"
              : "Channel configuration: incomplete — no probe can succeed until it is filled in."}
          </div>
        )}
        {"blocked_reason" in item && item.blocked_reason && (
          <div className="text-amber-600 dark:text-amber-400 text-xs">
            Scans are blocked: {BLOCKED_REASON_LABELS[item.blocked_reason] ?? humanizeCode(item.blocked_reason)}
          </div>
        )}
        {"quota_remaining" in item && (item.quota_remaining != null || item.quota_reason) && (
          <div className="text-xs text-muted-foreground">
            {item.quota_remaining != null
              ? `Provider quota: ${formatNumber(item.quota_remaining)}${
                  item.quota_budget != null
                    ? ` of ${formatNumber(item.quota_budget)} requests left today`
                    : " requests left today"
                }`
              : `Provider quota unknown (${humanizeCode(item.quota_reason ?? "")})`}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function HealthSection({
  title, description, loading, error, items, generatedAt, onRefresh, refreshing, type,
}: {
  title: string;
  description: string;
  loading: boolean;
  error: boolean;
  items: (ConnectorHealth | AlertChannelHealth)[];
  generatedAt?: string | null;
  onRefresh: () => void;
  refreshing: boolean;
  type: "connector" | "alert";
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">{title}</h2>
          <p className="text-sm text-muted-foreground">
            {description}
            {generatedAt ? ` · Data as of ${formatDateTime(generatedAt)}` : ""}
          </p>
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
  // One request for the whole page (DHP-10): the summary, connector health and
  // channel health arrive together, so a load is one HTTP request, one audit
  // row and one acquisition of the audit chain's advisory lock. Three queries
  // would have meant three of each, and three chances for the sections to
  // describe different moments.
  const overview = useQuery<DashboardOverview>({
    queryKey: ["dashboard-overview"],
    queryFn: endpoints.dashboardOverview,
    staleTime: 30_000,
  });

  const { data: overviewData, isLoading, isError, refetch, isFetching } = overview;
  const data = overviewData?.summary;
  // A failed overview is a failed section, not a silently empty one: the health
  // cards must say they are unavailable rather than "no connectors registered".
  const connectors = {
    data: overviewData?.connectors,
    isLoading,
    isError,
    isFetching,
  };
  const alerts = {
    data: overviewData?.channels,
    isLoading,
    isError,
    isFetching,
  };
  // The breach captions come from the server, which applies the same rule the report
  // prints: a number whose meaning is written where the number is (WI-16).
  const breachCaptions = data?.kpi.breach?.captions;
  // "How many findings" and "which kind of exposure" are different answers to the same
  // worry, so the split travels beside the total rather than replacing it (WI-16).
  const breachByKind = data?.kpi.breach?.findings_by_exposure_kind;
  const breachBreakdown = breachByKind
    ? BREACH_EXPOSURE_KINDS.map(
        (kind) => `${formatNumber(breachByKind[kind] ?? 0)} ${breachExposureKindLabel(kind).toLowerCase()}`,
      ).join(" · ")
    : undefined;
  const kpis = [
    { label: "Active assets", value: data?.kpi.total_assets ?? 0, icon: ListTree, tone: "text-green-500", bg: "bg-green-500/10" },
    { label: "Phishing findings", value: data?.kpi.total_phishing ?? 0, icon: ShieldAlert, tone: "text-orange-500", bg: "bg-orange-500/10" },
    { label: "Breach matches", value: data?.kpi.total_breaches ?? 0, icon: AlertTriangle, tone: "text-red-500", bg: "bg-red-500/10", caption: breachCaptions?.total_findings, detail: breachBreakdown },
    { label: "Active phishing and breach threats (7d)", value: data?.kpi.active_threats_7d ?? 0, icon: Activity, tone: "text-blue-500", bg: "bg-blue-500/10", caption: breachCaptions?.active_findings_7d },
    { label: "New breach incidents (7d)", value: data?.kpi.new_breach_incidents_7d ?? 0, icon: Globe, tone: "text-violet-500", bg: "bg-violet-500/10", caption: breachCaptions?.new_incidents_7d },
  ];

  // A chart's empty state is a statement about the data, not about the array: the
  // server always returns 30 calendar days, so the timeline can never be "empty"
  // by length, and a pending query must not look empty either (DSH-01).
  //
  // The series are the server's registry view (DHP-11): keys, labels and the list
  // of modules left out all arrive in the response, so this page draws whatever
  // the installation declares instead of two names written into the bundle.
  const timeline = data?.timeline ?? [];
  const timelineSeries = data?.timeline_series ?? [];
  const timelineExcluded = data?.timeline_excluded ?? [];
  const comparison = data?.timeline_comparison ?? {};
  const timelineTotals = timelineSeries.map((series) => ({
    ...series,
    total: timeline.reduce((sum, day) => sum + Number(day[series.key] ?? 0), 0),
  }));
  const timelineTotal = timelineTotals.reduce((sum, series) => sum + series.total, 0);
  const previousTotals = timelineSeries.map((series) => ({
    ...series,
    total: comparison[series.key]?.previous ?? 0,
  }));
  const timelineWindow =
    timeline.length > 0 ? `${timeline[0].date} … ${timeline[timeline.length - 1].date}` : null;
  const timelineDescription =
    timelineSeries.length === 0
      ? "Stored findings by day (UTC). No enabled module records dated findings."
      : `Stored findings by day (UTC) from the modules that record them: ${timelineSeries
          .map((series) => series.label)
          .join(", ")}.${
          timelineExcluded.length > 0
            ? ` Not in this series: ${timelineExcluded
                .map(
                  (item) =>
                    `${item.label} (${EXCLUDED_REASON_LABELS[item.reason] ?? humanizeCode(item.reason)})`,
                )
                .join(", ")}.`
            : ""
        }`;
  const assetSlices = data?.assets_by_criticality ?? [];
  const assetTotal = assetSlices.reduce((total, slice) => total + slice.count, 0);
  const sourceSlices = data?.phishing_by_source ?? [];
  const sourceTotal = sourceSlices.reduce((total, slice) => total + slice.count, 0);
  const chartsReady = !isLoading && !isError;

  const waiting = alerts.data?.delivery_queue?.waiting_recipients;
  const waitingNote =
    waiting === undefined
      ? ""
      : ` ${formatNumber(waiting)} recipient${waiting === 1 ? "" : "s"} waiting on a hold or a retry window.`;

  const refreshAll = () => {
    refetch();
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
        <Button variant="outline" onClick={refreshAll} disabled={isFetching}>
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
        {kpis.map(({ label, value, icon: Icon, tone, bg, caption, detail }) => (
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
                {caption ? <div className="text-xs text-muted-foreground mt-1">{caption}</div> : null}
                {detail ? <div className="text-xs text-muted-foreground mt-1">{detail}</div> : null}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {data?.platform && <PlatformStatusCard platform={data.platform} />}

      <HealthSection
        title="Connectors Health"
        description="Health status reported by registered data-source connectors."
        loading={connectors.isLoading}
        error={connectors.isError}
        items={connectors.data?.items ?? []}
        generatedAt={connectors.data?.generated_at}
        onRefresh={refreshAll}
        refreshing={connectors.isFetching}
        type="connector"
      />

      <HealthSection
        title="Alert Channels Health"
        description={`Operational status of configured alert delivery channels.${waitingNote}`}
        loading={alerts.isLoading}
        error={alerts.isError}
        items={alerts.data?.items ?? []}
        generatedAt={alerts.data?.generated_at}
        onRefresh={refreshAll}
        refreshing={alerts.isFetching}
        type="alert"
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Findings by module — last 30 days</CardTitle>
            <CardDescription>{timelineDescription}</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              <ChartState
                loading={isLoading}
                error={isError}
                empty={timelineTotal === 0}
                errorText="Timeline unavailable while summary statistics cannot be loaded."
                emptyText="No findings recorded in the last 30 days."
              >
                <div
                  className="h-full"
                  role="img"
                  aria-label={`Findings per day by module, ${timelineWindow ?? "the last 30 days"}, UTC — ${timelineSeries
                    .map((series) => series.label)
                    .join(", ")}`}
                >
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={timeline}>
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                      <XAxis
                        dataKey="date"
                        fontSize={11}
                        tickFormatter={(value: string, index: number) =>
                          index === 0 ? value : String(value).slice(5)
                        }
                      />
                      <YAxis fontSize={11} />
                      <Tooltip />
                      <Legend />
                      {timelineSeries.map((series, index) => (
                        <Line
                          key={series.key}
                          type="linear"
                          dataKey={series.key}
                          stroke={SERIES_COLORS[index % SERIES_COLORS.length]}
                          name={series.label}
                        />
                      ))}
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </ChartState>
            </div>
            {chartsReady && timelineTotal > 0 && (
              <p className="mt-2 text-xs text-muted-foreground">
                Window: {timelineWindow} (UTC) ·{" "}
                {timelineTotals
                  .map((series) => `${series.label} ${formatNumber(series.total)}`)
                  .join(" · ")}
              </p>
            )}
            {chartsReady && timelineTotal > 0 && (
              // "More than last month" is answerable without another request: the
              // server counts the same series over the 30 days before this window.
              <p className="mt-1 text-xs text-muted-foreground">
                Previous 30 days:{" "}
                {previousTotals
                  .map((series) => `${series.label} ${formatNumber(series.total)}`)
                  .join(" · ")}
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Assets by Criticality</CardTitle>
            <CardDescription>Active assets grouped by criticality</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-72">
              <ChartState
                loading={isLoading}
                error={isError}
                empty={assetTotal === 0}
                errorText="Asset breakdown unavailable."
                emptyText="No assets yet."
              >
                <div className="h-full" role="img" aria-label="Active assets by criticality">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={assetSlices} dataKey="count" nameKey="criticality" cx="50%" cy="50%" outerRadius={85}>
                        {assetSlices.map((e) => (
                          <Cell key={e.criticality} fill={COLORS[e.criticality] || "#22c55e"} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </ChartState>
            </div>
            {chartsReady && assetTotal > 0 && (
              <p className="mt-2 text-xs text-muted-foreground">
                Total {formatNumber(assetTotal)} active assets ·{" "}
                {assetSlices
                  .map((slice) => `${formatNumber(slice.count)} ${slice.criticality ?? "medium"}`)
                  .join(" · ")}
              </p>
            )}
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
            <ChartState
              loading={isLoading}
              error={isError}
              empty={sourceTotal === 0}
              errorText="Detection sources unavailable."
              emptyText="No phishing findings yet."
            >
              <div className="h-full" role="img" aria-label="Phishing findings by detection source">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={sourceSlices}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis dataKey="source" fontSize={11} tickFormatter={(value) => detectionSourceLabel(String(value))} />
                    <YAxis fontSize={11} />
                    <Tooltip labelFormatter={(value) => detectionSourceLabel(String(value))} />
                    <Bar dataKey="count" fill="hsl(var(--primary))" name="Findings" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </ChartState>
          </div>
          {chartsReady && sourceTotal > 0 && (
            <p className="mt-2 text-xs text-muted-foreground">
              Total {formatNumber(sourceTotal)} findings ·{" "}
              {sourceSlices
                .map((slice) => `${formatNumber(slice.count)} ${detectionSourceLabel(slice.source)}`)
                .join(" · ")}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}