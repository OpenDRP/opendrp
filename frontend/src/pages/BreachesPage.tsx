import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, RefreshCw, Rocket, Globe, Calendar, Hash, Trash2, Mail, Eraser, PlusCircle } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import { formatNumber } from "@/lib/utils";
import { humanizeKey, threatStatusLabel } from "@/lib/labels";
import {
  BREACH_EXPOSURE_KINDS,
  BREACH_FLAG_FILTERS,
  BREACH_SEVERITIES,
  BREACH_SORT_OPTIONS,
  breachAttribute,
  breachDataClassLabel,
  breachExposureKind,
  breachExposureKindLabel,
  breachExtraAttributes,
  breachFlag,
  breachReadinessReasonLabel,
  breachReadinessStatusLabel,
  breachReadinessVerdict,
  breachSeverity,
  breachSeverityLabel,
  breachSeverityTone,
  breachVerificationFor,
  breachVerificationReasonLabel,
  breachVerificationStatusLabel,
  formatBreachAttributeValue,
} from "@/lib/breach";
import { useModuleJobTypes } from "@/hooks/useModuleJobTypes";
import { TIME_ZONE_HINT, formatDate, formatDateTime } from "@/lib/datetime";
import type {
  Breach,
  BreachDomainVerification,
  BreachExposureKind,
  BreachFlagFilter,
  BreachProviderReadiness,
  BreachSeverity,
  ThreatStatus,
} from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { JobsTable } from "@/components/JobsTable";
import { toast } from "@/components/ui/use-toast";
import { summarizeScanJobs, waitForScanJobs } from "@/lib/scanPolling";

const STATUSES: ThreatStatus[] = ["active", "investigating", "resolved"];

const statusTone: Record<ThreatStatus, string> = {
  active: "bg-red-500/15 text-red-500 border-red-500/30",
  investigating: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  resolved: "bg-green-500/15 text-green-500 border-green-500/30",
};

/**
 * What the source answered about enrolling one domain (WI-20).
 *
 * Rendered inside the domain's own row: the record an operator has to publish, the
 * time the attempt was answered, and why it was refused when it was. A verified
 * domain keeps its line so the page says the access exists, not that it was asked
 * for, and an answer this build has never seen still names itself.
 */
function VerificationAttempt({ attempt }: { attempt: BreachDomainVerification }) {
  const tone =
    attempt.status === "verified"
      ? "border-emerald-500/40 text-emerald-600"
      : attempt.status === "failed"
        ? "border-red-500/40 text-red-600"
        : "border-amber-500/40 text-amber-600";
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className="text-muted-foreground">Last attempt:</span>
      <Badge variant="outline" className={tone}>
        {breachVerificationStatusLabel(attempt.status)}
      </Badge>
      {attempt.requested_at ? (
        <span className="text-muted-foreground">{formatDateTime(attempt.requested_at)}</span>
      ) : null}
      {attempt.txt_record_value ? (
        <code className="break-all rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
          {attempt.txt_record_value}
        </code>
      ) : null}
      {breachVerificationReasonLabel(attempt.reason) ? (
        <span className="text-muted-foreground">{breachVerificationReasonLabel(attempt.reason)}</span>
      ) : null}
    </div>
  );
}

export default function BreachesPage() {
  const canWrite = useIsAnalystPlus();
  const isAdmin = useIsAdmin();
  const qc = useQueryClient();
  // Declared by the registered breach connectors, not by this page.
  const moduleJobTypes = useModuleJobTypes("breaches");

  const [findingId] = useState(() => new URLSearchParams(window.location.search).get("finding_id") || undefined);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  // "What did the last scan turn up?" is the question an operator opens this page
  // with, and it is not the same as "what is still exposed?" (WI-09).
  const [newSinceLastScan, setNewSinceLastScan] = useState(false);
  // An account was compromised, appeared in a paste, or was found in a stealer log:
  // three different things to do about the same row, so they are filtered apart
  // rather than mixed into one total (WI-21).
  const [exposureKind, setExposureKind] = useState<BreachExposureKind | "all">("all");
  // "What can be done with the data" and "who said so" are the two questions
  // triage asks after "what is new": severity comes from the exposed classes, the
  // flag from the source's own payload, and the status from the operator (F-13).
  const [severity, setSeverity] = useState<BreachSeverity | "all">("all");
  const [flag, setFlag] = useState<BreachFlagFilter | "all">("all");
  const [statusFilter, setStatusFilter] = useState<ThreatStatus | "all">("all");
  const [domainFilter, setDomainFilter] = useState("");
  const debouncedDomain = useDebounce(domainFilter, 400);
  // One ordering at a time, as `sort`/`order`; the API refuses a field outside the
  // set it declares, so the page cannot ask for an order that has no index behind it.
  const [sortValue, setSortValue] = useState<string>(BREACH_SORT_OPTIONS[0].value);
  const sort = BREACH_SORT_OPTIONS.find((option) => option.value === sortValue) ?? BREACH_SORT_OPTIONS[0];

  const [deleteOpen, setDeleteOpen] = useState(false);
  // AWI-13/U-1: the finding already names the value; monitoring it is one click
  // instead of a retyped mailbox on the assets page.
  const promoteMut = useMutation({
    mutationFn: (id: string) => endpoints.promoteBreachAsset(id),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast({
        title: result?.already_exists ? "Already monitored" : "Asset added",
        description: result?.already_exists
          ? "That value was already in the inventory; nothing changed."
          : "The value this finding names is now monitored.",
      });
    },
    onError: (error: any) =>
      toast({
        variant: "destructive",
        title: "Could not take the value under monitoring",
        description: describeApiError(error),
      }),
  });
  const [deletingBreach, setDeletingBreach] = useState<Breach | null>(null);
  const [cleanOrphansOpen, setCleanOrphansOpen] = useState(false);
  const [highlightedBreachName, setHighlightedBreachName] = useState<string | null>(null);

  const { data, isLoading, isPlaceholderData, isError, refetch, isFetching } = useQuery({
    queryKey: [
      "breaches",
      findingId,
      page,
      size,
      debouncedSearch,
      newSinceLastScan,
      exposureKind,
      severity,
      flag,
      statusFilter,
      debouncedDomain,
      sortValue,
    ],
    queryFn: () => endpoints.listBreaches({
      finding_id: findingId,
      page,
      size,
      search: debouncedSearch || undefined,
      new_since_last_scan: newSinceLastScan || undefined,
      exposure_kind: exposureKind === "all" ? undefined : exposureKind,
      severity: severity === "all" ? undefined : severity,
      flag: flag === "all" ? undefined : flag,
      status: statusFilter === "all" ? undefined : statusFilter,
      domain: debouncedDomain.trim() || undefined,
      sort: sort.sort,
      order: sort.order,
    }),
    staleTime: 30_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0, unannounced: 0, new_since: null },
  });

  // What the last scan was allowed to ask (F-04, WI-14). Read from the scan's own
  // summary, so an empty list beside a refused domain cannot be mistaken for a clean
  // scan, and the page and Jobs history cannot disagree about the same run.
  const { data: readiness } = useQuery<BreachProviderReadiness>({
    queryKey: ["breaches", "provider-readiness"],
    queryFn: () => endpoints.breachProviderReadiness(),
    staleTime: 30_000,
  });

  const updateStatusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: ThreatStatus }) => endpoints.updateBreach(id, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["breaches"] }); toast({ title: "Breach updated" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Update failed", description: describeApiError(e) }),
  });
  const cleanOrphansMut = useMutation({
    mutationFn: () => endpoints.cleanOrphanBreaches(),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["breaches"] });
      setCleanOrphansOpen(false);
      toast({
        title: "Orphan breach entries cleaned",
        description: `${result.deleted ?? 0} entr${result.deleted === 1 ? "y" : "ies"} deleted.`,
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to clean orphan breach entries", description: describeApiError(e) }),
  });

  const scanMut = useMutation({
    mutationFn: async () => {
      const started = await endpoints.scanBreaches();
      const jobs = started?.job_ids?.length ? await waitForScanJobs(started.job_ids) : [];
      return { started, jobs };
    },
    onSuccess: ({ started, jobs }) => {
      qc.invalidateQueries({ queryKey: ["breaches"] });
      const summary = summarizeScanJobs(jobs);
      const scheduled = started?.status === "scheduled";
      const alreadyRunning = started?.status === "already_running";
      toast({
        variant: summary.failed || (!scheduled && !alreadyRunning) ? "destructive" : "default",
        title: summary.failed ? "Breach rescan failed" : alreadyRunning ? "Breach rescan already running" : !scheduled ? "Breach connector unavailable" : summary.pending || !jobs.length ? "Breach rescan started" : "Breach rescan completed",
        description: started?.error || (alreadyRunning ? "Follow the existing scan in Jobs history." : summary.failed ? `${summary.failed} job(s) failed. See Jobs history for details.` : summary.pending || !jobs.length ? `${started?.job_ids?.length ?? 0} job(s) queued. Progress is in Jobs history below.` : `${summary.succeeded} job(s) completed.`),
      });
    },
    onError: (e: any) => {
      // 429 carries the operator-facing explanation of the per-user rate limit.
      toast({
        variant: "destructive",
        title: e?.response?.status === 429 ? "Rate limit reached" : "Breach scan failed",
        description: describeApiError(e),
      });
    },
  });

  // Enrolling a domain is an operator's step, and the worker's answer is what the
  // page needs next (the TXT value, or why the record is not visible yet), so the
  // request is followed to the end of its job rather than left as "queued" (WI-20).
  const verificationMut = useMutation({
    mutationFn: async ({ domain, action }: { domain: string; action: "generate" | "verify" }) => {
      const started = await endpoints.requestBreachDomainVerification({
        domain,
        action,
        connector: readiness?.connector ?? undefined,
      });
      const jobs = started?.job_ids?.length ? await waitForScanJobs(started.job_ids, { timeoutMs: 2 * 60_000 }) : [];
      return { started, jobs };
    },
    onSuccess: ({ started, jobs }) => {
      qc.invalidateQueries({ queryKey: ["breaches", "provider-readiness"] });
      const summary = summarizeScanJobs(jobs);
      const scheduled = started?.status === "scheduled";
      toast({
        variant: !scheduled || summary.failed ? "destructive" : "default",
        title: !scheduled
          ? "Verification could not be queued"
          : summary.failed
            ? "Verification attempt failed"
            : summary.pending || !jobs.length
              ? "Verification queued"
              : "Verification attempt finished",
        description:
          started?.error ||
          (summary.failed
            ? "See Jobs history for what the source answered."
            : summary.pending || !jobs.length
              ? `${started?.job_ids?.length ?? 0} job(s) queued — the answer appears here when it arrives.`
              : "The source's answer is shown beside the domain."),
      });
    },
    onError: (e: any) => {
      toast({
        variant: "destructive",
        title: e?.response?.status === 429 ? "Rate limit reached" : "Verification request failed",
        description: describeApiError(e),
      });
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => endpoints.deleteBreach(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["breaches"] }); toast({ title: "Breach match deleted" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Delete failed", description: describeApiError(e) }),
  });

  // An attempt whose domain the last scan did not name — no scan has finished, or the
  // domain left the monitored set — still has an answer an operator asked for, and a
  // TXT value nobody can see is a step nobody can take.
  const unlistedVerifications = useMemo(() => {
    const listed = new Set((readiness?.domains ?? []).map((domain) => domain.domain));
    return (readiness?.verifications ?? []).filter((attempt) => !listed.has(attempt.domain));
  }, [readiness]);

  const detailsRows = useMemo(() => {
    const grouped = new Map<string, Breach>();
    for (const breach of data?.items ?? []) {
      const key = `${breach.source_id ?? "unattributed"}:${breach.breach_name}`;
      if (!grouped.has(key)) grouped.set(key, breach);
    }
    return Array.from(grouped.values());
  }, [data?.items]);

  useEffect(() => {
    if (!highlightedBreachName) return;
    const timeout = window.setTimeout(() => setHighlightedBreachName(null), 2500);
    return () => window.clearTimeout(timeout);
  }, [highlightedBreachName]);

  const jumpToDetails = (breachName: string) => {
    setHighlightedBreachName(breachName);
    window.requestAnimationFrame(() => {
      document.getElementById(`breach-detail-${encodeURIComponent(breachName)}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  };

  // Flags come from the source-declared attribute payload; a source that does
  // not report a given flag simply shows no badge for it.
  const FLAG_BADGES: Array<{ key: string; label: string; tone: string }> = [
    { key: "is_verified", label: "Verified", tone: "bg-emerald-500/10 text-emerald-600" },
    { key: "is_spam_list", label: "Spam", tone: "bg-amber-500/10 text-amber-600" },
    { key: "is_malware", label: "Malware", tone: "bg-rose-500/10 text-rose-600" },
    { key: "is_fabricated", label: "Fake", tone: "bg-slate-500/10 text-slate-600" },
    { key: "is_sensitive", label: "Sensitive", tone: "bg-violet-500/10 text-violet-600" },
    { key: "is_retired", label: "Retired", tone: "bg-zinc-500/10 text-zinc-600" },
  ];

  const renderFlags = (b: Breach) => {
    const badges = FLAG_BADGES
      .filter((flag) => breachFlag(b, flag.key))
      .map((flag) => (
        <Badge key={flag.key} className={`${flag.tone} border-0 text-[10px]`}>{flag.label}</Badge>
      ));
    return badges.length ? <div className="flex flex-wrap gap-1">{badges}</div> : <span className="text-muted-foreground text-xs">—</span>;
  };

  const renderAttributes = (b: Breach) => {
    const entries = breachExtraAttributes(b);
    return entries.length ? (
      <div className="flex flex-wrap gap-1" title={entries.map((e) => `${e.label}: ${e.value}`).join("\n")}>
        {entries.map((entry) => (
          <Badge key={entry.key} variant="outline" className="text-[10px] font-normal">
            {entry.label}: {entry.value}
          </Badge>
        ))}
      </div>
    ) : (
      <span className="text-muted-foreground text-xs">—</span>
    );
  };

  const renderDataClasses = (b: Breach) => {
    const classes = Array.isArray(b.data_classes) ? b.data_classes : [];
    // The source's own name for a class it published, and the stored name when it
    // published none: the page never invents a vocabulary the source did not use.
    const labels = readiness?.data_class_labels;
    return classes.length ? (
      <div className="flex flex-wrap gap-1">
        {classes.map((d) => {
          const label = breachDataClassLabel(String(d), labels);
          return (
            <Badge
              key={String(d)}
              variant="secondary"
              className="text-[10px]"
              title={label === String(d) ? undefined : `${d} — as the reporting source names it`}
            >
              {label}
            </Badge>
          );
        })}
      </div>
    ) : (
      <span className="text-muted-foreground">—</span>
    );
  };

  // The account's own entitlements, in neutral words. A value the source did not
  // publish is shown as "not stated" rather than as a negative answer.
  const entitlementFacts: Array<{ label: string; value: string }> = (() => {
    const ent = readiness?.entitlements;
    if (!ent) return [];
    const facts: Array<{ label: string; value: string }> = [];
    if (ent.subscription) facts.push({ label: "Subscription", value: ent.subscription });
    if (typeof ent.requests_per_minute === "number") facts.push({ label: "Rate the source states", value: `${formatNumber(ent.requests_per_minute)} requests/minute` });
    if (typeof ent.domains_verified === "number") facts.push({ label: "Domains verified", value: formatNumber(ent.domains_verified) });
    if (ent.includes_stealer_logs != null) facts.push({ label: "Includes stealer logs", value: ent.includes_stealer_logs ? "Yes" : "No" });
    if (ent.includes_kanon != null) facts.push({ label: "Includes k-anonymity ranges", value: ent.includes_kanon ? "Yes" : "No" });
    return facts;
  })();

  const pacingFacts: Array<{ label: string; value: string }> = Object.entries(readiness?.pacing ?? {}).map(
    ([key, value]) => ({ label: humanizeKey(key), value: typeof value === "boolean" ? (value ? "Yes" : "No") : String(value) }),
  );

  const unannounced = data?.unannounced ?? 0;

  const columns: DataTableColumn<Breach>[] = [    {
      key: "matched_email",
      title: "Breached account",
      width: 260,
      minWidth: 200,
      render: (b) => (
        <div className="flex items-center gap-2 min-w-0">
          <Mail className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
          <span className="font-mono text-sm truncate">{b.matched_email || "—"}</span>
          {/* The same account in several incidents is one account to handle, not
              several: saying so here stops the row from being triaged as new (F-13). */}
          {b.matched_email && (b.email_incident_count ?? 0) > 1 ? (
            <Badge
              variant="outline"
              className="text-[10px] shrink-0 border-violet-500/30 text-violet-600 bg-violet-500/10"
              title={`This address already appears in ${b.email_incident_count} incidents held by the platform.`}
            >
              {b.email_incident_count} incidents
            </Badge>
          ) : null}
        </div>
      ),
    },
    {
      key: "matched_asset",
      title: "Matched asset",
      width: 280,
      minWidth: 220,
      render: (b) => {
        const matchedDomain = b.matched_asset_type === "domain";
        const matchedValue = b.matched_asset || b.matched_domain;
        const maskedPassword = breachAttribute(b, "masked_password");
        if (matchedValue) {
          return (
            <div className="flex items-center gap-2 min-w-0">
              {matchedDomain ? (
                <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              ) : (
                <Mail className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              )}
              <span className="font-mono text-sm truncate">{matchedValue}</span>
              <Badge variant="outline" className="text-[10px] shrink-0 capitalize">
                {matchedDomain ? "domain" : "email account"}
              </Badge>
              {maskedPassword ? (
                <Badge variant="outline" className="text-[10px] border-red-500/30 text-red-500 bg-red-500/10 shrink-0">
                  pw: {formatBreachAttributeValue(maskedPassword)}
                </Badge>
              ) : null}
            </div>
          );
        }
        return <span className="text-muted-foreground text-sm">—</span>;
      },
    },
    {
      key: "breach_name",
      title: "Breach Name",
      width: 220,
      minWidth: 180,
      render: (b) => (
        <button
          type="button"
          className="font-semibold text-sm text-left truncate max-w-full underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded"
          onClick={() => jumpToDetails(`${b.source_id ?? "unattributed"}:${b.breach_name}`)}
          aria-label={`Show details for ${b.breach_name}`}
        >
          {b.breach_name}
        </button>
      ),
    },
    {
      key: "breach_date",
      title: "Breach date",
      width: 190,
      minWidth: 150,
      render: (b) => (
        <div className="flex flex-wrap items-center gap-1.5 text-sm text-muted-foreground">
          <Calendar className="w-3.5 h-3.5 shrink-0" />
          {formatDate(b.breach_date)}
          {/* The source could not describe the incident, so the stored date is the
              day it was observed. Saying so is the difference between a fact and a
              date the platform made up (F-02). */}
          {b.metadata_incomplete ? (
            <Badge variant="outline" className="text-[10px] border-amber-500/30 text-amber-600 bg-amber-500/10 shrink-0" title="The source did not report when this incident happened; the date shown is when it was observed.">
              metadata incomplete
            </Badge>
          ) : null}
        </div>
      ),
    },
    {
      key: "exposure_kind",
      title: "Exposure",
      width: 150,
      minWidth: 130,
      // The class the row belongs to, so a list filtered to one class still says what
      // each row is: a breach of an account, a paste or a stealer log (WI-21).
      render: (b) => (
        <Badge variant="outline" className="text-[10px] whitespace-nowrap">
          {breachExposureKindLabel(breachExposureKind(b))}
        </Badge>
      ),
    },
    {
      key: "severity",
      title: "Severity",
      width: 140,
      minWidth: 120,
      // Derived by the core from the classes of data exposed, and stored on the row:
      // the badge, the filter and the sort all read that one value (F-13).
      render: (b) => (
        <Badge
          variant="outline"
          className={`${breachSeverityTone(breachSeverity(b))} text-[10px] whitespace-nowrap`}
          title="Derived from the classes of data this incident exposed, not from how many people it affected."
        >
          {breachSeverityLabel(breachSeverity(b))}
        </Badge>
      ),
    },
    {
      key: "status",
      title: "Status",
      width: 160,
      minWidth: 140,
      render: (b) => (
        canWrite ? (
          <Select value={b.status} onValueChange={(v: string) => updateStatusMut.mutate({ id: b.id, status: v as ThreatStatus })}>
            <SelectTrigger className="!h-7 text-xs w-36" aria-label={`Status for breach match ${b.breach_name}`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>{STATUSES.map(s => <SelectItem key={s} value={s} className="text-xs">{threatStatusLabel(s)}</SelectItem>)}</SelectContent>
          </Select>
        ) : (
          <Badge variant="outline" className={statusTone[b.status]}>
            <span>{threatStatusLabel(b.status)}</span>
          </Badge>
        )
      ),
    },
    {
      key: "actions",
      title: "Actions",
      width: 90,
      minWidth: 80,
      align: "right",
      render: (b) => (
        canWrite ? (
          <div className="inline-flex gap-1 justify-end">
            <Button
              size="icon"
              variant="ghost"
              onClick={() => promoteMut.mutate(b.id)}
              disabled={promoteMut.isPending}
              title="Take the affected account or domain under monitoring"
              aria-label="Monitor the value this breach names"
            >
              <PlusCircle className="w-4 h-4" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              className="text-destructive hover:text-destructive"
              onClick={() => { setDeletingBreach(b); setDeleteOpen(true); }}
              title="Delete breach match"
              aria-label="Delete breach match"
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        ) : null
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="min-w-0 flex-1 max-w-2xl">
          <h1 className="text-2xl font-bold">Breaches</h1>
          <p className="text-muted-foreground text-sm mt-1">Leaked-credential and account-compromise findings matched against your monitored mailboxes and domains.</p>
          <p className="text-xs text-muted-foreground mt-1">{TIME_ZONE_HINT}</p>
        </div>
        <div className="flex shrink-0 flex-nowrap gap-2 overflow-x-auto">
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          {isAdmin && (
            <Button variant="outline" onClick={() => setCleanOrphansOpen(true)}>
              <Eraser className="w-4 h-4 mr-2" />
              Clean orphans
            </Button>
          )}
          {canWrite && (
            <Button onClick={() => scanMut.mutate()} disabled={scanMut.isPending}>
              <Rocket className={`w-4 h-4 mr-2 ${scanMut.isPending ? "animate-pulse" : ""}`} />
              {scanMut.isPending ? "Starting..." : "Rescan"}
            </Button>
          )}
        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Filters</CardTitle>
          <CardDescription>
            Total records: <span className="font-semibold text-foreground">{formatNumber(data?.total ?? 0)}</span>
            {unannounced > 0 ? (
              <>
                {" · "}
                <span className="text-amber-600">
                  {formatNumber(unannounced)} finding{unannounced === 1 ? "" : "s"} not announced yet
                </span>
                {" — no alert channel has reported them, which is a configuration problem rather than a clean scan."}
              </>
            ) : null}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative max-w-xl">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input className="pl-9" placeholder="Search breach, email, domain..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button
              variant={newSinceLastScan ? "default" : "outline"}
              size="sm"
              aria-pressed={newSinceLastScan}
              onClick={() => { setNewSinceLastScan((v) => !v); setPage(1); }}
            >
              New since last scan
            </Button>
            <span className="text-xs text-muted-foreground">
              {newSinceLastScan
                ? data?.new_since
                  ? `Showing what arrived since the last finished scan (${formatDateTime(data.new_since)}).`
                  : "No breach scan has finished yet, so every finding is new."
                : "Filter to findings the most recent scan turned up."}
            </span>
            <Select
              value={exposureKind}
              onValueChange={(v: string) => { setExposureKind(v as BreachExposureKind | "all"); setPage(1); }}
            >
              <SelectTrigger className="!h-8 w-56 text-xs" aria-label="Class of exposure">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All classes of exposure</SelectItem>
                {BREACH_EXPOSURE_KINDS.map((kind) => (
                  <SelectItem key={kind} value={kind} className="text-xs">
                    {breachExposureKindLabel(kind)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={severity}
              onValueChange={(v: string) => { setSeverity(v as BreachSeverity | "all"); setPage(1); }}
            >
              <SelectTrigger className="!h-8 w-52 text-xs" aria-label="Severity">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All severities</SelectItem>
                {BREACH_SEVERITIES.map((level) => (
                  <SelectItem key={level} value={level} className="text-xs">
                    {breachSeverityLabel(level)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={statusFilter}
              onValueChange={(v: string) => { setStatusFilter(v as ThreatStatus | "all"); setPage(1); }}
            >
              <SelectTrigger className="!h-8 w-48 text-xs" aria-label="Triage status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All triage states</SelectItem>
                {STATUSES.map((state) => (
                  <SelectItem key={state} value={state} className="text-xs">
                    {threatStatusLabel(state)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={flag}
              onValueChange={(v: string) => { setFlag(v as BreachFlagFilter | "all"); setPage(1); }}
            >
              <SelectTrigger className="!h-8 w-52 text-xs" aria-label="Source flag">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">Any source flag</SelectItem>
                {BREACH_FLAG_FILTERS.map((option) => (
                  <SelectItem key={option.value} value={option.value} className="text-xs">
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input
              className="!h-8 w-56 text-xs"
              placeholder="Domain (e.g. acme.test)"
              aria-label="Domain"
              value={domainFilter}
              onChange={(e) => { setDomainFilter(e.target.value); setPage(1); }}
            />
            <Select
              value={sortValue}
              onValueChange={(v: string) => { setSortValue(v); setPage(1); }}
            >
              <SelectTrigger className="!h-8 w-56 text-xs" aria-label="Sort findings">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {BREACH_SORT_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value} className="text-xs">
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {readiness ? (
        <Card>
          <CardHeader className="pb-4">
            <CardTitle className="text-base">What the last scan was allowed to ask</CardTitle>
            <CardDescription>{breachReadinessVerdict(readiness)}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {readiness.scan_job_id ? (
                <>
                  <span>
                    Last finished scan: <span className="font-mono text-foreground">{readiness.scan_job_id.slice(0, 8)}</span>
                    {readiness.scanned_at ? ` at ${formatDateTime(readiness.scanned_at)}` : ""}
                  </span>
                  {readiness.status ? (
                    <Badge variant="outline" className={readiness.partial ? "border-amber-500/40 text-amber-600" : "border-emerald-500/40 text-emerald-600"}>
                      {readiness.partial ? `${readiness.status} — some questions were refused` : readiness.status}
                    </Badge>
                  ) : null}
                </>
              ) : (
                <span>No breach scan has finished yet.</span>
              )}
            </div>

            {readiness.domains.length ? (
              <div className="space-y-2">
                {readiness.domains.map((domain) => {
                  const attempt = breachVerificationFor(readiness, domain.domain);
                  const pendingHere =
                    verificationMut.isPending && verificationMut.variables?.domain === domain.domain;
                  return (
                    <div key={domain.domain} className="space-y-1 border-b border-border/40 pb-2 last:border-0 last:pb-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs">{domain.domain}</span>
                        <Badge
                          variant="outline"
                          className={
                            domain.status === "asked"
                              ? "border-emerald-500/40 text-emerald-600"
                              : domain.status === "unscanned"
                                ? "border-red-500/40 text-red-600"
                                : "border-amber-500/40 text-amber-600"
                          }
                        >
                          {breachReadinessStatusLabel(domain.status)}
                        </Badge>
                        {domain.reason ? (
                          <span className="text-xs text-muted-foreground">
                            <span className="font-mono">{domain.reason}</span>
                            {breachReadinessReasonLabel(domain.reason) ? ` — ${breachReadinessReasonLabel(domain.reason)}` : ""}
                          </span>
                        ) : null}
                      </div>
                      {attempt ? <VerificationAttempt attempt={attempt} /> : null}
                      {canWrite ? (
                        <div className="flex flex-wrap items-center gap-2">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 text-xs"
                            disabled={pendingHere}
                            onClick={() => verificationMut.mutate({ domain: domain.domain, action: "generate" })}
                          >
                            Get DNS record
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 text-xs"
                            disabled={pendingHere}
                            onClick={() => verificationMut.mutate({ domain: domain.domain, action: "verify" })}
                          >
                            Check DNS now
                          </Button>
                          {pendingHere ? (
                            <span className="text-xs text-muted-foreground">Asking the source…</span>
                          ) : null}
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}

            {unlistedVerifications.length ? (
              <div className="space-y-1">
                {unlistedVerifications.map((attempt) => (
                  <div key={attempt.domain} className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{attempt.domain}</span>
                    <VerificationAttempt attempt={attempt} />
                  </div>
                ))}
              </div>
            ) : null}

            {entitlementFacts.length || pacingFacts.length ? (
              <div className="flex flex-wrap gap-2">
                {[...entitlementFacts, ...pacingFacts].map((fact) => (
                  <Badge key={fact.label} variant="outline" className="text-[10px] font-normal">
                    {fact.label}: {fact.value}
                  </Badge>
                ))}
              </div>
            ) : null}

            {Object.keys(readiness.reasons).length ? (
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <span>What the scan could not do:</span>
                {Object.entries(readiness.reasons).map(([reason, count]) => (
                  <Badge key={reason} variant="outline" className="text-[10px] font-normal">
                    {reason}: {formatNumber(count)}
                  </Badge>
                ))}
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardContent className="p-4">
          <PaginatedDataTable
            columns={columns}
            rows={data?.items ?? []}
            total={data?.total ?? 0}
            page={page}
            pageSize={size}
            onPageChange={setPage}
            onPageSizeChange={(s) => { setSize(s); setPage(1); }}
            storageKey="breaches-table-widths-v2"
            ariaLabel="Leaked accounts"
            loading={isLoading || isPlaceholderData}
            isError={isError}
            errorDescription="The breach match list could not be loaded, so it is not known whether any credential is exposed. Retry before treating this as a clean result."
            onRetry={() => refetch()}
            emptyText={
              search ||
              exposureKind !== "all" ||
              severity !== "all" ||
              statusFilter !== "all" ||
              flag !== "all" ||
              debouncedDomain.trim()
                ? "No breach matches for the current filter."
                : "No leaked accounts found in the current data. Findings appear here after a breach scan completes."
            }
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Breach details</CardTitle>
          <CardDescription>
            Breach metadata reported by the configured source connectors, grouped by source and incident name; different providers remain separate.
            {detailsRows.length < (data?.items?.length ?? 0)
              ? ` Showing ${detailsRows.length} distinct breach(es) from the ${data?.items?.length ?? 0} matches on this page.`
              : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4">
          <PaginatedDataTable
            columns={[
              { key: "source_id", title: "Source", width: 130, render: (b: Breach) => <span>{b.source_id ?? "unattributed"}</span> },
              { key: "breach_name", title: "Breach Name", width: 220, minWidth: 180, render: (b: Breach) => <span className="font-semibold text-sm">{b.breach_name}</span> },
              { key: "breach_date", title: "Breach date", width: 150, minWidth: 130, render: (b: Breach) => <div className="flex items-center gap-1.5 text-sm text-muted-foreground"><Calendar className="w-3.5 h-3.5" />{formatDate(b.breach_date)}</div> },
              { key: "domain", title: "Domain", width: 180, minWidth: 140, render: (b: Breach) => <span className="font-mono text-sm truncate">{b.domain || "—"}</span> },
              { key: "flags", title: "Flags", width: 180, minWidth: 140, render: renderFlags },
              { key: "pwn_count", title: "Affected", width: 130, minWidth: 110, render: (b: Breach) => <div className="flex items-center gap-1.5 text-sm"><Hash className="w-3.5 h-3.5 text-muted-foreground" /><span className="font-semibold">{formatNumber(b.pwn_count)}</span></div> },
              { key: "data_classes", title: "Data classes", minWidth: 200, render: renderDataClasses },
              {
                key: "attributes",
                title: "Source attributes",
                minWidth: 220,
                render: renderAttributes,
              },
            ]}
            rows={detailsRows}
            total={detailsRows.length}
            page={1}
            pageSize={10000}
            onPageChange={() => undefined}
            onPageSizeChange={() => undefined}
            storageKey="breaches-details-widths-v1"
            ariaLabel="Breach details"
            loading={isLoading || isPlaceholderData}
            emptyText="No breach details available."
            getRowId={(b) => `breach-detail-${encodeURIComponent(`${b.source_id ?? "unattributed"}:${b.breach_name}`)}`}
            getRowClassName={(b) => highlightedBreachName === `${b.source_id ?? "unattributed"}:${b.breach_name}` ? "bg-primary/10 ring-2 ring-inset ring-primary/40" : undefined}
          />
        </CardContent>
      </Card>

      <JobsTable jobTypes={moduleJobTypes} />

      <ConfirmDialog
        open={cleanOrphansOpen}
        onOpenChange={setCleanOrphansOpen}
        variant="destructive"
        title="Clean orphan breach findings?"
        description="This permanently deletes breach findings that are not linked to any configured asset. Existing assets, including inactive assets, are preserved."
        confirmLabel="Clean entries"
        confirmLoading={cleanOrphansMut.isPending}
        onConfirm={() => cleanOrphansMut.mutate()}
        onCancel={() => setCleanOrphansOpen(false)}
      />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        variant="destructive"
        title="Delete breach match?"
        description={deletingBreach ? (
          <>You are about to permanently delete the breach match for <span className="font-semibold">{deletingBreach.title}</span> (<span className="font-mono">{deletingBreach.matched_domain || deletingBreach.matched_email}</span>). This action cannot be undone.</>
        ) : "This action cannot be undone."}
        confirmLabel="Delete breach"
        confirmLoading={deleteMut.isPending}
        onConfirm={() => {
          if (deletingBreach) deleteMut.mutate(deletingBreach.id);
          setDeleteOpen(false);
          setDeletingBreach(null);
        }}
        onCancel={() => setDeletingBreach(null)}
      />
    </div>
  );
}
