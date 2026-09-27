import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, RefreshCw, Rocket, Globe, Calendar, Hash, Trash2, Mail, Eraser } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import { formatNumber } from "@/lib/utils";
import { threatStatusLabel } from "@/lib/labels";
import {
  breachAttribute,
  breachExtraAttributes,
  breachFlag,
  formatBreachAttributeValue,
} from "@/lib/breach";
import { useModuleJobTypes } from "@/hooks/useModuleJobTypes";
import { TIME_ZONE_HINT, formatDate } from "@/lib/datetime";
import type { Breach, ThreatStatus } from "@/types/api";
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

export default function BreachesPage() {
  const canWrite = useIsAnalystPlus();
  const isAdmin = useIsAdmin();
  const qc = useQueryClient();
  // Declared by the registered breach connectors, not by this page.
  const moduleJobTypes = useModuleJobTypes("breaches");

  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingBreach, setDeletingBreach] = useState<Breach | null>(null);
  const [cleanOrphansOpen, setCleanOrphansOpen] = useState(false);
  const [highlightedBreachName, setHighlightedBreachName] = useState<string | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["breaches", page, size, debouncedSearch],
    queryFn: () => endpoints.listBreaches({ page, size, search: debouncedSearch || undefined }),
    staleTime: 30_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
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

  const deleteMut = useMutation({
    mutationFn: (id: string) => endpoints.deleteBreach(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["breaches"] }); toast({ title: "Breach match deleted" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Delete failed", description: describeApiError(e) }),
  });

  const detailsRows = useMemo(() => {
    const grouped = new Map<string, Breach>();
    for (const breach of data?.items ?? []) {
      if (!grouped.has(breach.breach_name)) grouped.set(breach.breach_name, breach);
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
    return classes.length ? <div className="flex flex-wrap gap-1">{classes.map(d => <Badge key={d} variant="secondary" className="text-[10px]">{d}</Badge>)}</div> : <span className="text-muted-foreground">—</span>;
  };

  const columns: DataTableColumn<Breach>[] = [    {
      key: "matched_email",
      title: "Breached account",
      width: 260,
      minWidth: 200,
      render: (b) => (
        <div className="flex items-center gap-2 min-w-0">
          <Mail className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
          <span className="font-mono text-sm truncate">{b.matched_email || "—"}</span>
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
          onClick={() => jumpToDetails(b.breach_name)}
          aria-label={`Show details for ${b.breach_name}`}
        >
          {b.breach_name}
        </button>
      ),
    },
    {
      key: "breach_date",
      title: "Breach date",
      width: 150,
      minWidth: 130,
      render: (b) => (
        <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <Calendar className="w-3.5 h-3.5 shrink-0" />
          {formatDate(b.breach_date)}
        </div>
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
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Breaches</h1>
          <p className="text-muted-foreground text-sm mt-1">Leaked-credential and account-compromise findings matched against your monitored mailboxes and domains.</p>
          <p className="text-xs text-muted-foreground mt-1">{TIME_ZONE_HINT}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          {isAdmin && (
            <Button variant="outline" onClick={() => setCleanOrphansOpen(true)}>
              <Eraser className="w-4 h-4 mr-2" />
              Clean orphan entries
            </Button>
          )}
          {canWrite && (
            <Button variant="outline" onClick={() => scanMut.mutate()} disabled={scanMut.isPending}>
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
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative max-w-xl">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input className="pl-9" placeholder="Search breach, email, domain..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
          </div>
        </CardContent>
      </Card>

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
            loading={isLoading}
            isError={isError}
            errorDescription="The breach match list could not be loaded, so it is not known whether any credential is exposed. Retry before treating this as a clean result."
            onRetry={() => refetch()}
            emptyText={search ? "No breach matches for this search." : "No leaked accounts found in the current data. Findings appear here after a breach scan completes."}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Breach details</CardTitle>
          <CardDescription>
            Breach metadata reported by the configured source connectors, grouped by breach name.
            {detailsRows.length < (data?.items?.length ?? 0)
              ? ` Showing ${detailsRows.length} distinct breach(es) from the ${data?.items?.length ?? 0} matches on this page.`
              : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4">
          <PaginatedDataTable
            columns={[
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
            loading={isLoading}
            emptyText="No breach details available."
            getRowId={(b) => `breach-detail-${encodeURIComponent(b.breach_name)}`}
            getRowClassName={(b) => highlightedBreachName === b.breach_name ? "bg-primary/10 ring-2 ring-inset ring-primary/40" : undefined}
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
