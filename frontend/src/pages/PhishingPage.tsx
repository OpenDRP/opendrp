import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, RefreshCw, Copy, Rocket, ExternalLink, Trash2, Eraser } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import { formatNumber, copyToClipboard } from "@/lib/utils";
import { detectionSourceLabel, threatStatusLabel } from "@/lib/labels";
import { useModuleJobTypes } from "@/hooks/useModuleJobTypes";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import type { PhishingThreat, DetectionSource, ThreatStatus } from "@/types/api";
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

const SOURCES: DetectionSource[] = ["dnstwist", "shodan_ssl", "shodan_title", "shodan_favicon"];
const STATUSES: ThreatStatus[] = ["active", "investigating", "resolved"];

/** Human-readable label for the detection source of a finding. */
function sourceLabel(source: DetectionSource | string): string {
  return detectionSourceLabel(source);
}

const statusTone: Record<ThreatStatus, string> = {
  active: "bg-red-500/15 text-red-500 border-red-500/30",
  investigating: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  resolved: "bg-green-500/15 text-green-500 border-green-500/30",
};

export default function PhishingPage() {
  const canWrite = useIsAnalystPlus();
  const isAdmin = useIsAdmin();
  const qc = useQueryClient();
  // Job history covers every job type the registered phishing connectors
  // declare, so a connector added later appears without a frontend change.
  const moduleJobTypes = useModuleJobTypes("phishing");

  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [sourceFilter, setSourceFilter] = useState<DetectionSource | undefined>();
  const [statusFilter, setStatusFilter] = useState<ThreatStatus | undefined>();

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingThreat, setDeletingThreat] = useState<PhishingThreat | null>(null);
  const [cleanOrphansOpen, setCleanOrphansOpen] = useState(false);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["phishing", page, size, debouncedSearch, sourceFilter, statusFilter],
    queryFn: () => endpoints.listPhishing({
      page, size, detection_source: sourceFilter, status: statusFilter, search: debouncedSearch || undefined,
    }),
    staleTime: 15_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
  });

  const updateStatusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: ThreatStatus }) => endpoints.updatePhishingThreat(id, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["phishing"] }); toast({ title: "Threat updated" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Update failed", description: describeApiError(e) }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => endpoints.deletePhishingThreat(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["phishing"] }); toast({ title: "Threat deleted" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Delete failed", description: describeApiError(e) }),
  });

  const cleanOrphansMut = useMutation({
    mutationFn: () => endpoints.cleanOrphanPhishing(),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["phishing"] });
      setCleanOrphansOpen(false);
      toast({
        title: "Orphan phishing entries cleaned",
        description: `${result.deleted ?? 0} entr${result.deleted === 1 ? "y" : "ies"} deleted.`,
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to clean orphan findings", description: describeApiError(e) }),
  });

  const scanMut = useMutation({
    // One request per registered phishing connector; the core stays agnostic
    // about which connectors exist, so wording stays source-independent.
    mutationFn: async () => {
      const started = await Promise.allSettled([endpoints.scanDnstwist(), endpoints.scanShodan()]);
      const jobIds = started.flatMap((result) => result.status === "fulfilled" ? (result.value.job_ids ?? []) : []);
      const jobs = jobIds.length ? await waitForScanJobs(jobIds) : [];
      return { started, jobs };
    },
    onSuccess: ({ started, jobs }) => {
      qc.invalidateQueries({ queryKey: ["phishing"] });
      const results = started;
      const succeeded = results.filter((r) => r.status === "fulfilled" && r.value?.status === "scheduled").length;
      const reasons = results
        .filter((r): r is PromiseRejectedResult => r.status === "rejected")
        // Surface the API reason (rate limit, no connector registered, …)
        // instead of a generic failure so the operator knows what to do.
        .map((r) => describeApiError(r.reason))
        .concat(results
          .filter((r): r is PromiseFulfilledResult<any> => r.status === "fulfilled" && r.value?.status !== "scheduled")
          .map((r) => r.value?.error || "No connector is enabled for this scan."))
        .filter(Boolean);
      const jobSummary = summarizeScanJobs(jobs);
      if (succeeded && !reasons.length && (jobSummary.pending > 0 || jobs.length === 0)) {
        toast({ title: "Rescan started", description: "Phishing source scans queued. Progress is in Jobs history below." });
      } else if (succeeded && reasons.length && jobSummary.pending === 0) {
        toast({
          variant: "destructive",
          title: "Rescan partially started",
          description: `${reasons.join(" | ")} See Jobs history for the source that was queued.`,
        });
      } else if (succeeded && !reasons.length && jobSummary.failed === 0) {
        toast({ title: "Rescan completed", description: `Scan finished. ${jobSummary.succeeded} source job(s) completed.` });
      } else if (succeeded && jobSummary.pending === 0) {
        toast({
          variant: "destructive",
          title: "Rescan partially started",
          description: `${jobSummary.failed} source job(s) failed. ${reasons.join(" | ") || "See Jobs history for details."}`,
        });
      } else {
        toast({
          variant: "destructive",
          title: "Rescan failed",
          description: reasons.join(" | ") || "No source scan could be started.",
        });
      }
      qc.invalidateQueries({ queryKey: ["jobs"] });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Rescan failed", description: describeApiError(e) }),
  });

  const columns: DataTableColumn<PhishingThreat>[] = [
    {
      key: "phishing_domain",
      title: "Domain",
      width: 260,
      minWidth: 200,
      render: (t) => (
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-sm truncate">{t.phishing_domain}</span>
          <Button size="icon" variant="ghost" className="!h-6 !w-6 shrink-0" onClick={() => { copyToClipboard(`http://${t.phishing_domain}`); toast({ title: "URL copied" }); }} aria-label="Copy phishing URL" title="Copy URL">
            <Copy className="w-3 h-3" />
          </Button>
          <a href={`http://${t.phishing_domain}`} target="_blank" rel="noreferrer" className="text-muted-foreground hover:text-foreground shrink-0" aria-label="Open URL in new tab" title="Open URL">
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>
      ),
    },
    {
      key: "matched_asset",
      title: "Matched asset",
      width: 300,
      minWidth: 240,
      render: (t) => (
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-xs text-muted-foreground truncate">{t.matched_asset}</span>
          <Badge
            variant="outline"
            className="shrink-0 bg-sidebar-primary/10 border-sidebar-primary/30 text-sidebar-primary"
            title={`Detected via ${sourceLabel(t.detection_source)}`}
          >
            {sourceLabel(t.detection_source)}
          </Badge>
        </div>
      ),
    },
    {
      key: "ip_address",
      title: "IP / Ports",
      width: 160,
      minWidth: 140,
      render: (t) => (
        <div className="text-xs">
          <div className="font-mono">{t.ip_address || "—"}</div>
          {t.web_ports && <div className="text-muted-foreground mt-0.5">ports: {t.web_ports}</div>}
        </div>
      ),
    },
    {
      key: "created_at",
      title: "Created",
      width: 150,
      minWidth: 130,
      render: (t) => <span className="text-muted-foreground text-sm">{formatDateTime(t.created_at)}</span>,
    },
    {
      key: "status",
      title: "Status",
      width: 160,
      minWidth: 140,
      render: (t) => (
        canWrite ? (
          <Select value={t.status} onValueChange={(v: string) => updateStatusMut.mutate({ id: t.id, status: v as ThreatStatus })}>
            <SelectTrigger className="!h-7 text-xs w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>{STATUSES.map(s => <SelectItem key={s} value={s} className="text-xs">{threatStatusLabel(s)}</SelectItem>)}</SelectContent>
          </Select>
        ) : (
          <Badge variant="outline" className={statusTone[t.status]}>
            <span>{threatStatusLabel(t.status)}</span>
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
      render: (t) => (
        <div className="inline-flex gap-1 justify-end">
          {canWrite && (
            <Button
              size="icon"
              variant="ghost"
              className="text-destructive hover:text-destructive"
              onClick={() => { setDeletingThreat(t); setDeleteOpen(true); }}
              title="Delete threat"
              aria-label="Delete threat"
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Phishing Threats</h1>
          <p className="text-muted-foreground text-sm mt-1">Look-alike domains, certificate abuse and impersonation sites matched against your monitored assets.</p>
          <p className="text-xs text-muted-foreground mt-1">{TIME_ZONE_HINT}</p>
        </div>
        <div className="flex flex-wrap gap-2">
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
            Total threats: <span className="font-semibold text-foreground">{formatNumber(data?.total ?? 0)}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input className="pl-9" placeholder="Search domain / IP..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
            </div>
            <Select value={sourceFilter || "all"} onValueChange={(v: string) => { setSourceFilter(v === "all" ? undefined : (v as DetectionSource)); setPage(1); }}>
              <SelectTrigger aria-label="Filter by detection source"><SelectValue placeholder="Source" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All sources</SelectItem>
                {SOURCES.map(s => <SelectItem key={s} value={s}>{sourceLabel(s)}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={statusFilter || "all"} onValueChange={(v: string) => { setStatusFilter(v === "all" ? undefined : (v as ThreatStatus)); setPage(1); }}>
              <SelectTrigger aria-label="Filter by status"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                {STATUSES.map(s => <SelectItem key={s} value={s}>{threatStatusLabel(s)}</SelectItem>)}
              </SelectContent>
            </Select>
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
            storageKey="phishing-table-widths-v1"
            loading={isLoading}
            isError={isError}
            errorDescription="The threat list could not be loaded, so this is not evidence that no phishing infrastructure exists. Retry before drawing a conclusion."
            onRetry={() => refetch()}
            emptyText={search || sourceFilter || statusFilter ? "No threats match the current filters." : "No phishing findings yet. Run a rescan to look for look-alike domains."}
          />
        </CardContent>
      </Card>

      <JobsTable jobTypes={moduleJobTypes} />

      <ConfirmDialog
        open={cleanOrphansOpen}
        onOpenChange={setCleanOrphansOpen}
        variant="destructive"
        title="Clean orphan phishing findings?"
        description="This permanently deletes phishing findings that are not linked to any configured asset. Existing assets, including inactive assets, are preserved."
        confirmLabel="Clean entries"
        confirmLoading={cleanOrphansMut.isPending}
        onConfirm={() => cleanOrphansMut.mutate()}
        onCancel={() => setCleanOrphansOpen(false)}
      />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        variant="destructive"
        title="Delete threat?"
        description={deletingThreat ? (
          <>You are about to permanently delete phishing threat <span className="font-mono font-semibold">{deletingThreat.phishing_domain}</span>. This action cannot be undone.</>
        ) : "This action cannot be undone."}
        confirmLabel="Delete threat"
        confirmLoading={deleteMut.isPending}
        onConfirm={() => {
          if (deletingThreat) deleteMut.mutate(deletingThreat.id);
          setDeleteOpen(false);
          setDeletingThreat(null);
        }}
        onCancel={() => setDeletingThreat(null)}
      />

    </div>
  );
}
