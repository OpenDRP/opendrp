import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, FileBarChart, Play, Download, Trash2, Clock, CheckCircle, XCircle, Loader2, Info } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useAuthStore, useIsAdmin, useIsAuthenticated } from "@/store/auth";
import { formatNumber } from "@/lib/utils";
import { useModuleJobTypes } from "@/hooks/useModuleJobTypes";
import { JobsTable } from "@/components/JobsTable";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import type { Paginated, Report, ReportStatus } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { toast } from "@/components/ui/use-toast";

const statusIcon: Record<ReportStatus, any> = {
  pending: Clock,
  generating: Loader2,
  completed: CheckCircle,
  failed: XCircle,
};

const statusTone: Record<ReportStatus, string> = {
  pending: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  generating: "bg-blue-500/15 text-blue-500 border-blue-500/30",
  completed: "bg-green-500/15 text-green-500 border-green-500/30",
  failed: "bg-red-500/15 text-red-500 border-red-500/30",
};

export default function ReportsPage() {
  // Report generation is open to every signed-in role (viewer included);
  // destructive actions stay admin-only, matching the API.
  const canGenerate = useIsAuthenticated();
  const isAdmin = useIsAdmin();
  const qc = useQueryClient();
  const { token } = useAuthStore();
  // Core-owned job type; the registry contributes nothing for this module, so
  // the built-in default is what the history shows.
  const moduleJobTypes = useModuleJobTypes("reports");

  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingReport, setDeletingReport] = useState<Report | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery<Paginated<Report>>({
    queryKey: ["reports", page, size],
    queryFn: () => endpoints.listReports({ page, size }),
    staleTime: 10_000,
    placeholderData: { items: [], total: 0, page: 1, size: 50, pages: 0 },
    refetchInterval: (q) => {
      const state = q.state.data;
      return state && state.items.some((r) => r.status === "generating" || r.status === "pending") ? 3000 : false;
    },
  });

  const genMut = useMutation({
    mutationFn: () => endpoints.generateReport(),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["reports"] });
      toast({ title: "Report generation started", description: `ETA ~${r.estimated_seconds}s · ID ${r.report_id.slice(0, 8)}` });
    },
    onError: (e: any) => {
      toast({
        variant: "destructive",
        title: e?.response?.status === 429 ? "Rate limit reached" : "Failed to start report",
        description: describeApiError(e),
      });
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => endpoints.deleteReport(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["reports"] }); toast({ title: "Report deleted" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Delete failed", description: describeApiError(e) }),
  });

  async function downloadReport(id: string, reportName?: string) {
    setDownloadingId(id);
    try {
      const blob = await endpoints.downloadReportBlob(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      // Prefer the operator-facing report name; fall back to the id suffix.
      const safeName = (reportName || `opendrp-report-${id.slice(0, 8)}`)
        .replace(/[^\w.-]+/g, "_")
        .replace(/_+/g, "_");
      a.download = safeName.toLowerCase().endsWith(".pdf") ? safeName : `${safeName}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast({ title: "Download started" });
    } catch (e: any) {
      toast({
        variant: "destructive",
        title: "Download failed",
        description: describeApiError(e),
      });
    } finally {
      setDownloadingId(null);
    }
  }

  const columns: DataTableColumn<Report>[] = [
    {
      key: "report_name",
      title: "Name",
      width: 320,
      minWidth: 220,
      render: (r) => (
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <FileBarChart className="w-4 h-4 text-primary" />
          </div>
          <div>
            <div className="font-medium text-sm">{r.report_name}</div>
            <div className="text-[11px] text-muted-foreground font-mono">{r.id.slice(0, 12)}…</div>
            {r.is_truncated && (
              <div className="mt-1 inline-flex items-center gap-1 text-[11px] text-amber-600 dark:text-amber-400" title={`Report sections are limited to ${r.truncation_metadata?.limit ?? "the configured row limit"} rows`}>
                <Info className="h-3 w-3" aria-hidden="true" />
                <span>Truncated</span>
              </div>
            )}
          </div>
        </div>
      ),
    },
    {
      key: "created_by",
      title: "Created by",
      width: 200,
      minWidth: 160,
      render: (r) => r.created_by_email ? (
        <span className="text-sm text-muted-foreground">{r.created_by_email}</span>
      ) : (
        <span className="text-xs font-semibold tracking-wide text-muted-foreground">SYSTEM</span>
      ),
    },
    {
      key: "created_at",
      title: "Created",
      width: 180,
      minWidth: 160,
      render: (r) => <span className="text-sm text-muted-foreground">{formatDateTime(r.created_at)}</span>,
    },
    {
      key: "status",
      title: "Status",
      width: 160,
      minWidth: 130,
      render: (r) => {
        const Icon = statusIcon[r.status];
        return (
          <div className="flex flex-col items-start gap-1">
          <Badge variant="outline" className={statusTone[r.status]}>
            <Icon className={`w-3 h-3 mr-1 ${r.status === "generating" ? "animate-spin" : ""}`} />
            <span className="capitalize">{r.status}</span>
          </Badge>
          {r.is_truncated && <span className="text-[11px] text-amber-600 dark:text-amber-400">Limited rows</span>}
          </div>
        );
      },
    },
    {
      key: "actions",
      title: "Actions",
      width: 200,
      minWidth: 170,
      align: "right",
      render: (r) => {
        // A completed row whose artifact vanished from the store cannot be
        // downloaded; offer the reason instead of a guaranteed 404.
        const fileMissing = r.status === "completed" && r.file_available === false;
        return (
        <div className="inline-flex gap-1 justify-end">
          <Button
            size="sm"
            variant="outline"
            disabled={r.status !== "completed" || fileMissing || downloadingId === r.id}
            onClick={() => downloadReport(r.id, r.report_name)}
            aria-label={`Download report ${r.report_name}`}
            title={fileMissing ? "Report file is no longer available on the server — regenerate the report" : undefined}
          >
            {downloadingId === r.id ? (
              <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
            ) : (
              <Download className="w-3.5 h-3.5 mr-1.5" />
            )}
            {downloadingId === r.id ? "Downloading..." : fileMissing ? "File missing" : "Download"}
          </Button>
          {isAdmin && (
            <Button
              size="icon"
              variant="ghost"
              className="text-destructive hover:text-destructive"
              onClick={() => { setDeletingReport(r); setDeleteOpen(true); }}
              title="Delete report"
              aria-label="Delete report"
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          )}
        </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Reports</h1>
          <p className="text-muted-foreground text-sm mt-1">PDF reports summarising assets, threats and exposure over time.</p>
          <p className="text-xs text-muted-foreground mt-1">{TIME_ZONE_HINT}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          {canGenerate && (
            <Button onClick={() => genMut.mutate()} disabled={genMut.isPending}>
              <Play className="w-4 h-4 mr-2" />
              {genMut.isPending ? "Starting..." : "Generate report"}
            </Button>
          )}
        </div>
      </div>

      <div className="space-y-2">
        <p className="text-xs text-muted-foreground">
          Counts cover the reports listed on this page only. Total reports:{" "}
          <span className="font-medium text-foreground">{formatNumber(data?.total ?? 0)}</span>.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
        {(["completed", "generating", "pending", "failed"] as ReportStatus[]).map((st) => {
          const count = (data?.items ?? []).filter(r => r.status === st).length;
          const Icon = statusIcon[st];
          // Only spin the "generating" icon while reports are actually generating.
          const spinning = st === "generating" && count > 0;
          return (
            <Card key={st}>
              <CardContent className="p-5">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${statusTone[st]}`}>
                    <Icon className={`w-5 h-5 ${spinning ? "animate-spin" : ""}`} />
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground capitalize">{st} on this page</div>
                    <div className="text-2xl font-bold tracking-tight">{count}</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Report history</CardTitle>
          <CardDescription className="flex items-center gap-1 text-amber-600 dark:text-amber-400">
            <Info className="h-3 w-3" aria-hidden="true" />
            A “Truncated” report contains at most the configured REPORT_MAX_ROWS per section; totals remain complete.
          </CardDescription>
          <CardDescription>
            Total: <span className="font-semibold text-foreground">{formatNumber(data?.total ?? 0)}</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="p-4">
          <PaginatedDataTable
            columns={columns}
            rows={data?.items ?? []}
            total={data?.total ?? 0}
            page={page}
            pageSize={size}
            onPageChange={setPage}
            onPageSizeChange={(s) => { setSize(s); setPage(1); }}
            storageKey="reports-table-widths-v1"
            loading={isLoading}
            isError={isError}
            errorDescription="The report list could not be loaded, so previously generated reports may exist without being shown here."
            onRetry={() => refetch()}
            emptyText={
              canGenerate
                ? "No reports yet. Generate your first PDF report to get a consolidated view."
                : "No reports yet."
            }
          />
        </CardContent>
      </Card>

      <JobsTable jobTypes={moduleJobTypes} />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        variant="destructive"
        title="Delete report?"
        description={deletingReport ? (
          <>You are about to permanently delete report <span className="font-semibold">{deletingReport.report_name}</span>. This action cannot be undone.</>
        ) : "This action cannot be undone."}
        confirmLabel="Delete report"
        confirmLoading={deleteMut.isPending}
        onConfirm={() => {
          if (deletingReport) deleteMut.mutate(deletingReport.id);
          setDeleteOpen(false);
          setDeletingReport(null);
        }}
        onCancel={() => setDeletingReport(null)}
      />
    </div>
  );
}
