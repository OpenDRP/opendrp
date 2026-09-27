import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, Search, Trash2 } from "lucide-react";
import { api, describeApiError, endpoints } from "@/lib/api";
import { humanizeSummary, jobStatusLabel, jobTypeLabel } from "@/lib/labels";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import { useIsAdmin } from "@/store/auth";
import type { Job, JobStatus } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { toast } from "@/components/ui/use-toast";

const statusTone: Record<JobStatus, string> = {
  pending: "bg-slate-500/15 text-slate-600 dark:text-slate-300 border-slate-500/30",
  running: "bg-blue-500/15 text-blue-600 dark:text-blue-300 border-blue-500/30",
  success: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border-emerald-500/30",
  partial: "bg-amber-500/15 text-amber-600 dark:text-amber-300 border-amber-500/30",
  error: "bg-red-500/15 text-red-600 dark:text-red-300 border-red-500/30",
  cancelled: "bg-amber-500/15 text-amber-600 dark:text-amber-300 border-amber-500/30",
  skipped: "bg-gray-500/15 text-gray-600 dark:text-gray-300 border-gray-500/30",
};
function shortId(id: string) { return id ? id.slice(0, 8) : "—"; }
interface JobsTableProps { jobTypes?: string[]; }

export function JobsTable({ jobTypes }: JobsTableProps) {
  const isAdmin = useIsAdmin();
  const qc = useQueryClient();
  const [page, setPage] = useState(1), [size, setSize] = useState(10), [search, setSearch] = useState("");
  const [deletingJob, setDeletingJob] = useState<Job | null>(null);
  const jobTypeFilter = jobTypes && jobTypes.length > 0 ? jobTypes.join(",") : undefined;
  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["jobs", page, size, search, jobTypeFilter],
    queryFn: () => endpoints.listJobs({ page, size, search: search || undefined, job_type_in: jobTypeFilter }),
    staleTime: 10_000, refetchInterval: 10_000,
    placeholderData: { items: [], total: 0, page: 1, size: 10, pages: 0 },
  });
  const deleteMut = useMutation({
    mutationFn: (id: string) => api.delete(`/jobs/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["jobs"] }); setDeletingJob(null); toast({ title: "Job deleted" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to delete job", description: describeApiError(e) }),
  });
  const columns: DataTableColumn<Job>[] = [
    { key: "id", title: "Job ID", width: 110, minWidth: 90, render: (row) => <TooltipProvider delayDuration={100}><Tooltip><TooltipTrigger asChild><span className="font-mono text-xs cursor-help">{shortId(row.id)}</span></TooltipTrigger><TooltipContent side="top" align="start"><div className="font-mono text-xs break-all max-w-[420px]">{row.id}</div>{row.task_id && <div className="text-xs text-muted-foreground mt-1 break-all">task: {row.task_id}</div>}</TooltipContent></Tooltip></TooltipProvider> },
    { key: "job_type", title: "Type", width: 180, minWidth: 140, render: (row) => <div className="flex flex-col"><span className="font-medium">{jobTypeLabel(row.job_type)}</span>{row.title && <span className="text-xs text-muted-foreground truncate max-w-[240px]">{row.title}</span>}</div> },
    { key: "created_by_email", title: "Started by", width: 180, minWidth: 140, render: (row) => row.created_by_email || (!row.created_by ? <span className="text-xs font-semibold tracking-wide text-muted-foreground">SYSTEM</span> : "—") },
    { key: "status", title: "Status", width: 110, minWidth: 100, render: (row) => <Badge className={statusTone[row.status] || statusTone.pending} variant="outline">{jobStatusLabel(row.status)}</Badge> },
    { key: "created_at", title: "Created", width: 160, minWidth: 140, render: (row) => formatDateTime(row.created_at) },
    { key: "started_at", title: "Started", width: 160, minWidth: 140, render: (row) => formatDateTime(row.started_at) },
    { key: "finished_at", title: "Finished", width: 160, minWidth: 140, render: (row) => formatDateTime(row.finished_at) },
    { key: "error_message", title: "Details", width: 220, minWidth: 140, render: (row) => { const error = row.error_message; const result = humanizeSummary(row.result_summary); if (!error && !result) return "—"; return <TooltipProvider delayDuration={100}><Tooltip><TooltipTrigger asChild><span className={"text-xs truncate block max-w-[200px] cursor-help " + (error ? "text-red-600 dark:text-red-400" : "text-muted-foreground")}>{error ? error.slice(0, 80) + (error.length > 80 ? "…" : "") : result.slice(0, 80) + (result.length > 80 ? "…" : "")}</span></TooltipTrigger><TooltipContent side="top" align="start" className="max-w-[520px]">{error && <div className="text-xs text-red-600 dark:text-red-400 whitespace-pre-wrap break-words">{error}</div>}{result && <div className={"text-xs whitespace-pre-wrap break-words mt-1 " + (error ? "text-muted-foreground" : "")}>{result}</div>}</TooltipContent></Tooltip></TooltipProvider>; } },
    ...(isAdmin ? [{ key: "actions", title: "Action", width: 80, minWidth: 70, align: "right" as const, render: (row: Job) => <Button size="icon" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => setDeletingJob(row)} title="Delete job" aria-label="Delete job"><Trash2 className="w-4 h-4" /></Button> }] : []),
  ];
  return <Card><CardHeader><div className="flex items-center justify-between gap-4 flex-wrap"><div><CardTitle className="text-lg">Jobs history</CardTitle><CardDescription>Status of background scans and tasks, including tasks started by the platform itself. Updates automatically. {TIME_ZONE_HINT}.{isAdmin ? "" : " You see your own tasks and system tasks."}</CardDescription></div><div className="flex items-center gap-2"><div className="relative w-60"><Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" /><Input placeholder="Search jobs…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} className="pl-8" /></div><Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}><RefreshCw className={"h-4 w-4 mr-2 " + (isFetching ? "animate-spin" : "")} />Refresh</Button></div></div></CardHeader><CardContent><PaginatedDataTable storageKey="jobs-table-cols-v1" columns={columns} rows={data?.items || []} total={data?.total || 0} page={data?.page || page} pageSize={data?.size || size} onPageChange={setPage} onPageSizeChange={(s) => { setSize(s); setPage(1); }} loading={isLoading} isRefreshing={isFetching} isError={isError} errorDescription="The job history could not be loaded, so recent scan activity is not shown." onRetry={() => refetch()} emptyText="No jobs to show for this scope yet. Run a scan or generate a report to see entries here." /></CardContent><ConfirmDialog open={!!deletingJob} onOpenChange={(open) => { if (!open && !deleteMut.isPending) setDeletingJob(null); }} variant="destructive" title="Delete job?" description={deletingJob ? <>This permanently deletes job <span className="font-mono font-semibold">{shortId(deletingJob.id)}</span> and its history.</> : undefined} confirmLabel="Delete job" confirmLoading={deleteMut.isPending} onConfirm={() => { if (deletingJob) deleteMut.mutate(deletingJob.id); }} onCancel={() => setDeletingJob(null)} /></Card>;
}
