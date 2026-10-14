import { useState } from "react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/use-toast";
import { describeApiError, endpoints } from "@/lib/api";
import { PROMOTED_ASSET_CRITICALITY, promotedAssetType } from "@/lib/assetValidation";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import { useIsAnalystPlus } from "@/store/auth";

type Observation = {
  id: string; subject: string; matched_asset: string; source: string; status: string;
  observed_at: string | null; first_seen_at: string; last_seen_at: string;
  payload: { port?: number; transport?: string; protocol?: string; metadata?: Record<string, unknown> };
};

type ScanSource = { connector?: unknown; status?: unknown; reason?: unknown };

// The exposure module ships exactly two providers (``exposure-netlas`` and
// ``exposure-shodan-endpoints``) and the API accepts any source string, so the
// filter is the list of live connectors — not of whatever observations happen
// to be stored. Withdrawn providers must not keep offering a filter here.
const EXPOSURE_SOURCES = ["netlas", "shodan"] as const;
type ScanResult = { status?: unknown; job_ids?: unknown; sources?: unknown };

function describeExposureScanError(error: unknown): string {
  const response = error as {
    response?: { data?: { detail?: unknown } };
  } | null;
  const detail = response?.response?.data?.detail;
  if (!detail || typeof detail !== "object" || Array.isArray(detail)) {
    return describeApiError(error);
  }

  const result = detail as ScanResult;
  if (!Array.isArray(result.sources)) return describeApiError(error);
  const sources = result.sources
    .filter((source): source is ScanSource => Boolean(source) && typeof source === "object")
    .map(source => {
      const connector = typeof source.connector === "string" ? source.connector : "Source";
      const status = typeof source.status === "string" ? source.status.replaceAll("_", " ") : "blocked";
      const reason = typeof source.reason === "string" ? source.reason : "";
      return `${connector}: ${status}${reason ? ` (${reason})` : ""}`;
    });
  if (sources.length === 0) return describeApiError(error);

  const jobIds = Array.isArray(result.job_ids) ? result.job_ids : [];
  const prefix = jobIds.length > 0 ? "Some sources were blocked" : "No scans started";
  return `${prefix}: ${sources.join("; ")}`;
}

export default function ExposurePage() {
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [source, setSource] = useState("");
  // WI-14: a promoted exposure observation becomes a monitored asset, so the
  // confirmation names the type and criticality it will get — and, unlike DNS
  // observations, warns that provider-observed shared hosting does not by itself
  // establish ownership.
  const [promoting, setPromoting] = useState<Observation | null>(null);
  const canScan = useIsAnalystPlus();
  const qc = useQueryClient();
  const { toast } = useToast();
  const query = useQuery({ queryKey: ["exposure", page, size, source], queryFn: () => endpoints.listExposure({ page, size, ...(source ? { source } : {}) }), refetchInterval: 30_000 });
  const triage = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "observed" | "investigating" | "resolved" }) => endpoints.updateExposure(id, status),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["exposure"] }),
    onError: error => toast({ variant: "destructive", title: "Could not update observation", description: describeApiError(error) }),
  });
  const promote = useMutation({
    mutationFn: (id: string) => endpoints.promoteExposureObservation(id),
    onSuccess: result => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["exposure"] });
      // WI-13: the same wording as DNS Security names the source, because
      // ``matched_asset`` alone cannot tell an operator which provider observed
      // the host that became this asset.
      toast({
        title: result.already_exists ? "Already in Assets" : "Asset added",
        description: result.already_exists
          ? `${result.asset?.asset_value ?? "This observation"} is already monitored.`
          : `${result.asset?.asset_value ?? "The asset"} added from the ${result.source ?? "source"} observation.`,
      });
    },
    onError: error => toast({ variant: "destructive", title: "Could not add asset", description: describeApiError(error) }),
  });
  const columns: DataTableColumn<Observation>[] = [
    { key: "subject", title: "Observed host", minWidth: 200, render: r => <span className="font-mono">{r.subject}</span> },
    { key: "service", title: "Service", minWidth: 150, render: r => `${r.payload.port ?? "—"}/${r.payload.transport ?? "—"} · ${r.payload.protocol ?? "unknown"}` },
    { key: "matched_asset", title: "Matched asset", minWidth: 180, render: r => r.matched_asset },
    { key: "source", title: "Source", minWidth: 110, render: r => r.source },
    { key: "observed_at", title: "Provider observation (UTC)", minWidth: 180, render: r => r.observed_at ? formatDateTime(r.observed_at) : "Unknown" },
    { key: "first_seen_at", title: "First seen (UTC)", minWidth: 180, render: r => formatDateTime(r.first_seen_at) },
    { key: "last_seen_at", title: "Last seen (UTC)", minWidth: 180, render: r => formatDateTime(r.last_seen_at) },
    { key: "status", title: "Triage", minWidth: 150, render: r => <Badge variant={r.status === "resolved" ? "secondary" : r.status === "investigating" ? "outline" : "default"}>{r.status}</Badge> },
    ...(canScan ? [{ key: "actions", title: "Actions", minWidth: 250, render: (r: Observation) => <div className="flex gap-2"><Select value={r.status} onValueChange={value => triage.mutate({ id: r.id, status: value as "observed" | "investigating" | "resolved" })}><SelectTrigger aria-label={`Triage ${r.subject}`} className="h-8 w-36"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="observed">Observed</SelectItem><SelectItem value="investigating">Investigating</SelectItem><SelectItem value="resolved">Resolved</SelectItem></SelectContent></Select><Button size="sm" variant="outline" onClick={() => setPromoting(r)} disabled={promote.isPending} aria-label={`Add ${r.subject} to Assets`}>Add asset</Button></div> }] : []),
  ];
  const scan = useMutation({
    mutationFn: () => endpoints.scanModule("exposure"),
    onSuccess: result => {
      toast({ title: "Exposure scan queued", description: result.sources.map(s => `${s.connector}: ${s.status}`).join(" · ") });
      qc.invalidateQueries({ queryKey: ["jobs"] });
    },
    onError: error => toast({ variant: "destructive", title: "Scan not started", description: describeExposureScanError(error) }),
  });
  return <div className="space-y-6">
    <div className="flex justify-between gap-4"><div><h1 className="text-2xl font-bold">Exposure</h1><p className="text-sm text-muted-foreground">Passively observed external services. Not verified vulnerabilities or proof of exploitation.</p></div>
      {canScan && <Button disabled={scan.isPending} onClick={() => scan.mutate()}>Rescan</Button>}
    </div>
    <label className="flex items-center gap-2 text-sm">Source<select aria-label="Exposure source" className="rounded border bg-background p-2" value={source} onChange={event => { setSource(event.target.value); setPage(1); }}><option value="">All sources</option>{EXPOSURE_SOURCES.map(s => <option key={s} value={s}>{s}</option>)}</select></label>
    <p className="text-xs text-muted-foreground">Shared IP/CDN and certificate names alone do not establish ownership. Failed or truncated scans never resolve earlier observations. {TIME_ZONE_HINT}.</p>
    <PaginatedDataTable<Observation> ariaLabel="Exposure observations" storageKey="exposure-columns" columns={columns} rows={query.data?.items ?? []} total={query.data?.total ?? 0} page={page} pageSize={size} onPageChange={setPage} onPageSizeChange={n => { setSize(n); setPage(1); }} loading={query.isLoading} isRefreshing={query.isFetching && !query.isLoading} isError={query.isError} onRetry={() => query.refetch()} errorDescription="Exposure observations could not be loaded." emptyText="No observations yet. Configure and enable an opt-in source in Settings." />
    <ConfirmDialog open={promoting !== null} onOpenChange={open => { if (!open) setPromoting(null); }} title="Add to Assets?" description={promoting ? <>Add <span className="font-mono font-semibold">{promoting.subject}</span> to your monitored assets?</> : undefined} confirmLabel="Add to Assets" confirmLoading={promote.isPending} onConfirm={() => { if (promoting) promote.mutate(promoting.id); setPromoting(null); }} onCancel={() => setPromoting(null)}>
      <p className="text-sm text-muted-foreground">{promoting ? `It is created as an asset of type ${promotedAssetType(promoting.subject)} with criticality ${PROMOTED_ASSET_CRITICALITY}, checked by future scans — not retroactively. A ${promoting.source} observation of a shared IP or CDN name does not prove ownership of the host, so confirm this address really belongs to your organisation before monitoring it.` : ""}</p>
    </ConfirmDialog>
  </div>;
}
