import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe2, RefreshCw, Rocket, Plus, Eraser, Trash2, Check } from "lucide-react";
import { endpoints, describeApiError } from "@/lib/api";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import { PROMOTED_ASSET_CRITICALITY, promotedAssetType } from "@/lib/assetValidation";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import type { DNSObservation, DNSObservationSource } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import CertificateTriage from "@/components/CertificateTriage";
import { JobsTable } from "@/components/JobsTable";
import { useModuleJobTypes } from "@/hooks/useModuleJobTypes";
import { toast } from "@/components/ui/use-toast";

// The DNS & TLS Intelligence module produces observations from exactly these
// sources: the keyless and keyed DNS connectors, Netlas passive DNS, the active
// TLS probe that reads the certificate a host serves rather than the one a log
// recorded, and the Shodan confirmation worker that asks an independent index what
// our own addresses serve. The union in ``types/api`` is the contract, so a filter
// entry that is not in it is a compile error rather than a silently dead option.
// Exported because it is the filter's contract, and the filter's options are
// rendered from it: a test asserts the vocabulary rather than opening a Radix
// portal, which jsdom cannot drive here (see ``PhishingPage.sort.test.tsx``).
export const DNS_SOURCES: DNSObservationSource[] = ["rdap", "resolver", "ctlogs", "virustotal", "netlas", "tlsprobe", "shodan"];
export const DNS_SOURCE_LABELS: Record<DNSObservationSource, string> = { rdap: "RDAP", resolver: "DNS resolver", ctlogs: "CT Logs", virustotal: "VirusTotal", netlas: "Netlas", tlsprobe: "TLS probe", shodan: "Shodan" };

//: What the row *is*, which is not the same as whether the fact is current: certificate
//: evidence says where it came from, and a name a provider scores malicious says so on
//: the row itself instead of leaving that in provider-specific metadata (F-09).
function evidenceBadge(row: DNSObservation) {
  if (row.observation_type === "certificate") {
    return <Badge variant="outline" title={`${row.evidence_count ?? 1} certificate evidence record(s) retained`}>Historical CT{row.evidence_count > 1 ? ` · ${row.evidence_count} records` : ""}</Badge>;
  }
  if (row.observation_type === "tls_certificate") {
    return <Badge variant="outline" title="Read from an active handshake with this service">Served certificate{row.evidence_count > 1 ? ` · ${row.evidence_count} records` : ""}</Badge>;
  }
  if (row.metadata?.suspicious === true) {
    const malicious = Number(row.metadata?.analysis_malicious ?? 0);
    const suspicious = Number(row.metadata?.analysis_suspicious ?? 0);
    return <Badge variant="destructive" title={`VirusTotal: ${malicious} engine(s) flag it malicious, ${suspicious} suspicious`}>Suspicious · {malicious + suspicious}</Badge>;
  }
  if (row.observation_type === "vt_domain") {
    return <Badge variant="outline" title="VirusTotal reputation, categories and served certificate for this name">Reputation</Badge>;
  }
  return <Badge variant="outline">{row.status}</Badge>;
}

export default function DNSSecurityPage() {
  const canWrite = useIsAnalystPlus();
  const isAdmin = useIsAdmin();
  const [cleanOrphansOpen, setCleanOrphansOpen] = useState(false);
  const [deleting, setDeleting] = useState<DNSObservation | null>(null);
  // WI-14: promoting an observation is a configuration change, so it is
  // confirmed with the type and criticality the asset will actually get. The
  // value alone cannot tell an operator that "Add" creates an asset that later
  // scans will act on.
  const [promoting, setPromoting] = useState<{ id: string; target: string } | null>(null);
  const health = useQuery({
    queryKey: ["connectors-health"],
    queryFn: endpoints.connectorsHealth,
    refetchInterval: 30_000,
  });
  const dnsConnectors = health.data?.items.filter((item) => item.connector_type === "dns") ?? [];
  const unavailable = dnsConnectors.filter((item) => item.online === false || (item.online === undefined && ["unknown", "degraded", "disabled"].includes(item.health)));
  const noWorkers = health.isSuccess && (dnsConnectors.length === 0 || unavailable.length === dnsConnectors.length);
  const qc = useQueryClient();
  const jobTypes = useModuleJobTypes("dns");
  const [source, setSource] = useState<string>("all");
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const { data, isLoading, isPlaceholderData, isError, isFetching, refetch } = useQuery({
    queryKey: ["dns-security", source, page, size],
    queryFn: () => endpoints.listDNSObservations({ source: source === "all" ? undefined : source, page, size }),
    staleTime: 20_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
  });
  const addAsset = useMutation({
    mutationFn: ({ id, target }: { id: string; target: string }) => endpoints.promoteDNSObservation(id, target),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["dns-security"] });
      // WI-13: the toast says where the asset came from, so an operator who
      // promoted it days ago can still place it. The durable record is the
      // promotion's audit row, which carries the same source.
      toast({
        title: result.already_exists ? "Already in Assets" : "Asset added",
        description: result.already_exists
          ? `${result.asset?.asset_value ?? "This observation"} is already monitored.`
          : `${result.asset?.asset_value ?? "The asset"} added from the ${result.source ?? "DNS"} observation.`,
      });
    },
    onError: (error: unknown) => toast({ variant: "destructive", title: "Could not add asset", description: describeApiError(error) }),
  });
  const remove = useMutation({
    mutationFn: (row: DNSObservation) => endpoints.deleteDNSObservation(row.id, row.source === "resolver" && row.observation_type === "dns_record" ? row.value : undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-security"] });
      setDeleting(null);
      toast({ title: "DNS observation deleted" });
    },
    onError: (error: unknown) => toast({ variant: "destructive", title: "Could not delete observation", description: describeApiError(error) }),
  });
  const cleanup = useMutation({
    mutationFn: endpoints.cleanOrphanDNSObservations,
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["dns-security"] });
      setCleanOrphansOpen(false);
      toast({ title: "Orphan DNS entries cleaned", description: `${result.deleted} entries deleted.` });
    },
    onError: (error: unknown) => toast({ variant: "destructive", title: "Cleanup failed", description: describeApiError(error) }),
  });
  const scan = useMutation({
    mutationFn: endpoints.scanDNSSecurity,
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["jobs"] });
      toast({ title: "DNS Security scan queued", description: `${result.job_ids.length} source job(s) queued. Follow execution in Jobs history.${result.offline_connectors?.length ? ` Offline sources skipped: ${result.offline_connectors.join(", ")}.` : ""}` });
    },
    onError: (error: unknown) => toast({ variant: "destructive", title: "Scan could not start", description: describeApiError(error) }),
  });

  const assetButton = (row: DNSObservation, target: string, exists: boolean, wildcard = false) => canWrite && (
    <Button size="sm" variant="outline" className="shrink-0" onClick={() => setPromoting({ id: row.id, target })} disabled={addAsset.isPending || exists || wildcard}
      aria-label={exists ? `${target} already in Assets` : wildcard ? `Cannot add wildcard ${target}` : `Add ${target} to Assets`}
      title={exists ? "Already in Assets (including inactive assets)" : wildcard ? "Wildcard evidence is not a concrete hostname" : `Add ${target} to Assets`}>
      {exists ? <Check className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}{exists ? "In Assets" : wildcard ? "Wildcard" : "Add"}
    </Button>
  );
  const columns: DataTableColumn<DNSObservation>[] = [
    { key: "subject", title: "Hostname / IP", width: 260, minWidth: 190, render: (row) => <div className="flex items-center gap-2"><span className="font-mono text-sm break-all">{row.metadata?.wildcard === true ? `*.${row.subject}` : row.subject}</span>{assetButton(row, row.subject, row.subject_in_assets, row.metadata?.wildcard === true)}</div> },
    { key: "observation_type", title: "Observation", width: 150, minWidth: 120, render: (row) => <Badge variant="outline">{row.observation_type.replaceAll("_", " ")}</Badge> },
    { key: "record_type", title: "Record", width: 100, minWidth: 80, render: (row) => row.record_type || "—" },
    { key: "value", title: "Value", minWidth: 180, render: (row) => <div className="flex items-center gap-2"><span className="font-mono text-xs break-all">{row.value || "—"}</span>{row.value_asset_target && assetButton(row, row.value_asset_target, row.value_in_assets)}</div> },
    { key: "source", title: "Source", width: 135, minWidth: 120, render: (row) => <Badge variant="secondary">{DNS_SOURCE_LABELS[row.source]}</Badge> },
    { key: "status", title: "Evidence", width: 170, minWidth: 140, render: (row) => evidenceBadge(row) },
    { key: "expires_at", title: "Validity / Expiry (UTC)", width: 270, minWidth: 230, render: (row) => {
      const monitor = row.expiry_monitor;
      const kind = row.expiry_kind ?? (row.observation_type === "rdap" ? "registration" : row.observation_type.startsWith("certificate") ? "certificate" : row.observation_type === "tls_probe" ? "tls" : row.source === "resolver" ? "dns_cache" : "unknown");
      const label = kind === "registration" ? "Domain registration expiry" : kind === "tls" ? "Live TLS certificate expiry" : kind === "certificate" ? "Observed certificate expiry" : kind === "dns_cache" ? "DNS cache validity (TTL)" : "Validity";
      const date = row.observation_type === "certificate_check" || row.observation_type === "tls_probe" ? monitor?.expires_at ?? row.expires_at : row.expires_at;
      const remaining = date ? (new Date(date).getTime() - Date.now()) / 86400000 : null;
      // `formatDateTime` renders the stored UTC instant as UTC. A local-time
      // rendering here would disagree with the audit trail, the schedules and the
      // expiry thresholds an operator compares this column against.
      return <div className="space-y-1 text-xs"><div className="font-medium">{label}</div><div>{date ? formatDateTime(date) : "Unknown"}</div>{remaining !== null && <div>{remaining <= 0 ? "Expired" : `${Math.ceil(remaining)} day(s) remaining`}</div>}{kind !== "dns_cache" && <><Badge variant="outline">{monitor?.state.replaceAll("_", " ") ?? "unverified"}</Badge><div>Last successful check: {monitor?.successful_at ? formatDateTime(monitor.successful_at) : "Not verified"}</div></>}      {kind === "certificate" && <div className="text-muted-foreground">Passive CT evidence; use by the service is not verified.</div>}{kind === "tls" && <div className="text-muted-foreground">Active TLS probe: this is the certificate the service serves, read from a verified handshake.</div>}{kind === "dns_cache" && <div className="text-muted-foreground">Cache lifetime only; no expiry alert.</div>}</div>;
    } },
    { key: "actions", title: "Actions", width: 90, minWidth: 80, align: "right", render: (row) => canWrite ? <Button size="icon" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => setDeleting(row)} title="Delete DNS observation" aria-label="Delete DNS observation"><Trash2 className="w-4 h-4" /></Button> : null },
  ];

  return <div className="space-y-6">
    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
      <div className="min-w-0 flex-1 max-w-2xl"><h1 className="text-2xl font-bold flex items-center gap-2"><Globe2 className="h-6 w-6 text-primary" />DNS Security</h1><p className="mt-1 text-sm text-muted-foreground">Current DNS records, registration data, historical certificate evidence, and passive-DNS intelligence. CT appearance alone does not establish current DNS or ownership.</p></div>
      <div className="flex shrink-0 flex-nowrap gap-2 overflow-x-auto"><Button variant="outline" onClick={() => refetch()} disabled={isFetching}><RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />Refresh</Button>{isAdmin && <Button variant="outline" onClick={() => setCleanOrphansOpen(true)}><Eraser className="h-4 w-4" />Clean orphans</Button>}{canWrite && <Button onClick={() => scan.mutate()} disabled={scan.isPending || noWorkers}><Rocket className="h-4 w-4" />{scan.isPending ? "Starting…" : "Rescan"}</Button>}</div>
    </div>
    {health.isError && <p role="alert" className="text-sm text-destructive">Connector availability could not be checked. Rescan will validate worker availability on the server.</p>}
    {health.isSuccess && (noWorkers || unavailable.length > 0) && <div role="status" className="rounded-md border border-yellow-500/30 bg-yellow-500/10 p-4 text-sm"><strong>{noWorkers ? "DNS workers are not running." : "Some DNS workers are unavailable."}</strong> {unavailable.map((item) => item.name).join(", ")}. Configure connector tokens and start the DNS Security worker containers; wait for their heartbeat. Offline sources are not queued. Existing pending jobs wait for their worker, not for Celery.</div>}
    <Card><CardHeader><CardTitle className="text-base">Source observations</CardTitle><CardDescription>{data?.total ?? 0} records. Source results are retained independently; provider failure does not delete prior or sibling-source results. {TIME_ZONE_HINT}.</CardDescription></CardHeader><CardContent className="space-y-4"><Select value={source} onValueChange={(value) => { setSource(value); setPage(1); }}><SelectTrigger aria-label="Filter by source" className="max-w-xs"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All sources</SelectItem>{DNS_SOURCES.map((item) => <SelectItem key={item} value={item}>{DNS_SOURCE_LABELS[item]}</SelectItem>)}</SelectContent></Select><PaginatedDataTable columns={columns} rows={data?.items ?? []} total={data?.total ?? 0} page={page} pageSize={size} onPageChange={setPage} onPageSizeChange={(value) => { setSize(value); setPage(1); }} getRowId={(row) => `${row.id}:${row.value ?? ""}`} storageKey="dns-security-observations-v2" loading={isLoading || isPlaceholderData} isError={isError} errorDescription="DNS Security observations could not be loaded; this is not evidence of a clean DNS posture." onRetry={() => refetch()} emptyText="No observations yet. Add a domain asset and run a scan." /></CardContent></Card>
    <CertificateTriage />
    <JobsTable jobTypes={jobTypes} />
    <ConfirmDialog open={deleting !== null} onOpenChange={(open) => { if (!open) setDeleting(null); }} variant="destructive" title="Delete DNS observation?" description={`Permanently delete ${deleting?.subject ?? ""}${deleting?.observation_type === "certificate" ? " and all certificate evidence grouped in this row" : deleting?.source === "resolver" ? ` (${deleting.value ?? ""})` : ""}? Assets and other sources are not deleted. A later scan may rediscover it.`} confirmLabel="Delete" confirmLoading={remove.isPending} onConfirm={() => { if (deleting) remove.mutate(deleting); }} onCancel={() => setDeleting(null)} />
    <ConfirmDialog open={cleanOrphansOpen} onOpenChange={setCleanOrphansOpen} variant="destructive" title="Clean orphan DNS observations?" description="This permanently deletes observations whose hostname/IP and originating scan domain are no longer configured assets. Inactive assets and observations linked through certificate or passive-DNS provenance are preserved." confirmLabel="Clean entries" confirmLoading={cleanup.isPending} onConfirm={() => cleanup.mutate()} onCancel={() => setCleanOrphansOpen(false)} />
    <ConfirmDialog open={promoting !== null} onOpenChange={(open) => { if (!open) setPromoting(null); }} title="Add to Assets?" description={promoting ? <>Add <span className="font-mono font-semibold">{promoting.target}</span> as a monitored asset?</> : undefined} confirmLabel="Add to Assets" confirmLoading={addAsset.isPending} onConfirm={() => { if (promoting) addAsset.mutate(promoting); setPromoting(null); }} onCancel={() => setPromoting(null)}>
      <p className="text-sm text-muted-foreground">{promoting ? `It is created as an asset of type ${promotedAssetType(promoting.target)} with criticality ${PROMOTED_ASSET_CRITICALITY}, and is monitored from now on; scans do not run retroactively. Only the value is promoted — this source observation stays as evidence.` : ""}</p>
    </ConfirmDialog>
  </div>;
}
