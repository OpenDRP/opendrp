import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Search, RefreshCw, Copy, Rocket, ExternalLink, Trash2, Eraser, Check, Ban, Undo2, PlusCircle } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import { formatNumber, copyToClipboard } from "@/lib/utils";
import {
  alertBandLabel,
  detectionSourceLabel,
  evidenceCapabilityLabel,
  signalLabel,
  SIGNAL_NAMES,
  threatStatusLabel,
  verdictLabel,
} from "@/lib/labels";
import { useModuleJobTypes } from "@/hooks/useModuleJobTypes";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import type { AlertBand, PhishingEvidence, PhishingThreat, PhishingVerdict, DetectionSource, ThreatStatus } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { JobsTable } from "@/components/JobsTable";
import { toast } from "@/components/ui/use-toast";
import { summarizeScanJobs, waitForScanJobs } from "@/lib/scanPolling";

const SOURCES: DetectionSource[] = ["dnstwist", "shodan_ssl", "shodan_title", "shodan_favicon", "netlas"];
const STATUSES: ThreatStatus[] = ["active", "investigating", "resolved"];

/**
 * The orderings the list offers, as the `sort`/`order` pair the API declares.
 *
 * "Newest finding first", "strongest candidate first" and "youngest domain first"
 * are different questions: the first asks when the platform noticed the candidate,
 * the second what the evidence adds up to, the third how new its registration is —
 * and a young registration is the signal a look-alike carries. Every pair here is
 * one the API declares; anything else is a 422 rather than an ordering.
 */
export const SORT_OPTIONS = [
  { value: "created_at:desc", sort: "created_at", order: "desc", label: "Newest finding first" },
  { value: "created_at:asc", sort: "created_at", order: "asc", label: "Oldest finding first" },
  { value: "confidence:desc", sort: "confidence", order: "desc", label: "Strongest candidate first" },
  { value: "confidence:asc", sort: "confidence", order: "asc", label: "Weakest candidate first" },
  { value: "age:asc", sort: "age", order: "asc", label: "Youngest domain first" },
  { value: "age:desc", sort: "age", order: "desc", label: "Oldest domain first" },
] as const;

/** Human-readable label for the detection source of a finding. */
function sourceLabel(source: DetectionSource | string): string {
  return detectionSourceLabel(source);
}

const statusTone: Record<ThreatStatus, string> = {
  active: "bg-red-500/15 text-red-500 border-red-500/30",
  investigating: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  resolved: "bg-green-500/15 text-green-500 border-green-500/30",
};

/**
 * How a verdict is drawn. Its tone is the *effect*, not an opinion: a confirmed
 * candidate is the one the channel is loud about, and a rejected one is the one it is
 * silent about (WI-12).
 */
const verdictTone: Record<PhishingVerdict, string> = {
  confirmed: "bg-red-500/15 text-red-500 border-red-500/30",
  rejected: "bg-muted text-muted-foreground border-border",
};

/**
 * How a band is drawn. It names the decision, not the number: the thresholds belong
 * to the deployment, so the page shows what will happen rather than the score that
 * happens to trigger it here (WI-07/WI-08).
 */
const bandTone: Record<AlertBand, string> = {
  direct: "bg-red-500/15 text-red-500 border-red-500/30",
  digest: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  list: "bg-muted text-muted-foreground border-border",
};

/** One signal as an operator reads it: its name and what it contributed. */
function signalPoints(entries: [string, number][]): string {
  return entries
    .map(([name, points]) => `${signalLabel(name)} (${points > 0 ? `+${points}` : points})`)
    .join("\n");
}

/**
 * What a row discloses about one candidate: its signals, and who registered it.
 *
 * The columns answer "what is it"; this answers the two questions an analyst
 * opens a candidate with — who registered it and who can be told to take it down,
 * and which sources reported it. The registrar, the abuse contact and the
 * registration date are stored by the WHOIS enrichment and used to reach only the
 * alert email, so triaging from the list meant leaving the page (W0.5).
 *
 * A fact nobody resolved says so: an empty cell would read as "there is no
 * registrar", which is a different and wrong conclusion, exactly as the age column
 * distinguishes "0 d" from "unknown".
 */
function CandidateEvidence({ threat }: { threat: PhishingThreat }) {
  const [open, setOpen] = useState(false);
  // Read for the row that was opened, never for the page: twenty rows would be
  // twenty requests, and most of them are never read.
  const query = useQuery({ queryKey: ["phishing-evidence", threat.id], queryFn: () => endpoints.phishingEvidence(threat.id), enabled: open });
  const unresolved = "Not resolved yet";
  return <div className="text-xs"><Button size="sm" variant="ghost" onClick={() => setOpen(!open)} aria-expanded={open}>Signals</Button>
    {open && <div className="space-y-2">
      <p className="text-muted-foreground">Matches are candidates, not verified malicious verdicts.</p>
      <div className="space-y-0.5">
        <p className="font-medium text-foreground">Score</p>
        <p>
          <span className="text-muted-foreground">Confidence:</span>{" "}
          <span className="font-mono">{threat.confidence}</span> — {alertBandLabel(threat.alert_band)}
        </p>
        {Object.entries(threat.signals ?? {}).length ? (
          Object.entries(threat.signals).map(([name, points]) => (
            <p key={name}>
              {signalLabel(name)} <span className="font-mono text-muted-foreground">{points > 0 ? `+${points}` : points}</span>
            </p>
          ))
        ) : (
          <p className="text-muted-foreground">
            No signal has fired for this candidate yet: nothing has been established about it, so it
            scores nothing and stays in the list.
          </p>
        )}
      </div>
      <div className="space-y-0.5">
        <p className="font-medium text-foreground">Decision</p>
        {threat.verdict ? (
          <>
            <p>
              <span className="text-muted-foreground">Verdict:</span>{" "}
              {verdictLabel(threat.verdict)}
            </p>
            {/* An empty line would read as "no reason given", which is a different
                claim from "the reason was not recorded" — a confirmation may
                legitimately carry none. */}
            <p>
              <span className="text-muted-foreground">Reason:</span>{" "}
              {threat.verdict_reason || "None recorded"}
            </p>
            <p>
              <span className="text-muted-foreground">Decided:</span>{" "}
              {threat.verdict_at ? formatDateTime(threat.verdict_at) : unresolved}
            </p>
          </>
        ) : (
          <p className="text-muted-foreground">
            No decision recorded: this candidate is routed by its score alone.
          </p>
        )}
      </div>
      <div className="space-y-0.5">
        <p className="font-medium text-foreground">Registrar / abuse</p>
        <p><span className="text-muted-foreground">Registered:</span> {threat.domain_created_at ? formatDateTime(threat.domain_created_at) : unresolved}</p>
        <p><span className="text-muted-foreground">Registrar:</span> {threat.whois_registrar || unresolved}</p>
        <p><span className="text-muted-foreground">Abuse contact:</span> {threat.whois_abuse_email || unresolved}</p>
      </div>
      <div className="space-y-0.5">
        <p className="font-medium text-foreground">Source evidence</p>
        {query.isLoading ? <p>Loading evidence…</p> : query.isError ? <p>Evidence could not be loaded.</p> : query.data?.items.length ? query.data.items.map((e: PhishingEvidence, i: number) => (
          <p key={i}>
            {sourceLabel(e.source)} · {e.matched_asset}
            {/* What the row *is* comes before when it happened: a certificate that claims
                the brand and a registration record about a candidate we already have are
                different statements, and a bare source and timestamp reads as one. */}
            {e.fields?.capability ? <> · {evidenceCapabilityLabel(e.fields.capability)}</> : null}
            {e.fields?.verdict ? <> · {verdictLabel(e.fields.verdict)}</> : null}
            {e.fields?.registrar ? <> · registrar: {e.fields.registrar}</> : null}
            {e.fields?.created ? <> · registered: {formatDateTime(e.fields.created)}</> : null}
            {e.fields?.mail_capable === true ? " · receives mail" : e.fields?.mail_capable === false ? " · no mail records" : null}
            {" · observed: "}{e.observed_at ? formatDateTime(e.observed_at) : "unknown"}
            {" · first: "}{formatDateTime(e.first_seen_at)} · last: {formatDateTime(e.last_seen_at)}
          </p>
        )) : <p>No recorded source evidence.</p>}
      </div>
    </div>}
  </div>;
}

export default function PhishingPage() {
  const canWrite = useIsAnalystPlus();
  const isAdmin = useIsAdmin();
  const qc = useQueryClient();
  // Job history covers every job type the registered phishing connectors
  // declare, so a connector added later appears without a frontend change.
  const moduleJobTypes = useModuleJobTypes("phishing");

  const [findingId] = useState(() => new URLSearchParams(window.location.search).get("finding_id") || undefined);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [sourceFilter, setSourceFilter] = useState<DetectionSource | undefined>();
  const [statusFilter, setStatusFilter] = useState<ThreatStatus | undefined>();
  // The two scoring filters (WI-11): a minimum score and a signal that has to have
  // fired. Both are sent as the API declares them, and both reset paging — a filter
  // that left the reader on page 4 of a shorter list would look like an empty list.
  const [minConfidence, setMinConfidence] = useState<number | undefined>();
  const [signalFilter, setSignalFilter] = useState<string | undefined>();
  const [sortValue, setSortValue] = useState<string>(SORT_OPTIONS[0].value);
  const sort = SORT_OPTIONS.find((option) => option.value === sortValue) ?? SORT_OPTIONS[0];

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingThreat, setDeletingThreat] = useState<PhishingThreat | null>(null);
  const [cleanOrphansOpen, setCleanOrphansOpen] = useState(false);
  // The rejection is the one verdict that needs something written down before it can
  // be recorded, so it is the one that gets a dialog (WI-12).
  const [rejecting, setRejecting] = useState<PhishingThreat | null>(null);
  const [rejectReason, setRejectReason] = useState("");

  const { data, isLoading, isPlaceholderData, isError, refetch, isFetching } = useQuery({
    queryKey: ["phishing", findingId, page, size, debouncedSearch, sourceFilter, statusFilter, minConfidence, signalFilter, sortValue],
    queryFn: () => endpoints.listPhishing({
      finding_id: findingId, page, size, detection_source: sourceFilter, status: statusFilter, search: debouncedSearch || undefined,
      min_confidence: minConfidence, signal: signalFilter,
      sort: sort.sort, order: sort.order,
    }),
    staleTime: 15_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
  });

  const updateStatusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: ThreatStatus }) => endpoints.updatePhishingThreat(id, { status }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["phishing"] }); toast({ title: "Threat updated" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Update failed", description: describeApiError(e) }),
  });

  const promoteMut = useMutation({
    mutationFn: (id: string) => endpoints.promotePhishingAsset(id),
    onSuccess: (result: any) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast({
        title: result?.already_exists ? "Already monitored" : "Domain added",
        description: result?.already_exists
          ? "That look-alike was already in the inventory; nothing changed."
          : "The look-alike domain is now monitored in its own right.",
      });
    },
    onError: (error: any) =>
      toast({
        variant: "destructive",
        title: "Could not take the domain under monitoring",
        description: describeApiError(error),
      }),
  });

  const verdictMut = useMutation({
    mutationFn: ({ id, verdict, reason }: { id: string; verdict: PhishingVerdict | null; reason?: string }) =>
      endpoints.updatePhishingThreat(
        id,
        verdict === null ? { verdict: null } : { verdict, ...(reason ? { verdict_reason: reason } : {}) },
      ),
    onSuccess: (_data, variables) => {
      qc.invalidateQueries({ queryKey: ["phishing"] });
      toast({
        title:
          variables.verdict === "confirmed"
            ? "Candidate confirmed"
            : variables.verdict === "rejected"
              ? "Candidate rejected"
              : "Verdict cleared",
        // The decision changes what the channel does, so the message says what
        // changed rather than only that a field was saved.
        description:
          variables.verdict === "confirmed"
            ? "It now alerts whatever it scores, and every change to it is reported."
            : variables.verdict === "rejected"
              ? "It stays in the list and the alert channel goes quiet about it, digest included."
              : "The candidate is routed by its score again.",
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Could not record the decision", description: describeApiError(e) }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => endpoints.deletePhishingThreat(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["phishing"] });
      toast({ title: "Threat deleted" });
      // The dialog closes when the API has answered, not when it was clicked
      // (WI-21): a refusal has to be readable where the decision was made.
      setDeleteOpen(false);
      setDeletingThreat(null);
    },
    onError: () => { /* shown inside the dialog, which stays open */ },
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
    // Registry owns fan-out and per-source admission, not this UI.
    mutationFn: async () => {
      const result = await endpoints.scanModule("phishing");
      const jobs = result.job_ids.length ? await waitForScanJobs(result.job_ids) : [];
      return { result, jobs };
    },
    onSuccess: ({ result, jobs }) => {
      qc.invalidateQueries({ queryKey: ["phishing"] });
      const succeeded = result.job_ids.length;
      // `sources` is optional on `ScanStartResult`: six scan routes share the type and
      // not all of them report per-source admission. A module scan does, and `?? []`
      // keeps the toast honest if a future route stops.
      const reasons = (result.sources ?? []).filter(source => source.status !== "queued" && source.status !== "disabled")
        .map(source => `${source.connector}: ${source.reason || source.status}`);
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
      key: "sources",
      title: "Sources",
      width: 190,
      minWidth: 150,
      render: (t) => {
        // Who reported it, not only who found it (WI-30). The count is the
        // corroboration the score rewards, and the names are what lets a reader tell
        // two independent providers from one connector reporting twice. A candidate
        // with no evidence rows shows "unknown" rather than its own detection source,
        // which is a different fact.
        const sources = t.sources ?? [];
        if (!sources.length) {
          // "not recorded" rather than "unknown": the column asks a different
          // question from the age beside it, and two different absences that read the
          // same are two absences a reader cannot act on differently.
          return (
            <span className="text-xs text-muted-foreground">not recorded</span>
          );
        }
        return (
          <span className="font-mono text-xs" title={sources.join(", ")}>
            {t.source_count ?? sources.length} ({sources.join(", ")})
          </span>
        );
      },
    },
    {
      key: "confidence",
      title: "Confidence",
      width: 170,
      minWidth: 150,
      render: (t) => {
        // The number and the decision it leads to. The tooltip is the audit trail a
        // score needs: an analyst reading "80" has to be able to see which facts
        // produced it without opening anything (WI-08).
        const fired = Object.entries(t.signals ?? {});
        return (
          <div
            className="flex items-center gap-2"
            title={fired.length ? signalPoints(fired) : "No signal has fired yet"}
          >
            <span className="font-mono text-xs">{t.confidence}</span>
            <Badge variant="outline" className={`shrink-0 ${bandTone[t.alert_band] ?? bandTone.list}`}>
              {alertBandLabel(t.alert_band)}
            </Badge>
          </div>
        );
      },
    },
    {
      key: "verdict",
      title: "Verdict",
      width: 150,
      minWidth: 130,
      render: (t) =>
        t.verdict ? (
          // The reason travels in the tooltip: a decision and its justification
          // belong together, and the row has no space for the sentence.
          <Badge
            variant="outline"
            className={verdictTone[t.verdict] ?? verdictTone.rejected}
            title={t.verdict_reason ? `Reason: ${t.verdict_reason}` : "No reason recorded"}
          >
            {verdictLabel(t.verdict)}
          </Badge>
        ) : (
          <span className="text-xs text-muted-foreground">Not decided</span>
        ),
    },
    {
      key: "evidence",
      title: "Evidence",
      minWidth: 200,
      render: t => <CandidateEvidence threat={t} />,
    },
    {
      key: "domain_age_days",
      title: "Age",
      width: 120,
      minWidth: 100,
      render: (t) => {
        const days = t.domain_age_days;
        return (
          <span
            className="font-mono text-xs"
            title={
              t.domain_created_at
                ? `Registered ${formatDateTime(t.domain_created_at)}`
                : "Registration date not resolved yet"
            }
          >
            {days === null || days === undefined ? (
              <span className="text-muted-foreground">unknown</span>
            ) : (
              `${days} d`
            )}
          </span>
        );
      },
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
          {canWrite && t.verdict !== "confirmed" && (
            <Button
              size="icon"
              variant="ghost"
              onClick={() => verdictMut.mutate({ id: t.id, verdict: "confirmed" })}
              title="Confirm: alert on it whatever it scores"
              aria-label="Confirm candidate"
            >
              <Check className="w-4 h-4" />
            </Button>
          )}
          {canWrite && t.verdict !== "rejected" && (
            <Button
              size="icon"
              variant="ghost"
              onClick={() => { setRejecting(t); setRejectReason(t.verdict_reason ?? ""); }}
              title="Reject: stop the channel reporting it, with a reason"
              aria-label="Reject candidate"
            >
              <Ban className="w-4 h-4" />
            </Button>
          )}
          {canWrite && t.verdict && (
            <Button
              size="icon"
              variant="ghost"
              onClick={() => verdictMut.mutate({ id: t.id, verdict: null })}
              title="Clear the decision: route it by its score again"
              aria-label="Clear verdict"
            >
              <Undo2 className="w-4 h-4" />
            </Button>
          )}
          {canWrite && (
            <Button
              size="icon"
              variant="ghost"
              onClick={() => promoteMut.mutate(t.id)}
              disabled={promoteMut.isPending}
              title="Monitor this look-alike as an asset"
              aria-label="Monitor this look-alike domain"
            >
              <PlusCircle className="w-4 h-4" />
            </Button>
          )}
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
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="min-w-0 flex-1 max-w-2xl">
          <h1 className="text-2xl font-bold">Phishing Threats</h1>
          <p className="text-muted-foreground text-sm mt-1">Look-alike domains, certificate abuse and impersonation sites matched against your monitored assets.</p>
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
            Total threats: <span className="font-semibold text-foreground">{formatNumber(data?.total ?? 0)}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
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
            <Input
              type="number"
              min={0}
              max={100}
              inputMode="numeric"
              aria-label="Minimum confidence"
              placeholder="Min confidence"
              value={minConfidence ?? ""}
              onChange={(e) => {
                const raw = e.target.value.trim();
                if (!raw) { setMinConfidence(undefined); setPage(1); return; }
                const parsed = Number(raw);
                if (Number.isNaN(parsed)) return;
                setMinConfidence(Math.max(0, Math.min(100, Math.trunc(parsed))));
                setPage(1);
              }}
            />
            <Select value={signalFilter || "all"} onValueChange={(v: string) => { setSignalFilter(v === "all" ? undefined : v); setPage(1); }}>
              <SelectTrigger aria-label="Filter by signal"><SelectValue placeholder="Signal" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Any signal</SelectItem>
                {SIGNAL_NAMES.map(name => <SelectItem key={name} value={name}>{signalLabel(name)}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={sortValue} onValueChange={(v: string) => { setSortValue(v); setPage(1); }}>
              <SelectTrigger aria-label="Sort threats"><SelectValue placeholder="Sort" /></SelectTrigger>
              <SelectContent>
                {SORT_OPTIONS.map(option => <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>)}
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
            loading={isLoading || isPlaceholderData}
            isError={isError}
            errorDescription="The threat list could not be loaded, so this is not evidence that no phishing infrastructure exists. Retry before drawing a conclusion."
            onRetry={() => refetch()}
            emptyText={
              search || sourceFilter || statusFilter || minConfidence !== undefined || signalFilter
                ? "No threats match the current filters."
                : "No phishing findings yet. Run a rescan to look for look-alike domains."
            }
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
        onOpenChange={(open) => {
          if (!open && deleteMut.isPending) return;
          setDeleteOpen(open);
          if (!open) setDeletingThreat(null);
        }}
        variant="destructive"
        title="Delete threat?"
        description={deletingThreat ? (
          <>You are about to permanently delete phishing threat <span className="font-mono font-semibold">{deletingThreat.phishing_domain}</span>. This action cannot be undone.</>
        ) : "This action cannot be undone."}
        confirmLabel={deleteMut.isPending ? "Deleting…" : "Delete threat"}
        confirmLoading={deleteMut.isPending}
        onConfirm={() => {
          if (deletingThreat) deleteMut.mutate(deletingThreat.id);
        }}
        onCancel={() => setDeletingThreat(null)}
      >
        {deleteMut.isError && (
          <p role="alert" className="text-sm text-destructive">
            {describeApiError(deleteMut.error)}
          </p>
        )}
      </ConfirmDialog>

      <Dialog
        open={rejecting !== null}
        onOpenChange={(open) => { if (!open) { setRejecting(null); setRejectReason(""); } }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Reject this candidate?</DialogTitle>
            <DialogDescription>
              The alert channel will say nothing about{" "}
              <span className="font-mono">{rejecting?.phishing_domain}</span> — not when a scan
              reports it again, and not in the daily digest. It stays in the list. A reason is
              required because it is what the next reader of this finding has instead of the
              decision.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="reject-reason">Reason</Label>
            <Textarea
              id="reject-reason"
              rows={3}
              maxLength={2000}
              value={rejectReason}
              onChange={(event) => setRejectReason(event.target.value)}
              placeholder="Parked domain, no content, registered before the brand existed"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setRejecting(null); setRejectReason(""); }}>
              Cancel
            </Button>
            {/* Disabled until something is written: the server refuses an empty
                reason, so the button must not offer a request that cannot succeed. */}
            <Button
              variant="destructive"
              disabled={!rejectReason.trim() || verdictMut.isPending}
              onClick={() => {
                if (rejecting) {
                  verdictMut.mutate({ id: rejecting.id, verdict: "rejected", reason: rejectReason.trim() });
                }
                setRejecting(null);
                setRejectReason("");
              }}
            >
              Reject
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

    </div>
  );
}
