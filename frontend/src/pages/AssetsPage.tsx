import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Pencil, Trash2, RefreshCw, X, Check, Power, Download, Upload } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import { formatNumber } from "@/lib/utils";
import { assetTypeLabel } from "@/lib/labels";
import { fieldErrorsFromApiError, validateAssetValue } from "@/lib/assetValidation";
import {
  coverageByAssetType,
  coverageDescription,
  coverageForType,
  involvementBreakdown,
  lastSeenAt,
} from "@/lib/assetMonitoring";
import { fetchConnectorModules } from "@/lib/connectors";
import { TIME_ZONE_HINT, formatDateTime, formatDateTimeOrNever } from "@/lib/datetime";
import type { Asset, AssetType, AssetCriticality, AssetImportReport } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { toast } from "@/components/ui/use-toast";

const ASSET_TYPES: AssetType[] = ["domain", "ip_address", "email_account", "keyword_domain", "keyword_title"];
const CRITICALITIES: AssetCriticality[] = ["low", "medium", "high", "critical"];

/**
 * Save a downloaded file (WI-18).
 *
 * Isolated so the test environment — which has no object URLs — exercises the
 * request and the report rather than the browser's download plumbing.
 */
function saveBlob(content: Blob, filename: string) {
  if (typeof URL.createObjectURL !== "function") return;
  const url = URL.createObjectURL(content);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** The items of a pasted JSON import: either an array or an `items` array (WI-18). */
function importItemsFromJson(text: string): unknown[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("That is not valid JSON. Paste a JSON items array or a CSV file.");
  }
  const items = Array.isArray(parsed)
    ? parsed
    : (parsed as { items?: unknown } | null)?.items;
  if (!Array.isArray(items)) {
    throw new Error("A JSON import needs an `items` array of asset_type/asset_value rows.");
  }
  return items;
}

const criticalityTone: Record<AssetCriticality, string> = {
  critical: "bg-red-500/15 text-red-500 border-red-500/30",
  high: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
  low: "bg-green-500/15 text-green-500 border-green-500/30",
};

export default function AssetsPage() {
  const canWrite = useIsAnalystPlus();
  const canDelete = useIsAdmin();
  const qc = useQueryClient();

  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [typeFilter, setTypeFilter] = useState<string | undefined>();
  const [critFilter, setCritFilter] = useState<AssetCriticality | undefined>();
  const [activeFilter, setActiveFilter] = useState<boolean | undefined>();
  // WI-20: "what is monitored" as its own question — an asset nothing ever
  // reported about is configured, not monitored.
  const [findingsFilter, setFindingsFilter] = useState<boolean | undefined>();

  // Which modules/connectors consume each asset type, from the registry (WI-20).
  // Same query key as the module pages use, so the declaration is read once.
  const coverage = useQuery({
    queryKey: ["connector-modules"],
    queryFn: fetchConnectorModules,
    staleTime: 60_000,
    retry: false,
  });
  const coverageMap = coverageByAssetType(coverage.data);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [form, setForm] = useState<Partial<Asset>>({ asset_type: "domain", asset_value: "", criticality: "medium" });
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingAsset, setDeletingAsset] = useState<Asset | null>(null);
  // WI-23: with the cascade on, the operator types the asset's value. Deleting
  // an asset is reversible by re-adding it; deleting the findings about it is
  // not, and the checkbox alone is one click away from being checked by habit.
  const [cascadeConfirmation, setCascadeConfirmation] = useState("");
  const [togglingAsset, setTogglingAsset] = useState<Asset | null>(null);
  // WI-19: field-level validation, from the client-side rules and from a 422.
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  // WI-18: the batch import and its per-line report.
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importReport, setImportReport] = useState<AssetImportReport | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  // WI-14: the delete dialog says how much would be affected, so the counts come
  // from the same view the asset page uses (WI-12). They are fetched only while
  // the dialog is open.
  const relatedCounts = useQuery({
    queryKey: ["asset-findings", deletingAsset?.id],
    queryFn: () => endpoints.assetFindings(deletingAsset!.id, { page: 1, size: 1 }),
    enabled: Boolean(deletingAsset),
  });
  const [cascadeFindings, setCascadeFindings] = useState(false);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["assets", page, size, debouncedSearch, typeFilter, critFilter, activeFilter, findingsFilter],
    queryFn: () => endpoints.listAssets({
      page, size,
      asset_type: typeFilter as AssetType | undefined,
      criticality: critFilter,
      is_active: activeFilter,
      has_findings: findingsFilter,
      search: debouncedSearch || undefined,
    }),
    staleTime: 20_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
  });

  const createMut = useMutation({
    mutationFn: (d: Partial<Asset>) => endpoints.createAsset(d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setDialogOpen(false); resetForm(); toast({ title: "Asset created" }); },
    // WI-19: a 422 names fields the operator can see. Shown next to the field
    // instead of as one flattened sentence, which for a two-field error reads as
    // a single problem to guess at.
    onError: (e: any) => {
      const fields = fieldErrorsFromApiError(e);
      setFormErrors(fields);
      if (Object.keys(fields).length === 0) {
        toast({ variant: "destructive", title: "Failed to create asset", description: describeApiError(e) });
      }
    },
  });
  const updateMut = useMutation({
    mutationFn: ({ id, d }: { id: string; d: Partial<Asset> }) => endpoints.updateAsset(id, d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setDialogOpen(false); resetForm(); toast({ title: "Asset updated" }); },
    onError: (e: any) => {
      const fields = fieldErrorsFromApiError(e);
      setFormErrors(fields);
      if (Object.keys(fields).length === 0) {
        toast({ variant: "destructive", title: "Failed to update asset", description: describeApiError(e) });
      }
    },
  });
  // The delete dialog stays open until the mutation settles (WI-21): closing it
  // on the click left the operator with a toast for a failure and no way to
  // retry, and no sign at all that a large cascade was still running.
  const deleteMut = useMutation({
    mutationFn: ({ id, cascade }: { id: string; cascade: boolean }) => endpoints.deleteAsset(id, cascade),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["phishing"] });
      qc.invalidateQueries({ queryKey: ["breaches"] });
      toast({ title: "Asset deleted" });
      setDeleteOpen(false);
      setDeletingAsset(null);
      setCascadeFindings(false);
      setCascadeConfirmation("");
    },
    onError: () => { /* shown inside the dialog, which stays open */ },
  });
  const importMut = useMutation({
    mutationFn: ({ text, dryRun }: { text: string; dryRun: boolean }) => {
      const trimmed = text.trim();
      // Pasted JSON says what it is by starting like JSON; everything else is
      // read as CSV, which is the format an inventory arrives in.
      return trimmed.startsWith("{") || trimmed.startsWith("[")
        ? endpoints.importAssets(importItemsFromJson(trimmed), dryRun)
        : endpoints.importAssetsCsv(text, dryRun);
    },
    onSuccess: (report) => {
      setImportReport(report);
      setImportError(null);
      if (report.dry_run) return;
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast({
        title: "Import finished",
        description: `${report.created} created, ${report.duplicate} already monitored, ${report.invalid} rejected.`,
      });
    },
    onError: (error: unknown) => {
      setImportReport(null);
      setImportError(describeApiError(error));
    },
  });
  async function downloadExport() {
    setExporting(true);
    try {
      const blob = await endpoints.exportAssets({
        asset_type: typeFilter,
        criticality: critFilter,
        is_active: activeFilter,
        has_findings: findingsFilter,
        search: debouncedSearch || undefined,
        sort: "created_at",
        order: "desc",
        format: "csv",
      });
      saveBlob(blob, "assets.csv");
      toast({ title: "Export ready", description: "assets.csv downloaded." });
    } catch (error: unknown) {
      toast({ variant: "destructive", title: "Export failed", description: describeApiError(error) });
    } finally {
      setExporting(false);
    }
  }
  const toggleMut = useMutation({
    mutationFn: (a: Asset) => endpoints.updateAsset(a.id, { is_active: !a.is_active }),
    onSuccess: (_data, a) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast({ title: a.is_active ? "Asset deactivated" : "Asset activated" });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to update asset", description: describeApiError(e) }),
  });

  function resetForm() { setEditing(null); setForm({ asset_type: "domain", asset_value: "", criticality: "medium" }); setFormErrors({}); }
  function openCreate() { resetForm(); setDialogOpen(true); }
  function openEdit(a: Asset) { setEditing(a); setForm({ asset_type: a.asset_type, asset_value: a.asset_value, criticality: a.criticality }); setFormErrors({}); setDialogOpen(true); }
  function submit() {
    // WI-19: the same rules the API applies, checked here so the operator is not
    // told about a typo by a round trip — and so the message can sit under the
    // field it is about.
    const errors: Record<string, string> = {};
    if (!form.asset_type) errors.asset_type = "Type is required.";
    if (!form.asset_value) errors.asset_value = "Value is required.";
    if (!form.criticality) errors.criticality = "Criticality is required.";
    if (form.asset_type && form.asset_value && !errors.asset_value) {
      const detail = validateAssetValue(form.asset_type, form.asset_value);
      if (detail) errors.asset_value = detail;
    }
    setFormErrors(errors);
    if (Object.keys(errors).length > 0) {
      toast({
        variant: "destructive",
        title: "Validation",
        description: Object.values(errors)[0],
      });
      return;
    }
    if (editing) updateMut.mutate({ id: editing.id, d: form });
    else createMut.mutate(form);
  }
  const cascadeConfirmed =
    !cascadeFindings || cascadeConfirmation.trim() === (deletingAsset?.asset_value ?? "");

  const columns: DataTableColumn<Asset>[] = [
    {
      key: "asset_value",
      title: "Value",
      width: 280,
      minWidth: 180,
      // One value, not two: `asset_value` is stored canonicalized, so a second
      // line showing `normalized_value` could never differ from it. The column
      // used to render that line conditionally and so never rendered at all.
      // The value is also the way into the asset's own page (WI-12): "what is
      // this domain involved in" is the question an operator asks next.
      render: (a) => (
        <Link
          to={`/assets/${a.id}`}
          className="font-mono text-sm underline-offset-4 hover:underline"
        >
          {a.asset_value}
        </Link>
      ),
    },
    {
      key: "asset_type",
      title: "Type",
      width: 190,
      minWidth: 140,
      // WI-20: the type is not only a label — it is what decides whether anything
      // scans this row at all. The badge appears only when the registry says
      // nothing enabled consumes the type, so the exceptional case is visible
      // without repeating the normal one on every line.
      render: (a) => {
        const typeCoverage = coverageForType(coverageMap, a.asset_type);
        const monitored = typeCoverage.modules.length > 0 || typeCoverage.connectors.length > 0;
        return (
          <span
            className="text-sm inline-flex items-center gap-2"
            title={coverage.data ? coverageDescription(typeCoverage) : undefined}
          >
            {assetTypeLabel(a.asset_type)}
            {coverage.data && !monitored && (
              <Badge variant="outline" className="border-orange-500/40 text-orange-500">
                not scanned
              </Badge>
            )}
          </span>
        );
      },
    },
    {
      key: "findings",
      title: "Findings",
      width: 170,
      minWidth: 140,
      // WI-20: the counter that separates "configured" from "monitored", and
      // its date, so a stale involvement is as visible as a fresh one.
      render: (a) => {
        const summary = a.findings;
        if (!summary) return <span className="text-muted-foreground text-sm">—</span>;
        const seen = lastSeenAt(summary);
        return (
          <span className="text-sm block" title={involvementBreakdown(summary)}>
            <span className={summary.total > 0 ? "font-medium" : "text-muted-foreground"}>
              {summary.total > 0 ? `${formatNumber(summary.total)} found` : "none found"}
            </span>
            <span className="block text-xs text-muted-foreground">
              {summary.total > 0 ? `last seen ${formatDateTimeOrNever(seen)}` : "never seen"}
            </span>
          </span>
        );
      },
    },
    {
      key: "criticality",
      title: "Criticality",
      width: 140,
      minWidth: 120,
      render: (a) => (
        <Badge variant="outline" className={criticalityTone[a.criticality]}>
          <span className="capitalize">{a.criticality}</span>
        </Badge>
      ),
    },
    {
      key: "is_active",
      title: "Status",
      width: 130,
      minWidth: 110,
      render: (a) => (
        <Badge variant="outline" className={a.is_active ? "border-green-500/30 text-green-500 bg-green-500/10" : "border-muted text-muted-foreground bg-muted/30"}>
          {a.is_active ? <Check className="w-3 h-3 mr-1 inline" /> : <X className="w-3 h-3 mr-1 inline" />}
          {a.is_active ? "Active" : "Inactive"}
        </Badge>
      ),
    },
    {
      key: "created_at",
      title: "Created",
      width: 160,
      minWidth: 140,
      render: (a) => <span className="text-muted-foreground text-sm">{formatDateTime(a.created_at)}</span>,
    },
    {
      key: "actions",
      title: "Actions",
      width: 170,
      minWidth: 150,
      align: "right",
      render: (a) => (
        canWrite ? (
          <div className="inline-flex gap-1 justify-end">
            <Button size="icon" variant="ghost" onClick={() => openEdit(a)} title="Edit asset" aria-label="Edit asset"><Pencil className="w-4 h-4" /></Button>
            <Button
              size="icon"
              variant="ghost"
              className={a.is_active ? "text-orange-500 hover:text-orange-500" : "text-green-500 hover:text-green-500"}
              onClick={() => setTogglingAsset(a)}
              disabled={toggleMut.isPending}
              title={a.is_active ? "Deactivate asset" : "Activate asset"}
              aria-label={a.is_active ? "Deactivate asset" : "Activate asset"}
            >
              <Power className="w-4 h-4" />
            </Button>
            {canDelete && <Button size="icon" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => { setDeletingAsset(a); setCascadeFindings(false); setDeleteOpen(true); }} title="Delete asset" aria-label="Delete asset">
              <Trash2 className="w-4 h-4" />
            </Button>}
          </div>
        ) : null
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Assets</h1>
          <p className="text-muted-foreground text-sm mt-1">Domains, IP addresses, mailboxes and keywords monitored for brand abuse and data exposure.</p>
          <p className="text-xs text-muted-foreground mt-1">{TIME_ZONE_HINT}</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button
            variant="outline"
            onClick={downloadExport}
            disabled={exporting}
            title="Download the current filter as CSV"
          >
            <Download className="w-4 h-4 mr-2" />
            {exporting ? "Exporting..." : "Export"}
          </Button>
          {canWrite && (
            <Button variant="outline" onClick={() => { setImportOpen(true); setImportReport(null); setImportError(null); }}>
              <Upload className="w-4 h-4 mr-2" />
              Import
            </Button>
          )}
          {canWrite && (
            <Button onClick={openCreate}>
              <Plus className="w-4 h-4 mr-2" />
              Add asset
            </Button>
          )}
        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Filters</CardTitle>
          <CardDescription>
            Total results: <span className="font-semibold text-foreground">{formatNumber(data?.total ?? 0)}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="relative md:col-span-2">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input className="pl-9" placeholder="Search value..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
            </div>
            <Select value={typeFilter || "all"} onValueChange={(v: string) => { setTypeFilter(v === "all" ? undefined : (v as AssetType)); setPage(1); }}>
              <SelectTrigger aria-label="Filter by asset type"><SelectValue placeholder="Type" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{assetTypeLabel(t)}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={critFilter || "all"} onValueChange={(v: string) => { setCritFilter(v === "all" ? undefined : (v as AssetCriticality)); setPage(1); }}>
              <SelectTrigger aria-label="Filter by criticality"><SelectValue placeholder="Criticality" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All criticalities</SelectItem>
                {CRITICALITIES.map(c => <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={activeFilter === undefined ? "all" : activeFilter ? "active" : "inactive"} onValueChange={(v: string) => { setActiveFilter(v === "all" ? undefined : v === "active"); setPage(1); }}>
              <SelectTrigger aria-label="Filter by status"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
            <Select value={findingsFilter === undefined ? "all" : findingsFilter ? "with" : "without"} onValueChange={(v: string) => { setFindingsFilter(v === "all" ? undefined : v === "with"); setPage(1); }}>
              <SelectTrigger aria-label="Filter by findings"><SelectValue placeholder="Findings" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Any involvement</SelectItem>
                <SelectItem value="with">With findings</SelectItem>
                <SelectItem value="without">Without findings</SelectItem>
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
            storageKey="assets-table-widths-v1"
            loading={isLoading}
            isError={isError}
            errorDescription="The asset list could not be loaded, so it is not known whether any asset is currently monitored."
            onRetry={() => refetch()}
            emptyText={search || typeFilter || critFilter || activeFilter !== undefined || findingsFilter !== undefined ? "No assets match the current filters." : "No assets yet. Add a domain, IP address or mailbox to start monitoring it."}
          />
        </CardContent>
      </Card>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={(open) => {
          if (!open && deleteMut.isPending) return;
          setDeleteOpen(open);
          if (!open) { setDeletingAsset(null); setCascadeFindings(false); setCascadeConfirmation(""); }
        }}
        variant="destructive"
        title="Delete asset?"
        description={deletingAsset ? (
          <>You are about to permanently delete asset <span className="font-mono font-semibold">{deletingAsset.asset_value}</span>. This action cannot be undone.</>
        ) : "This action cannot be undone."}
        confirmLabel={deleteMut.isPending ? "Deleting..." : "Delete asset"}
        confirmLoading={deleteMut.isPending}
        confirmDisabled={!cascadeConfirmed}
        // The dialog is not closed here: `deleteMut.onSuccess` closes it, so the
        // button keeps its loading state for as long as the cascade runs and a
        // failure can be read (and retried) where the decision was made (WI-21).
        onConfirm={() => {
          if (deletingAsset) deleteMut.mutate({ id: deletingAsset.id, cascade: cascadeFindings });
        }}
        onCancel={() => { setDeletingAsset(null); setCascadeFindings(false); setCascadeConfirmation(""); }}
      >
        <p className="text-sm text-muted-foreground">
          {relatedCounts.isLoading
            ? "Checking what this asset is involved in…"
            : relatedCounts.isError
              ? "The related findings could not be counted, so they are not shown here."
              : (relatedCounts.data?.counts?.total ?? 0) > 0
                ? `Involved in ${formatNumber(relatedCounts.data.counts.total)} findings: phishing ${relatedCounts.data.counts.phishing}, breaches ${relatedCounts.data.counts.breaches}, DNS Security ${relatedCounts.data.counts.dns}, exposure ${relatedCounts.data.counts.exposure}, other modules ${relatedCounts.data.counts.findings}. Deleting the asset alone leaves all of them in place.`
                : "No findings name this asset right now."}
        </p>
        <label className="flex items-start gap-3 rounded-md border border-border p-3 text-sm cursor-pointer">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 accent-destructive"
            checked={cascadeFindings}
            onChange={(event) => { setCascadeFindings(event.target.checked); setCascadeConfirmation(""); }}
            disabled={deleteMut.isPending}
          />
          <span>
            <span className="font-medium">Delete related findings</span>
            <span className="block text-muted-foreground mt-1">Also permanently delete the phishing, breach and generic findings linked to this asset. Source observations are kept: they record what the provider saw, not what you monitor. This part cannot be undone.</span>
          </span>
        </label>
        {cascadeFindings && (
          <label className="block text-sm space-y-2">
            <span className="text-muted-foreground">
              Deleting evidence is not reversible. Type <span className="font-mono font-semibold text-foreground">{deletingAsset?.asset_value}</span> to confirm.
            </span>
            <Input
              value={cascadeConfirmation}
              onChange={(event) => setCascadeConfirmation(event.target.value)}
              disabled={deleteMut.isPending}
              aria-label="Type the asset value to confirm deleting related findings"
            />
          </label>
        )}
        {deleteMut.isError && (
          <p role="alert" className="text-sm text-destructive">
            {describeApiError(deleteMut.error)}
          </p>
        )}
      </ConfirmDialog>

      <Dialog
        open={importOpen}
        onOpenChange={(open) => { setImportOpen(open); if (!open) { setImportReport(null); setImportError(null); } }}
      >
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>Import assets</DialogTitle>
            <DialogDescription>
              Paste CSV with an <span className="font-mono">asset_type,asset_value,criticality</span> header, or a JSON array of those rows. Existing values are reported as duplicates, not changed.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <textarea
              className="min-h-40 w-full rounded-md border border-input bg-background p-3 font-mono text-xs"
              aria-label="Assets to import"
              placeholder={"asset_type,asset_value,criticality\ndomain,example.com,high\nip_address,10.0.0.1,"}
              value={importText}
              onChange={(event) => setImportText(event.target.value)}
              disabled={importMut.isPending}
            />
            {importError && <p role="alert" className="text-sm text-destructive">{importError}</p>}
            {importReport && (
              <div className="space-y-2" role="status" aria-label="Import report">
                <p className="text-sm">
                  {importReport.dry_run ? "Preview: " : "Imported: "}
                  {importReport.created} to create, {importReport.duplicate} already monitored, {importReport.invalid} rejected.
                </p>
                <ul className="max-h-56 space-y-1 overflow-y-auto text-xs">
                  {importReport.rows.slice(0, 100).map((row) => (
                    <li key={row.line} className="flex gap-2">
                      <span className="w-12 shrink-0 text-muted-foreground">line {row.line}</span>
                      <Badge
                        variant="outline"
                        className={
                          row.outcome === "created"
                            ? "border-green-500/30 text-green-500"
                            : row.outcome === "duplicate"
                              ? "border-yellow-500/30 text-yellow-600"
                              : "border-red-500/30 text-red-500"
                        }
                      >
                        {row.outcome}
                      </Badge>
                      <span className="font-mono break-all">{row.asset_type} {row.asset_value}</span>
                      {row.detail && <span className="text-muted-foreground">{row.detail}</span>}
                    </li>
                  ))}
                </ul>
                {importReport.rows.length > 100 && (
                  <p className="text-xs text-muted-foreground">
                    Showing the first 100 of {formatNumber(importReport.rows.length)} lines; the audit trail holds the full report.
                  </p>
                )}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)} disabled={importMut.isPending}>Cancel</Button>
            <Button
              variant="outline"
              onClick={() => importMut.mutate({ text: importText, dryRun: true })}
              disabled={importMut.isPending || !importText.trim()}
            >
              Preview
            </Button>
            <Button
              onClick={() => importMut.mutate({ text: importText, dryRun: false })}
              disabled={importMut.isPending || !importText.trim()}
            >
              {importMut.isPending ? "Working..." : "Import"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={togglingAsset !== null}
        onOpenChange={(open) => { if (!open) setTogglingAsset(null); }}
        title={togglingAsset?.is_active ? "Deactivate asset?" : "Activate asset?"}
        description={togglingAsset ? (
          <>{"You are about to "}{togglingAsset.is_active ? "deactivate" : "activate"} <span className="font-mono font-semibold">{togglingAsset.asset_value}</span>.</>
        ) : undefined}
        confirmLabel={togglingAsset?.is_active ? "Deactivate" : "Activate"}
        confirmLoading={toggleMut.isPending}
        onConfirm={() => { if (togglingAsset) toggleMut.mutate(togglingAsset); setTogglingAsset(null); }}
        onCancel={() => setTogglingAsset(null)}
      >
        <p className="text-sm text-muted-foreground">
          {togglingAsset?.is_active
            ? `A deactivated ${assetTypeLabel(togglingAsset.asset_type)} stops being scanned and drops out of breach, DNS and phishing matching — it is no longer monitored. Findings and source observations already recorded are kept: deactivation is not a delete. Reactivating restores monitoring.`
            : togglingAsset
              ? `The asset is scanned again by every module that monitors a ${assetTypeLabel(togglingAsset.asset_type)}. This only changes monitoring: findings recorded while it was inactive are not restored.`
              : null}
        </p>
      </ConfirmDialog>

      <Dialog open={dialogOpen} onOpenChange={(o) => { if (!o) resetForm(); setDialogOpen(o); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? "Edit asset" : "Add new asset"}</DialogTitle>
            <DialogDescription>Monitored assets define your protected digital footprint.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="asset-form-type">Type</Label>
              <Select
                value={form.asset_type || "domain"}
                onValueChange={(v: string) => setForm({ ...form, asset_type: v as AssetType })}
                disabled={Boolean(editing)}
              >
                <SelectTrigger id="asset-form-type"><SelectValue /></SelectTrigger>
                <SelectContent>{ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{assetTypeLabel(t)}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="asset-form-value">Value</Label>
              <Input
                id="asset-form-value"
                placeholder="example.com or 192.168.1.1"
                value={form.asset_value || ""}
                onChange={(e) => {
                  setForm({ ...form, asset_value: e.target.value });
                  setFormErrors((previous) => ({ ...previous, asset_value: "" }));
                }}
              />
              {formErrors.asset_value && (
                <p role="alert" className="text-xs text-destructive">{formErrors.asset_value}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="asset-form-criticality">Criticality</Label>
              <Select value={form.criticality || "medium"} onValueChange={(v: string) => setForm({ ...form, criticality: v as AssetCriticality })}>
                <SelectTrigger id="asset-form-criticality"><SelectValue /></SelectTrigger>
                <SelectContent>{CRITICALITIES.map(c => <SelectItem key={c} value={c} className="capitalize">{c}</SelectItem>)}</SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={createMut.isPending || updateMut.isPending}>Cancel</Button>
            <Button onClick={submit} disabled={createMut.isPending || updateMut.isPending}>
              {createMut.isPending || updateMut.isPending ? "Saving..." : editing ? "Save changes" : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
