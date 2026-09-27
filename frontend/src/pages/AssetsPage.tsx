import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Pencil, Trash2, RefreshCw, X, Check, Power } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import { formatNumber } from "@/lib/utils";
import { assetTypeLabel } from "@/lib/labels";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import type { Asset, AssetType, AssetCriticality } from "@/types/api";
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

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<Asset | null>(null);
  const [form, setForm] = useState<Partial<Asset>>({ asset_type: "domain", asset_value: "", criticality: "medium" });
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingAsset, setDeletingAsset] = useState<Asset | null>(null);
  const [cascadeFindings, setCascadeFindings] = useState(false);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["assets", page, size, debouncedSearch, typeFilter, critFilter, activeFilter],
    queryFn: () => endpoints.listAssets({
      page, size,
      asset_type: typeFilter as AssetType | undefined,
      criticality: critFilter,
      is_active: activeFilter,
      search: debouncedSearch || undefined,
    }),
    staleTime: 20_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
  });

  const createMut = useMutation({
    mutationFn: (d: Partial<Asset>) => endpoints.createAsset(d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setDialogOpen(false); resetForm(); toast({ title: "Asset created" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to create asset", description: describeApiError(e) }),
  });
  const updateMut = useMutation({
    mutationFn: ({ id, d }: { id: string; d: Partial<Asset> }) => endpoints.updateAsset(id, d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setDialogOpen(false); resetForm(); toast({ title: "Asset updated" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to update asset", description: describeApiError(e) }),
  });
  const deleteMut = useMutation({
    mutationFn: ({ id, cascade }: { id: string; cascade: boolean }) => endpoints.deleteAsset(id, cascade),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); qc.invalidateQueries({ queryKey: ["phishing"] }); qc.invalidateQueries({ queryKey: ["breaches"] }); toast({ title: "Asset deleted" }); },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to delete asset", description: describeApiError(e) }),
  });
  const toggleMut = useMutation({
    mutationFn: (a: Asset) => endpoints.updateAsset(a.id, { is_active: !a.is_active }),
    onSuccess: (_data, a) => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      toast({ title: a.is_active ? "Asset deactivated" : "Asset activated" });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to update asset", description: describeApiError(e) }),
  });

  function resetForm() { setEditing(null); setForm({ asset_type: "domain", asset_value: "", criticality: "medium" }); }
  function openCreate() { resetForm(); setDialogOpen(true); }
  function openEdit(a: Asset) { setEditing(a); setForm({ asset_type: a.asset_type, asset_value: a.asset_value, criticality: a.criticality }); setDialogOpen(true); }
  function submit() {
    if (!form.asset_type || !form.asset_value || !form.criticality) {
      toast({ variant: "destructive", title: "Validation", description: "Type, value and criticality are required." }); return;
    }
    if (editing) updateMut.mutate({ id: editing.id, d: form });
    else createMut.mutate(form);
  }

  const columns: DataTableColumn<Asset>[] = [
    {
      key: "asset_value",
      title: "Value",
      width: 280,
      minWidth: 180,
      render: (a) => (
        <div className="flex flex-col">
          <span className="font-mono text-sm">{a.asset_value}</span>
          {a.normalized_value && a.normalized_value !== a.asset_value && (
            <span className="text-xs text-muted-foreground font-mono" title="Canonical / normalized value">
              ↳ {a.normalized_value}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "asset_type",
      title: "Type",
      width: 160,
      minWidth: 120,
      render: (a) => <span className="text-sm">{assetTypeLabel(a.asset_type)}</span>,
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
              onClick={() => toggleMut.mutate(a)}
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
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
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
            emptyText={search || typeFilter || critFilter || activeFilter !== undefined ? "No assets match the current filters." : "No assets yet. Add a domain, IP address or mailbox to start monitoring it."}
          />
        </CardContent>
      </Card>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={(open) => { setDeleteOpen(open); if (!open) { setDeletingAsset(null); setCascadeFindings(false); } }}
        variant="destructive"
        title="Delete asset?"
        description={deletingAsset ? (
          <>You are about to permanently delete asset <span className="font-mono font-semibold">{deletingAsset.asset_value}</span>. This action cannot be undone.</>
        ) : "This action cannot be undone."}
        confirmLabel="Delete asset"
        confirmLoading={deleteMut.isPending}
        onConfirm={() => {
          if (deletingAsset) deleteMut.mutate({ id: deletingAsset.id, cascade: cascadeFindings });
          setDeleteOpen(false);
          setDeletingAsset(null);
          setCascadeFindings(false);
        }}
        onCancel={() => { setDeletingAsset(null); setCascadeFindings(false); }}
      >
        <label className="flex items-start gap-3 rounded-md border border-border p-3 text-sm cursor-pointer">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4 accent-destructive"
            checked={cascadeFindings}
            onChange={(event) => setCascadeFindings(event.target.checked)}
            disabled={deleteMut.isPending}
          />
          <span>
            <span className="font-medium">Delete related findings</span>
            <span className="block text-muted-foreground mt-1">Also permanently delete phishing and breach findings linked to this asset.</span>
          </span>
        </label>
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
              <Input id="asset-form-value" placeholder="example.com or 192.168.1.1" value={form.asset_value || ""} onChange={(e) => setForm({ ...form, asset_value: e.target.value })} />
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
