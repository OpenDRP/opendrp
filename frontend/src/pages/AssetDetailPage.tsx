import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, RefreshCw } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { TIME_ZONE_HINT, formatDateTime, formatDateTimeOrNever } from "@/lib/datetime";
import { assetTypeLabel } from "@/lib/labels";
import { formatNumber } from "@/lib/utils";
import { describeApiError, endpoints } from "@/lib/api";
import { fetchConnectorModules } from "@/lib/connectors";
import {
  coverageByAssetType,
  coverageDescription,
  coverageForType,
} from "@/lib/assetMonitoring";
import type { AssetRelatedFinding, RelatedFindingModule } from "@/types/api";

/**
 * The asset → findings view (WI-12 / AST-22).
 *
 * The relationship was observable in one direction only: a finding named its
 * asset, while an asset said nothing about what it was involved in, so answering
 * "is this domain involved in anything?" meant opening four module pages and
 * searching each one. The counters and the rows come from the backend's single
 * matching rule, so this view lists exactly the findings a cascade delete would
 * remove.
 */

const MODULES: { id: RelatedFindingModule; label: string; empty: string }[] = [
  {
    id: "phishing",
    label: "Phishing",
    empty: "No phishing findings name this asset.",
  },
  {
    id: "breaches",
    label: "Breaches",
    empty: "No breach findings name this asset or a mailbox at it.",
  },
  {
    id: "dns",
    label: "DNS Security",
    empty: "No DNS observation is about this asset.",
  },
  {
    id: "exposure",
    label: "Exposure",
    empty: "No exposure observation is about this asset.",
  },
  {
    id: "findings",
    label: "Other modules",
    empty: "No other module reported a finding about this asset.",
  },
];

export default function AssetDetailPage() {
  const { id = "" } = useParams();
  const [module, setModule] = useState<RelatedFindingModule>("phishing");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  // The asset's own record, read once when the page opens (AST-44). It is what
  // writes `asset.view` and what carries criticality and both dates; the
  // findings endpoint only ever returned a four-field summary of the asset.
  // A stable key with no remount refetch keeps the read count at one per open,
  // rather than one per tab that re-renders the page.
  const assetQuery = useQuery({
    queryKey: ["asset", id],
    queryFn: () => endpoints.getAsset(id),
    enabled: Boolean(id),
    staleTime: Infinity,
    refetchOnMount: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });

  const { data, isLoading, isFetching, isError, error, refetch } = useQuery({
    queryKey: ["asset-findings", id, module, page, pageSize],
    queryFn: () => endpoints.assetFindings(id, { module, page, size: pageSize }),
    enabled: Boolean(id),
  });

  // WI-20: what consumes this asset type, from the connector registry — the
  // answer to "is this row monitored, or only recorded".
  const coverage = useQuery({
    queryKey: ["connector-modules"],
    queryFn: fetchConnectorModules,
    staleTime: 60_000,
    retry: false,
  });
  const coverageMap = useMemo(
    () => coverageByAssetType(coverage.data),
    [coverage.data],
  );

  const record = assetQuery.data;
  const asset = record ?? data?.asset;
  const counts = data?.counts;
  const selected = MODULES.find((entry) => entry.id === module) ?? MODULES[0];
  const typeCoverage = asset ? coverageForType(coverageMap, asset.asset_type) : undefined;
  const lastSeenForModule = data?.last_seen?.[selected.id] ?? null;

  const columns: DataTableColumn<AssetRelatedFinding>[] = [
    {
      key: "title",
      title: "Finding",
      width: 320,
      minWidth: 200,
      render: (row) => <span className="font-mono text-sm break-all">{row.title}</span>,
    },
    {
      key: "matched_asset",
      title: "Matched value",
      width: 240,
      minWidth: 160,
      render: (row) => <span className="font-mono text-xs break-all">{row.matched_asset || "—"}</span>,
    },
    {
      key: "source",
      title: "Source",
      width: 160,
      minWidth: 120,
      render: (row) => <span className="text-sm">{row.source || "—"}</span>,
    },
    {
      key: "status",
      title: "Status",
      width: 130,
      minWidth: 110,
      render: (row) => (
        <Badge variant="outline" className="capitalize">{row.status || "—"}</Badge>
      ),
    },
    {
      key: "observed_at",
      title: "Observed",
      width: 160,
      minWidth: 130,
      render: (row) => (
        <span className="text-xs text-muted-foreground">{row.observed_at ? formatDateTime(row.observed_at) : "—"}</span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <Button variant="ghost" size="sm" className="-ml-2 mb-1" asChild>
            <Link to="/assets">
              <ArrowLeft className="w-4 h-4 mr-2" />
              All assets
            </Link>
          </Button>
          <h1 className="text-2xl font-bold font-mono break-all">{asset?.asset_value ?? "Asset"}</h1>
          <div className="text-muted-foreground text-sm mt-1 flex flex-wrap items-center gap-2">
            {asset && <span>{assetTypeLabel(asset.asset_type)}</span>}
            {asset && (
              <Badge variant="outline" className={asset.is_active ? "border-green-500/30 text-green-500 bg-green-500/10" : "border-muted text-muted-foreground bg-muted/30"}>
                {asset.is_active ? "Active" : "Inactive"}
              </Badge>
            )}
            {record && (
              <Badge variant="outline" className="capitalize">{record.criticality}</Badge>
            )}
            <span className="text-xs">{TIME_ZONE_HINT}</span>
          </div>
          {record && (
            <p className="text-xs text-muted-foreground mt-1">
              Created {formatDateTime(record.created_at)} · Updated {formatDateTime(record.updated_at)}
            </p>
          )}
        </div>
        <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
          <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Involvement</CardTitle>
          <CardDescription>
            What the platform holds about this asset across every module —{" "}
            <span className="font-semibold text-foreground">{formatNumber(counts?.total ?? 0)}</span> in total.
            Findings are matched to the asset with the same rule a cascade delete uses.
            {asset && (
              <span className="block mt-1">
                {selected.label}: last seen{" "}
                {formatDateTimeOrNever(lastSeenForModule)}.
              </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2" role="tablist" aria-label="Finding modules">
            {MODULES.map((entry) => {
              const count = counts?.[entry.id] ?? 0;
              const isSelected = entry.id === module;
              return (
                <Button
                  key={entry.id}
                  role="tab"
                  aria-selected={isSelected}
                  variant={isSelected ? "secondary" : "ghost"}
                  size="sm"
                  onClick={() => {
                    setModule(entry.id);
                    // A tab change is a new question: page 3 of the previous
                    // module means nothing in the next one.
                    setPage(1);
                  }}
                >
                  {entry.label}
                  <Badge variant="outline" className="ml-2">{count}</Badge>
                </Button>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {asset && (
        <Card>
          <CardHeader className="pb-4">
            <CardTitle className="text-base">Monitored by</CardTitle>
            <CardDescription>
              {coverage.isLoading
                ? "Reading the connector registry…"
                : coverage.isError
                  ? "The connector registry could not be read, so what consumes this asset type is unknown."
                  : coverageDescription(typeCoverage!)}
            </CardDescription>
          </CardHeader>
          {((typeCoverage?.modules.length ?? 0) > 0 || (typeCoverage?.connectors.length ?? 0) > 0) && (
            <CardContent className="flex flex-wrap gap-2">
              {typeCoverage!.modules.map((label) => (
                <Badge key={label} variant="secondary">{label}</Badge>
              ))}
              {typeCoverage!.connectors.map((connector) => (
                <Badge key={connector} variant="outline">{connector}</Badge>
              ))}
            </CardContent>
          )}
        </Card>
      )}

      <PaginatedDataTable<AssetRelatedFinding>
        columns={columns}
        rows={data?.items ?? []}
        total={data?.total ?? 0}
        page={data?.page ?? page}
        pageSize={data?.size ?? pageSize}
        onPageChange={setPage}
        onPageSizeChange={(size) => { setPageSize(size); setPage(1); }}
        storageKey={`asset-findings-${module}`}
        ariaLabel={`${selected.label} findings for this asset`}
        loading={isLoading}
        isRefreshing={isFetching && !isLoading}
        isError={isError}
        errorDescription={describeApiError(error)}
        onRetry={() => refetch()}
        emptyText={selected.empty}
      />
    </div>
  );
}
