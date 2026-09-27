import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, RefreshCw } from "lucide-react";

import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorState } from "@/components/ui/error-state";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/components/ui/use-toast";
import { useModules } from "@/hooks/useModules";
import { describeApiError } from "@/lib/api";
import { formatDateTime } from "@/lib/datetime";
import { updateFindingStatus } from "@/lib/findings";
import { fetchModuleFindings } from "@/lib/modules";
import { useIsAnalystPlus } from "@/store/auth";
import type { FindingStatus, ModuleFinding, RegistryModule } from "@/types/api";

/** Triage states, in the order an analyst works through them. */
const STATUSES: FindingStatus[] = ["active", "investigating", "resolved"];

const STATUS_LABELS: Record<FindingStatus, string> = {
  active: "Active",
  investigating: "Investigating",
  resolved: "Resolved",
};

const STATUS_VARIANTS: Record<FindingStatus, "default" | "secondary" | "outline"> = {
  active: "default",
  investigating: "secondary",
  resolved: "outline",
};

/** How a declared field's value is shown in the table. */
function renderValue(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.join(", ") || "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function fieldLabel(module: RegistryModule, name: string): string {
  return module.fields[name]?.label || name.replace(/_/g, " ");
}

/**
 * Columns come from the module's own declaration.
 *
 * Nothing here names a module or a field: the title column is the module's
 * ``title_field``, then its declared fields in declaration order, then the
 * platform-provided context. A module declared five minutes ago renders
 * correctly, which is what the registry exists for.
 */
function columnsFor(
  module: RegistryModule,
  rows: ModuleFinding[],
  onStatusChange?: (row: ModuleFinding, status: FindingStatus) => void
): DataTableColumn<ModuleFinding>[] {
  const declared = Object.keys(module.fields);
  const titleField = module.title_field || module.dedup_fields[0] || "";
  const extra = declared.filter((name) => name !== titleField);
  // ``attributes`` is the source's own payload: show it collapsed as one column
  // rather than inventing a column per unknown key.
  const columns: DataTableColumn<ModuleFinding>[] = [
    {
      key: "title",
      title: titleField ? fieldLabel(module, titleField) : "Finding",
      minWidth: 220,
      render: (row) => (
        <span className="font-medium break-all">
          {row.payload[titleField] !== undefined
            ? renderValue(row.payload[titleField])
            : row.title}
        </span>
      ),
    },
    ...extra.map<DataTableColumn<ModuleFinding>>((name) => ({
      key: name,
      title: fieldLabel(module, name),
      minWidth: 140,
      render: (row) => <span className="break-all">{renderValue(row.payload[name])}</span>,
    })),
  ];
  if (rows.some((row) => row.payload.attributes && Object.keys(row.payload.attributes).length)) {
    columns.push({
      key: "attributes",
      title: "Source attributes",
      minWidth: 180,
      render: (row) => {
        const attributes = (row.payload.attributes || {}) as Record<string, unknown>;
        const entries = Object.entries(attributes);
        if (entries.length === 0) return <span className="text-muted-foreground">—</span>;
        return (
          <span className="text-xs text-muted-foreground break-all">
            {entries.map(([key, value]) => `${key}: ${renderValue(value)}`).join(" · ")}
          </span>
        );
      },
    });
  }
  columns.push(
    {
      key: "status",
      title: "Status",
      width: 150,
      render: (row) => {
        if (!onStatusChange) {
          return (
            <Badge variant={STATUS_VARIANTS[row.status] ?? "outline"}>
              {STATUS_LABELS[row.status] ?? row.status}
            </Badge>
          );
        }
        return (
          <select
            aria-label={`Triage status for ${row.title}`}
            className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm"
            value={row.status}
            onChange={(event) => onStatusChange(row, event.target.value as FindingStatus)}
          >
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {STATUS_LABELS[status]}
              </option>
            ))}
          </select>
        );
      },
    },
    {
      key: "matched_asset",
      title: "Matched asset",
      minWidth: 140,
      render: (row) => <span className="break-all">{row.matched_asset || "—"}</span>,
    },
    {
      key: "connector_name",
      title: "Source",
      minWidth: 120,
      render: (row) => <span className="font-mono text-xs">{row.connector_name}</span>,
    },
    {
      key: "created_at",
      title: "Detected (UTC)",
      width: 180,
      render: (row) => <span className="text-xs">{formatDateTime(row.created_at)}</span>,
    },
  );
  return columns;
}

export default function ModulePage() {
  const { moduleId = "" } = useParams();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);

  const {
    data: registry,
    isLoading: registryLoading,
    isError: registryError,
    refetch: refetchRegistry,
  } = useModules();

  const module = registry?.modules.find((item) => item.id === moduleId);

  const {
    data: findings,
    isLoading: findingsLoading,
    isFetching,
    isError: findingsError,
    refetch: refetchFindings,
  } = useQuery({
    queryKey: ["module-findings", moduleId, page, pageSize],
    queryFn: () => fetchModuleFindings(moduleId, page, pageSize),
    enabled: Boolean(module) && module?.storage === "generic",
    refetchInterval: 30_000,
  });

  const canTriage = useIsAnalystPlus();
  const qc = useQueryClient();
  const { toast } = useToast();

  const triageMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      updateFindingStatus(id, status),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["module-findings", moduleId] });
    },
    onError: (e: any) =>
      toast({
        variant: "destructive",
        title: "Could not change the status",
        description: describeApiError(e),
      }),
  });

  const rows = findings?.items || [];
  const columns = useMemo(
    () =>
      module
        ? columnsFor(
            module,
            rows,
            // Triage is a write an analyst owns; a viewer sees the state as a badge.
            canTriage
              ? (row, status) => triageMut.mutate({ id: row.id, status })
              : undefined
          )
        : [],
    // Recomputing when the page changes keeps the conditional "source
    // attributes" column in step with the rows actually on screen.
    [module, rows, canTriage, triageMut],
  );

  if (registryLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-64 rounded-lg" />
        <Skeleton className="h-[420px] w-full rounded-xl" />
      </div>
    );
  }

  if (registryError) {
    return (
      <ErrorState
        title="Module registry could not be loaded"
        description="The platform could not list its registered modules, so this page cannot know which columns to show."
        onRetry={() => refetchRegistry()}
      />
    );
  }

  if (!module) {
    return (
      <ErrorState
        title={`No module called “${moduleId}”`}
        description="This page renders whatever the platform declares, so it only exists for a registered module. Declare it under Settings → Modules, then reload."
        onRetry={() => refetchRegistry()}
      />
    );
  }

  if (module.storage === "table") {
    // Built-in modules own a page with their own enrichment and actions.
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Boxes className="w-4 h-4 text-primary" />
            {module.label}
          </CardTitle>
          <CardDescription>
            This module stores its findings in a dedicated table and has its own page.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Open the{" "}
          <Link className="underline" to={`/${module.id}`}>
            {module.label}
          </Link>{" "}
          page instead.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            {module.label}
            {!module.enabled && (
              <Badge variant="outline" className="text-[10px]">
                disabled
              </Badge>
            )}
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            {module.description ||
              `Findings collected by the platform's ${module.label} connectors.`}
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Module <span className="font-mono">{module.id}</span> · deduplicated on{" "}
            {module.dedup_fields.map((name) => fieldLabel(module, name)).join(", ")} · all
            times UTC
          </p>
        </div>
        <Button variant="outline" onClick={() => refetchFindings()} disabled={isFetching}>
          <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      <PaginatedDataTable<ModuleFinding>
        ariaLabel={`${module.label} findings`}
        storageKey={`module-${module.id}-columns`}
        columns={columns}
        rows={rows}
        total={findings?.total || 0}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        onPageSizeChange={(size: number) => {
          setPageSize(size);
          setPage(1);
        }}
        loading={findingsLoading}
        isRefreshing={isFetching && !findingsLoading}
        isError={findingsError}
        errorDescription="These findings could not be loaded, which is not the same as there being none."
        onRetry={() => refetchFindings()}
        emptyText={`No ${module.label.toLowerCase()} findings yet. Findings appear here as soon as a connector for this module reports them.`}
      />
    </div>
  );
}
