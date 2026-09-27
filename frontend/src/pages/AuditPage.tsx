import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import type { LucideIcon } from "lucide-react";
import {
  Search,
  RefreshCw,
  RotateCcw,
  Mail,
  Network,
  Clock,
  KeyRound,
  User,
  Globe,
  AlertTriangle,
  FileText,
  Wrench,
  Cpu,
  Hash,
} from "lucide-react";
import { endpoints } from "@/lib/api";
import { auditActionLabel, auditCategory, describeAuditEntry } from "@/lib/audit";
import { useDebounce } from "@/lib/useDebounce";
import { formatNumber } from "@/lib/utils";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";

const catIcons: Record<string, LucideIcon> = {
  auth: KeyRound,
  user: User,
  asset: Globe,
  phishing: AlertTriangle,
  breach: Network,
  report: FileText,
  settings: Wrench,
  scan: Cpu,
  system: Hash,
};

const catTone: Record<string, string> = {
  auth: "bg-violet-500/15 text-violet-500 border-violet-500/30",
  user: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  asset: "bg-emerald-500/15 text-emerald-500 border-emerald-500/30",
  phishing: "bg-red-500/15 text-red-500 border-red-500/30",
  breach: "bg-pink-500/15 text-pink-500 border-pink-500/30",
  report: "bg-blue-500/15 text-blue-500 border-blue-500/30",
  settings: "bg-amber-500/15 text-amber-500 border-amber-500/30",
  scan: "bg-cyan-500/15 text-cyan-500 border-cyan-500/30",
  system: "bg-gray-500/15 text-gray-500 border-gray-500/30",
};

interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  user_email?: string;
  ip_address?: string;
  details?: Record<string, any>;
}

interface AuditActionsCatalog {
  groups?: Array<{ category: string; actions: string[] }>;
  total?: number;
  actions?: string[];
  labels?: Record<string, string>;
}

export default function AuditPage() {
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [actionFilter, setActionFilter] = useState<string | undefined>();
  const [userEmail, setUserEmail] = useState("");
  const debouncedUserEmail = useDebounce(userEmail, 400);
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");

  const appliedFilters = useMemo(
    () => ({
      page,
      size,
      search: debouncedSearch || undefined,
      action: actionFilter,
      user_email: debouncedUserEmail || undefined,
      from_date: buildUtcDate(fromDate),
      to_date: toDateUtc(),
    }),
    [page, size, debouncedSearch, actionFilter, debouncedUserEmail, fromDate, toDate]
  );

  const { data: actionsData, isLoading: actionsLoading } = useQuery<AuditActionsCatalog>({
    queryKey: ["audit-actions"],
    queryFn: () => endpoints.listAuditActions(),
    staleTime: 600_000,
  });

  const groupedActions = useMemo(() => {
    const g: Record<string, { actions: string[]; defaultLabel?: string }> = {};
    const actions = actionsData?.actions ?? [];
    const labels = actionsData?.labels ?? null;

    let allActions: string[] | null = actions.length > 0 ? actions : null;

    if (!allActions) {
      const fallback: Array<{ category: string; actions: string[] }> = [
        {
          category: "auth",
          actions: [
            "auth.login.success",
            "auth.login.failure",
            "auth.logout",
            "auth.refresh.success",
            "auth.refresh.failure",
          ],
        },
        {
          category: "user",
          actions: [
            "user.created",
            "user.deleted",
            "user.updated",
            "user.password_reset",
            "user.locked",
            "user.unlocked",
          ],
        },
        {
          category: "asset",
          actions: ["asset.create", "asset.update", "asset.delete"],
        },
        {
          category: "phishing",
          actions: [
            "phishing.threat.view",
            "phishing.threat.update",
            "phishing.threat.delete",
            "phishing.scan.scheduled",
            "phishing.scan.dnstwist.start",
            "phishing.scan.shodan.start",
          ],
        },
        {
          category: "breach",
          actions: [
            "breach.list",
            "breach.view",
            "breach.update",
            "breach.delete",
            "breach.orphans.cleaned",
            "breach.scan.scheduled",
            "breach.scan.start",
            "breach.scan.email",
            "breach.scan.domain",
          ],
        },
        {
          category: "report",
          actions: [
            "report.generate",
            "report.generate.failed",
            "report.download",
            "report.delete",
          ],
        },
        {
          category: "settings",
          actions: [
            "settings.update",
            "settings.view",
            "settings.test_email_sent",
            "settings.test_email_failed",
          ],
        },
        {
          category: "system",
          actions: [
            "task.started",
            "task.completed",
            "task.failed",
            "dashboard.view",
            "audit.log.view",
            "jobs.list",
            "alert.dispatch.success",
            "alert.dispatch.failed",
          ],
        },
      ];

      for (const group of fallback) {
        if (!g[group.category]) {
          g[group.category] = { actions: group.actions, defaultLabel: group.category };
        } else {
          for (const action of group.actions) {
            if (!g[group.category]!.actions.includes(action)) {
              g[group.category]!.actions.push(action);
            }
          }
        }
      }

      allActions = Object.values(g).flatMap((item) => item.actions);
    }

    for (const action of allActions) {
      const cat = auditCategory(action);
      if (!g[cat]) {
        g[cat] = { actions: [action], defaultLabel: auditActionLabel(action, labels) };
      } else if (!g[cat]!.actions.includes(action)) {
        g[cat]!.actions.push(action);
      }
    }

    return g;
  }, [actionsData]);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["audit-logs", appliedFilters],
    queryFn: () => endpoints.listAuditLogs(appliedFilters),
    staleTime: 15_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
  });

  function resetFilters() {
    setSearch("");
    setActionFilter(undefined);
    setUserEmail("");
    setFromDate("");
    setToDate("");
    setPage(1);
  }

  function buildUtcDate(iso: string | undefined): string | undefined {
    if (!iso) return undefined;
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return undefined;
    const y = d.getUTCFullYear();
    const mo = String(d.getUTCMonth() + 1).padStart(2, "0");
    const day = String(d.getUTCDate()).padStart(2, "0");
    if (iso.length <= 10) {
      return `${y}-${mo}-${day}T00:00:00.000Z`;
    }
    return iso;
  }

  function toDateUtc(): string | undefined {
    if (!toDate) return undefined;
    const d = new Date(toDate + "T23:59:59.999Z");
    return d.toISOString();
  }

  const columns: DataTableColumn<AuditLog>[] = [
    {
      key: "timestamp",
      title: "Timestamp",
      width: 200,
      minWidth: 170,
      render: (r) => (
        <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
          <Clock className="w-3.5 h-3.5" />
          {formatDateTime(r.timestamp)}
        </div>
      ),
    },
    {
      key: "action",
      title: "Action",
      width: 220,
      minWidth: 160,
      render: (r) => {
        const cat = auditCategory(r.action);
        const Icon = catIcons[cat] ?? catIcons.system;
        return (
          <Badge variant="outline" className={catTone[cat] ?? catTone.system}>
            <Icon className="w-3 h-3 mr-1" />
            <span>{auditActionLabel(r.action, actionsData?.labels ?? null)}</span>
          </Badge>
        );
      },
    },
    {
      key: "user_email",
      title: "User Email",
      width: 220,
      minWidth: 180,
      render: (r) => (
        <div className="flex items-center gap-1.5">
          {r.user_email ? (
            <>
              <Mail className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="font-mono text-xs truncate">{r.user_email}</span>
            </>
          ) : (
            <span className="text-muted-foreground text-xs">—</span>
          )}
        </div>
      ),
    },
    {
      key: "ip_address",
      title: "IP Address",
      width: 150,
      minWidth: 130,
      render: (r) => (
        <div className="flex items-center gap-1.5">
          {r.ip_address ? (
            <>
              <Network className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="font-mono text-xs">{r.ip_address}</span>
            </>
          ) : (
            <span className="text-muted-foreground text-xs">—</span>
          )}
        </div>
      ),
    },
    {
      key: "details",
      title: "Details Summary",
      minWidth: 300,
      render: (r) => (          <div className="text-sm leading-relaxed">{describeAuditEntry(r)}</div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Audit Log</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Immutable activity trail across the platform. {TIME_ZONE_HINT}.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>

        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Filters</CardTitle>
          <CardDescription>
            Total entries:{" "}
            <span className="font-semibold text-foreground">
              {formatNumber(data?.total ?? 0)}
            </span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="relative lg:col-span-2">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                id="audit-filter-search"
                aria-label="Search audit entries"
                className="pl-9"
                placeholder="Search action, user or details..."
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <div>
              <Label
                htmlFor="audit-filter-action"
                className="text-xs text-muted-foreground mb-1 hidden md:block"
              >
                Action
              </Label>
              <Select
                value={actionFilter || "all"}
                onValueChange={(v: string) => {
                  setActionFilter(v === "all" ? undefined : v);
                  setPage(1);
                }}
              >
                <SelectTrigger id="audit-filter-action" aria-label="Filter by action">
                  <SelectValue placeholder="Any action" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All actions</SelectItem>
                  {Object.entries(groupedActions).map(([cat, group]) => (
                    /* SelectGroup/SelectLabel keep Radix keyboard navigation and
                       typeahead working; a plain <div> wrapper breaks both. */
                    <SelectGroup key={cat}>
                      <SelectLabel className="px-2 py-1.5 text-[10px] uppercase tracking-wider text-muted-foreground capitalize">
                        {cat}
                      </SelectLabel>
                      {group.actions.map((a) => (
                        <SelectItem key={a} value={a} className="text-xs">
                          {auditActionLabel(a, actionsData?.labels ?? null)}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  ))}
                </SelectContent>
              </Select>
              {actionsLoading && (
                <p className="mt-1 text-xs text-muted-foreground">Loading available actions…</p>
              )}
            </div>
            <div>
              <Label
                htmlFor="audit-filter-email"
                className="text-xs text-muted-foreground mb-1 hidden md:block"
              >
                User email
              </Label>
              <Input
                id="audit-filter-email"
                placeholder="user@example.com"
                aria-label="Filter by user email"
                value={userEmail}
                onChange={(e) => {
                  setUserEmail(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <div>
              <Label
                htmlFor="audit-filter-from"
                className="text-xs text-muted-foreground mb-1 hidden md:block"
              >
                From (UTC)
              </Label>
              <Input
                id="audit-filter-from"
                type="date"
                aria-label="Filter from date (UTC)"
                value={fromDate}
                onChange={(e) => {
                  setFromDate(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <div className="flex gap-2 items-end">
              <div className="flex-1">
                <Label
                  htmlFor="audit-filter-to"
                  className="text-xs text-muted-foreground mb-1 hidden md:block"
                >
                  To (UTC)
                </Label>
                <Input
                  id="audit-filter-to"
                  type="date"
                  aria-label="Filter to date (UTC)"
                  value={toDate}
                  onChange={(e) => {
                    setToDate(e.target.value);
                    setPage(1);
                  }}
                />
              </div>
              <Button
                variant="ghost"
                size="icon"
                onClick={resetFilters}
                title="Reset filters"
                aria-label="Reset filters"
              >
                <RotateCcw className="w-4 h-4" />
              </Button>
            </div>
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
            onPageSizeChange={(s) => {
              setSize(s);
              setPage(1);
            }}
            storageKey="audit-table-widths-v1"
            loading={isLoading}
            isError={isError}
            errorDescription="The audit trail could not be loaded. This is an evidence gap, not an empty trail."
            onRetry={() => refetch()}
            emptyText="No audit log entries match the current filters."
          />
        </CardContent>
      </Card>
    </div>
  );
}
