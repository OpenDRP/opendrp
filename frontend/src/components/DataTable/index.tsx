import * as React from "react";
import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";
import {
  Table, TableHeader, TableRow, TableHead, TableBody, TableCell,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/error-state";
import { cn } from "@/lib/utils";

export interface DataTableColumn<T = any> {
  key: string;
  title: ReactNode;
  width?: number;
  minWidth?: number;
  render?: (row: T) => ReactNode;
  align?: "left" | "right" | "center";
}

export interface PaginatedDataTableProps<T = any> {
  columns: DataTableColumn<T>[];
  rows: T[];
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (p: number) => void;
  onPageSizeChange: (s: number) => void;
  storageKey: string;
  emptyText?: string;
  loading?: boolean;
  /** Accessible label for the data table. */
  ariaLabel?: string;
  /**
   * True while a background refresh (e.g. polling) is in flight. Instead of
   * resetting the table to skeleton rows (which causes visible judder), the
   * existing rows stay mounted and the container is dimmed slightly.
   */
  isRefreshing?: boolean;
  /** Force skeleton rows even when data is already displayed (e.g. filter changes). */
  forceSkeleton?: boolean;
  /**
   * True when the query failed. With no rows to keep on screen the table is
   * replaced by an explicit error state — showing an empty table instead would
   * read as "no findings", which is a different and dangerous conclusion.
   */
  isError?: boolean;
  errorDescription?: string;
  onRetry?: () => void;
  skeletonRows?: number;
  /** Stable DOM id for a rendered data row, useful for deep-linking within a page. */
  getRowId?: (row: T, index: number) => string | undefined;
  getRowClassName?: (row: T, index: number) => string | undefined;
}

const PAGE_SIZE_OPTIONS = [10, 20, 50, 10000] as const;
const RESIZE_HANDLE_WIDTH = 6;

export function PaginatedDataTable<T = any>({
  columns,
  rows,
  total,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  storageKey,
  ariaLabel = "Data table",
  emptyText = "No items",
  loading = false,
  isRefreshing = false,
  forceSkeleton = false,
  skeletonRows = 8,
  isError = false,
  errorDescription,
  onRetry,
  getRowId,
  getRowClassName,
}: PaginatedDataTableProps<T>) {
  const pages = pageSize === 10000 ? (total > 0 ? 1 : 0) : Math.max(0, Math.ceil(total / pageSize));

  const [colWidths, setColWidths] = React.useState<Record<string, number>>(() => {
    if (typeof window === "undefined") return {};
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw) return JSON.parse(raw);
    } catch {}
    return {};
  });

  React.useEffect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(colWidths));
    } catch {}
  }, [colWidths, storageKey]);

  const resizingRef = React.useRef<{ key: string; startX: number; startWidth: number } | null>(null);

  const onMouseDown = React.useCallback((e: React.MouseEvent, key: string, currentWidth: number) => {
    e.preventDefault();
    resizingRef.current = { key, startX: e.clientX, startWidth: currentWidth };
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }, []);

  React.useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      const r = resizingRef.current;
      if (!r) return;
      const delta = e.clientX - r.startX;
      const col = columns.find(c => c.key === r.key);
      const minW = col?.minWidth ?? 60;
      const newW = Math.max(minW, r.startWidth + delta);
      setColWidths(prev => ({ ...prev, [r.key]: newW }));
    };
    const onMouseUp = () => {
      if (resizingRef.current) {
        resizingRef.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    return () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };
  }, [columns]);

  function getColWidth(col: DataTableColumn<T>): number {
    if (colWidths[col.key]) return colWidths[col.key];
    return col.width ?? 150;
  }

  const pageNumbers = React.useMemo(() => {
    if (pages <= 0) return [];
    const window = 2;
    const result: (number | "...")[] = [];
    let start = Math.max(1, page - window);
    let end = Math.min(pages, page + window);
    if (start > 1) {
      result.push(1);
      if (start > 2) result.push("...");
    }
    for (let i = start; i <= end; i++) result.push(i);
    if (end < pages) {
      if (end < pages - 1) result.push("...");
      result.push(pages);
    }
    return result;
  }, [page, pages]);

  // Keep already-rendered rows mounted during background refreshes: only show
  // the skeleton on the initial load (or when explicitly forced). This prevents
  // the "page reload" judder caused by periodic polling.
  const hasData = rows.length > 0;
  const showSkeleton = loading && (forceSkeleton || !hasData);

  const SkeletonRow = (
    <TableRow>
      {columns.map(c => (
        <TableCell key={c.key} style={{ width: getColWidth(c), minWidth: c.minWidth ?? 60 }}>
          <div className="h-5 w-full rounded animate-pulse bg-muted" style={{ maxWidth: c.width ? c.width * 0.8 : undefined }} />
        </TableCell>
      ))}
    </TableRow>
  );

  if (isError && !hasData) {
    return (
      <ErrorState
        title="Could not load this list"
        description={
          errorDescription ??
          "The data could not be retrieved, so this table is not showing an empty result set."
        }
        onRetry={onRetry}
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="relative">
        <div className="pointer-events-none absolute right-0 top-0 bottom-0 z-10 w-8 bg-gradient-to-l from-background to-transparent sm:hidden" aria-hidden="true" />
        <div
          aria-busy={isRefreshing}
          className={cn(
            "rounded-md border transition-opacity duration-300 overflow-x-auto",
            isRefreshing && hasData && "opacity-70"
          )}
        >
        <Table aria-label={ariaLabel} style={{ tableLayout: "fixed" }}>
          <TableHeader>
            <TableRow>
              {columns.map(col => {
                const w = getColWidth(col);
                return (
                  <TableHead
                    key={col.key}
                    style={{ width: w, minWidth: col.minWidth ?? 60 }}
                    className={cn(
                      "relative",
                      col.align === "right" && "text-right",
                      col.align === "center" && "text-center"
                    )}
                  >
                    <div
                      className={cn(
                        col.align === "right" && "flex justify-end",
                        col.align === "center" && "flex justify-center"
                      )}
                    >
                      {col.title}
                    </div>
                    <div
                      role="separator"
                      aria-label={`Resize ${String(col.title)} column`}
                      tabIndex={0}
                      onMouseDown={(e) => onMouseDown(e, col.key, w)}
                      onKeyDown={(e) => {
                        if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
                        e.preventDefault();
                        const delta = e.key === "ArrowRight" ? 16 : -16;
                        const minW = col.minWidth ?? 60;
                        setColWidths(prev => ({ ...prev, [col.key]: Math.max(minW, w + delta) }));
                      }}
                      className="absolute top-0 right-0 h-full cursor-col-resize select-none touch-none z-10 hover:bg-primary/30 transition-colors"
                      style={{ width: RESIZE_HANDLE_WIDTH }}
                    />
                  </TableHead>
                );
              })}
            </TableRow>
          </TableHeader>
          <TableBody>
            {showSkeleton && Array.from({ length: skeletonRows }).map((_, i) => (
              <React.Fragment key={i}>{SkeletonRow}</React.Fragment>
            ))}
            {!showSkeleton && rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={columns.length} className="py-12 text-center text-muted-foreground">
                  {emptyText}
                </TableCell>
              </TableRow>
            )}
            {!showSkeleton && rows.map((row: any, ri) => (
              <TableRow key={row.id ?? ri} id={getRowId?.(row, ri)} className={getRowClassName?.(row, ri)}>
                {columns.map(col => (
                  <TableCell
                    key={col.key}
                    style={{ width: getColWidth(col), minWidth: col.minWidth ?? 60 }}
                    className={cn(
                      col.align === "right" && "text-right",
                      col.align === "center" && "text-center"
                    )}
                  >
                    {col.render ? col.render(row) : (row as any)[col.key]}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
        </div>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 px-1">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <span>Items per page:</span>
          <Select
            value={String(pageSize)}
            onValueChange={(v) => {
              const n = Number(v);
              onPageSizeChange(n);
              if (n === 10000) onPageChange(1);
            }}
          >
            <SelectTrigger className="w-[110px] h-8" aria-label="Items per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZE_OPTIONS.map(s => (
                <SelectItem key={s} value={String(s)}>
                  {s === 10000 ? "All" : s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="hidden sm:inline">
            {total > 0 ? (
              <>
                Showing{" "}
                <span className="font-medium text-foreground">
                  {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)}
                </span>{" "}
                of <span className="font-medium text-foreground">{total}</span>
              </>
            ) : (
              <>0 of <span className="font-medium text-foreground">{total}</span></>
            )}
          </span>
        </div>

        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => onPageChange(1)}
            disabled={page <= 1 || pages === 0}
            aria-label="First page"
          >
            <ChevronsLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1 || pages === 0}
            aria-label="Previous page"
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>

          <div className="flex items-center gap-0.5 mx-1">
            {pageNumbers.map((pn, i) =>
              pn === "..." ? (
                <span key={`e${i}`} className="px-2 text-xs text-muted-foreground">…</span>
              ) : (
                <Button
                  key={pn}
                  variant={pn === page ? "default" : "outline"}
                  size="sm"
                  className="h-8 min-w-[32px] px-2 text-xs"
                  onClick={() => onPageChange(pn)}
                >
                  {pn}
                </Button>
              )
            )}
          </div>

          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => onPageChange(page + 1)}
            disabled={pages === 0 || page >= pages}
            aria-label="Next page"
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => onPageChange(pages)}
            disabled={pages === 0 || page >= pages}
            aria-label="Last page"
          >
            <ChevronsRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
}
