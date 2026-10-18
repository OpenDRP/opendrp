import type { ReactNode } from "react";

import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

/**
 * The three states a chart card shows *instead of* a chart, decided once.
 *
 * The failure this closes (DSH-01, and the same class on the assets page before
 * it): the cards used to test `!data?.series?.length`, which is true while the
 * query is still in flight — so the first render of the most-opened page
 * asserted "No findings recorded in the last 30 days" before the server had
 * answered, and the timeline's empty state was unreachable after it had, because
 * the server always returns 30 calendar days. `empty` is therefore decided by
 * the caller from the *meaning* of the series (the sum of its counts), never
 * from the length of the array, and loading is checked first.
 *
 * The chart area keeps its height in every state, so the page does not jump as
 * the query resolves.
 */
export function ChartState({
  loading,
  error,
  empty,
  errorText,
  emptyText,
  className,
  children,
}: {
  loading: boolean;
  error: boolean;
  empty: boolean;
  errorText: string;
  emptyText: string;
  className?: string;
  children: ReactNode;
}) {
  if (loading) {
    return (
      <div
        className={cn("flex h-full items-end gap-2 p-3", className)}
        aria-busy="true"
        data-testid="chart-loading"
      >
        <Skeleton className="h-1/3 flex-1" />
        <Skeleton className="h-2/3 flex-1" />
        <Skeleton className="h-1/2 flex-1" />
        <Skeleton className="h-3/4 flex-1" />
        <Skeleton className="h-2/5 flex-1" />
      </div>
    );
  }
  if (error) {
    return (
      <div
        className={cn(
          "flex h-full items-center justify-center px-6 text-center text-sm text-muted-foreground",
          className,
        )}
        role="alert"
      >
        {errorText}
      </div>
    );
  }
  if (empty) {
    return (
      <div
        className={cn(
          "flex h-full items-center justify-center px-6 text-center text-sm text-muted-foreground",
          className,
        )}
        role="status"
      >
        {emptyText}
      </div>
    );
  }
  return <>{children}</>;
}
