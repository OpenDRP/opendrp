import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export function ErrorState({
  title = "Unable to load data",
  description = "Something went wrong while loading this section.",
  onRetry,
}: {
  title?: string;
  description?: string;
  onRetry?: () => void;
}) {
  return (
    // `role="alert"` (an assertive live region) rather than a plain box: every
    // caller renders this *instead of* the data, so the failure arrives without a
    // page navigation and a screen reader would otherwise be told nothing — the
    // table or card it replaced simply disappears. The retry button stays inside
    // the region, so the recovery action is announced with the failure.
    <div
      role="alert"
      className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/20 bg-destructive/5 px-6 py-10 text-center"
    >
      <AlertTriangle className="h-8 w-8 text-destructive" aria-hidden="true" />
      <div>
        <h3 className="font-semibold">{title}</h3>
        <p className="mt-1 text-sm text-muted-foreground">{description}</p>
      </div>
      {onRetry && (
        <Button type="button" variant="outline" onClick={onRetry}>
          <RefreshCw className="mr-2 h-4 w-4" aria-hidden="true" />
          Try again
        </Button>
      )}
    </div>
  );
}
