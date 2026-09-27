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
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-destructive/20 bg-destructive/5 px-6 py-10 text-center">
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
