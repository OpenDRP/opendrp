import * as React from "react";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  onConfirm: () => void;
  onCancel?: () => void;
  variant?: "default" | "destructive";
  confirmLoading?: boolean;
  /**
   * Keeps the confirm action unavailable until its condition is met (WI-23): a
   * destructive cascade asks the operator to type the asset's value, and a
   * disabled button is what says so before the click rather than after it.
   */
  confirmDisabled?: boolean;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  onConfirm,
  onCancel,
  variant = "default",
  confirmLoading = false,
  confirmDisabled = false,
}: ConfirmDialogProps) {
  const handleCancel = React.useCallback(() => {
    onOpenChange(false);
    onCancel?.();
  }, [onOpenChange, onCancel]);

  const handleConfirm = React.useCallback(() => {
    onConfirm();
  }, [onConfirm]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        {children && <div className="py-2">{children}</div>}
        <DialogFooter className="sm:justify-end flex-col-reverse sm:flex-row gap-2 sm:gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={handleCancel}
            disabled={confirmLoading}
          >
            {cancelLabel}
          </Button>
          <Button
            type="button"
            variant={variant === "destructive" ? "destructive" : "default"}
            onClick={handleConfirm}
            disabled={confirmLoading || confirmDisabled}
          >
            {confirmLoading ? (
              <>
                <span className="h-4 w-4 rounded-full border-2 border-current border-r-transparent animate-spin" />
                {confirmLabel}
              </>
            ) : (
              confirmLabel
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
