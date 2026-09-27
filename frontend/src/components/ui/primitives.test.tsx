import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { ErrorState } from "@/components/ui/error-state";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

describe("shared UI primitives", () => {
  it("renders ErrorState with and without retry action", async () => {
    const user = userEvent.setup();
    const onRetry = vi.fn();
    const { rerender } = render(<ErrorState onRetry={onRetry} />);
    expect(screen.getByText("Unable to load data")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledOnce();

    rerender(<ErrorState title="Custom error" description="Try later" />);
    expect(screen.getByText("Custom error")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();
  });

  it("switches tab content and keeps textarea attributes and value", async () => {
    const user = userEvent.setup();
    render(
      <>
        <Tabs defaultValue="first">
          <TabsList>
            <TabsTrigger value="first">First</TabsTrigger>
            <TabsTrigger value="second">Second</TabsTrigger>
          </TabsList>
          <TabsContent value="first">First content</TabsContent>
          <TabsContent value="second">Second content</TabsContent>
        </Tabs>
        <Textarea aria-label="Notes" defaultValue="initial" disabled />
      </>,
    );
    expect(screen.getByText("First content")).toBeVisible();
    expect(screen.queryByText("Second content")).not.toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Second" }));
    expect(screen.getByText("Second content")).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Notes" })).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Notes" })).toHaveValue("initial");
  });

  it("calls cancel and confirm handlers and disables actions while loading", () => {
    const onOpenChange = vi.fn();
    const onCancel = vi.fn();
    const onConfirm = vi.fn();
    const { rerender } = render(
      <ConfirmDialog
        open
        title="Delete item?"
        description="This cannot be undone."
        onOpenChange={onOpenChange}
        onCancel={onCancel}
        onConfirm={onConfirm}
      >
        <div>Additional warning</div>
      </ConfirmDialog>,
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("Additional warning")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onCancel).toHaveBeenCalledOnce();

    fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    expect(onConfirm).toHaveBeenCalledOnce();

    rerender(
      <ConfirmDialog open title="Delete item?" onOpenChange={onOpenChange} onConfirm={onConfirm} confirmLoading />,
    );
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Confirm" })).toBeDisabled();
  });
});
