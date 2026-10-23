import { act, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Toaster } from "@/components/ui/toaster";
import { toast } from "@/components/ui/use-toast";

/**
 * The toast host: the only surface a background failure reaches the operator on.
 *
 * Every page reports a refused request through `toast(...)`, and `main.tsx` mounts
 * this component once. Nothing rendered it in a test, so a host that dropped its
 * children would take every one of those messages with it and no page assertion
 * would notice — the pages mock `toast` itself.
 */
describe("Toaster", () => {
  it("renders the title and description of a raised toast", async () => {
    render(<Toaster />);

    act(() => {
      toast({ title: "Budget saved", description: "The direct score is now 90." });
    });

    expect(await screen.findByText("Budget saved")).toBeInTheDocument();
    expect(screen.getByText("The direct score is now 90.")).toBeInTheDocument();
  });
});
