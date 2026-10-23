import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "@/components/ErrorBoundary";

function Broken(): never {
  throw new Error("render failure");
}

describe("ErrorBoundary", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
  });

  it("renders children when no error occurs", () => {
    render(
      <ErrorBoundary>
        <div>healthy content</div>
      </ErrorBoundary>,
    );
    expect(screen.getByText("healthy content")).toBeInTheDocument();
  });

  it("renders the recovery UI and can reset after an error", () => {
    const { rerender } = render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>,
    );

    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.getByText("render failure")).toBeInTheDocument();

    rerender(
      <ErrorBoundary>
        <div>recovered content</div>
      </ErrorBoundary>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(screen.getByText("recovered content")).toBeInTheDocument();
  });

  /**
   * A render error replaces the tree, and the element that had focus goes with it:
   * focus falls back to `<body>`. The recovery screen was a plain box, so neither
   * the message nor the fact that the page had changed reached a screen reader, and
   * a keyboard user was left tabbing from the top of a page whose explanation was
   * above them.
   */
  it("announces the recovery screen and moves focus into it", () => {
    render(
      <ErrorBoundary>
        <Broken />
      </ErrorBoundary>,
    );

    const recovery = screen.getByRole("alert");
    expect(recovery).toHaveTextContent("Something went wrong");
    expect(recovery).toHaveFocus();
  });

  it("uses a custom fallback when provided", () => {
    render(
      <ErrorBoundary fallback={<div>custom fallback</div>}>
        <Broken />
      </ErrorBoundary>,
    );
    expect(screen.getByText("custom fallback")).toBeInTheDocument();
    expect(screen.queryByText("Something went wrong")).not.toBeInTheDocument();
  });
});
