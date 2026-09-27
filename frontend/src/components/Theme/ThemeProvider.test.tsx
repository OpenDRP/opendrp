import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ThemeProvider, useTheme } from "@/components/Theme/ThemeProvider";
import { ThemeToggle } from "@/components/Theme/ThemeToggle";

vi.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div role="menu">{children}</div>,
  DropdownMenuItem: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => <button role="menuitem" onClick={onClick}>{children}</button>,
}));

function ThemeProbe() {
  const { theme } = useTheme();
  return <span data-testid="theme-value">{theme}</span>;
}

function renderTheme(defaultTheme: "light" | "dark" | "system" = "light") {
  return render(
    <ThemeProvider defaultTheme={defaultTheme} storageKey="test-theme">
      <ThemeProbe />
      <ThemeToggle />
    </ThemeProvider>,
  );
}

describe("ThemeProvider and ThemeToggle", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.className = "";
    document.head.innerHTML = '<meta name="theme-color" content="">';
  });

  it("applies the default theme and persists a selected theme", () => {
    renderTheme();
    expect(screen.getByTestId("theme-value")).toHaveTextContent("light");
    expect(document.documentElement).toHaveClass("light");
    expect(document.querySelector('meta[name="theme-color"]')).toHaveAttribute("content", "#ffffff");

    fireEvent.click(screen.getByRole("menuitem", { name: "Dark" }));
    expect(screen.getByTestId("theme-value")).toHaveTextContent("dark");
    expect(document.documentElement).toHaveClass("dark");
    expect(localStorage.getItem("test-theme")).toBe("dark");
    expect(document.querySelector('meta[name="theme-color"]')).toHaveAttribute("content", "#0f172a");
  });

  it("restores a stored theme before rendering", () => {
    localStorage.setItem("test-theme", "dark");
    renderTheme();
    expect(screen.getByTestId("theme-value")).toHaveTextContent("dark");
    expect(document.documentElement).toHaveClass("dark");
  });
});
