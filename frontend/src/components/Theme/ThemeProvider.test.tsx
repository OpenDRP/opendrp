import { act, fireEvent, render, screen } from "@testing-library/react";
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

  /**
   * "System" is a question with a live answer.
   *
   * The scheme was read once, at the moment the theme changed, and never again:
   * a console left open across sunset kept the appearance it loaded with, and the
   * browser kept `color-scheme: light` for its own controls — the date inputs on
   * the audit page, a dialog's scrollbar — inside a page that had gone dark.
   */
  it("follows the system scheme while it is selected, and tells the browser which one", () => {
    const media = stubMatchMedia({ dark: false });
    renderTheme("system");

    expect(document.documentElement).toHaveClass("light");
    expect(document.documentElement.style.colorScheme).toBe("light");

    act(() => media.emit({ dark: true }));
    expect(document.documentElement).toHaveClass("dark");
    expect(document.documentElement.style.colorScheme).toBe("dark");
    expect(document.querySelector('meta[name="theme-color"]')).toHaveAttribute("content", "#0f172a");

    act(() => media.emit({ dark: false }));
    expect(document.documentElement).toHaveClass("light");
    expect(document.documentElement.style.colorScheme).toBe("light");
  });

  it("stops listening to the system once a fixed theme is chosen", () => {
    const media = stubMatchMedia({ dark: true });
    renderTheme("system");
    expect(document.documentElement).toHaveClass("dark");

    fireEvent.click(screen.getByRole("menuitem", { name: "Light" }));
    expect(media.listenerCount()).toBe(0);
    act(() => media.emit({ dark: false }));
    expect(document.documentElement).toHaveClass("light");
  });
});

/**
 * jsdom has no `matchMedia`, and the component asks one question of it: does this
 * query match now, and will it tell me when that changes?
 */
function stubMatchMedia(initial: { dark: boolean }) {
  const listeners = new Set<(event: MediaQueryListEvent) => void>();
  const state = { ...initial };
  const query = {
    get matches() {
      return state.dark;
    },
    addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
      listeners.add(listener);
    },
    removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => {
      listeners.delete(listener);
    },
  };
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: vi.fn(() => query),
  });
  return {
    emit(next: { dark: boolean }) {
      state.dark = next.dark;
      listeners.forEach((listener) => listener({ matches: next.dark } as MediaQueryListEvent));
    },
    listenerCount: () => listeners.size,
  };
}
