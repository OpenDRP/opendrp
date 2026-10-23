import { createContext, useContext, useEffect, useMemo, useState } from "react";

export type Theme = "dark" | "light" | "system";

type ThemeProviderProps = {
  children: React.ReactNode;
  defaultTheme?: Theme;
  storageKey?: string;
};

type ThemeProviderState = {
  theme: Theme;
  setTheme: (theme: Theme) => void;
};

const initialState: ThemeProviderState = {
  theme: "system",
  setTheme: () => null,
};

const ThemeProviderContext = createContext<ThemeProviderState>(initialState);

export function ThemeProvider({
  children,
  defaultTheme = "system",
  storageKey = "opendrp-ui-theme",
  ...props
}: ThemeProviderProps) {
  const [theme, setTheme] = useState<Theme>(() => {
    if (typeof window === "undefined") return defaultTheme;
    return (localStorage.getItem(storageKey) as Theme) || defaultTheme;
  });

  useEffect(() => {
    const root = window.document.documentElement;
    const meta = document.querySelector('meta[name="theme-color"]');

    /** Paint one scheme: the class the tokens hang off, the scheme the browser
     *  uses for its own controls, and the colour the tab strip shows. */
    const paint = (scheme: "light" | "dark") => {
      root.classList.remove("light", "dark");
      root.classList.add(scheme);
      // Native widgets — a date input's picker, a checkbox, the scrollbar of a
      // dialog — follow `color-scheme`, not our CSS variables. Without it they
      // render light-on-light inside a dark page.
      root.style.colorScheme = scheme;
      if (meta) meta.setAttribute("content", scheme === "dark" ? "#0f172a" : "#ffffff");
    };

    if (theme !== "system") {
      paint(theme);
      return;
    }

    // `system` is a question, not an answer taken once: the scheme used to be
    // read at the moment the theme changed and never again, so a console left
    // open all day kept the appearance it loaded with when the OS switched.
    if (typeof window.matchMedia !== "function") {
      paint("light");
      return;
    }
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    paint(media.matches ? "dark" : "light");

    const onChange = (event: MediaQueryListEvent) =>
      paint(event.matches ? "dark" : "light");
    if (typeof media.addEventListener === "function") {
      media.addEventListener("change", onChange);
      return () => media.removeEventListener("change", onChange);
    }
    // Safari before 14 has only the deprecated pair.
    media.addListener(onChange);
    return () => media.removeListener(onChange);
  }, [theme]);

  const value = useMemo(
    () => ({
      theme,
      setTheme: (t: Theme) => {
        if (typeof window !== "undefined") localStorage.setItem(storageKey, t);
        setTheme(t);
      },
    }),
    [theme, storageKey],
  );

  return (
    <ThemeProviderContext.Provider {...props} value={value}>
      {children}
    </ThemeProviderContext.Provider>
  );
}

export const useTheme = () => {
  const context = useContext(ThemeProviderContext);
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider");
  }
  return context;
};
