import { useState, useRef, useEffect, useCallback } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, ListTree, ShieldAlert, AlertTriangle,
  FileBarChart, Settings2, LogOut, ShieldCheck, Users, Menu, X, Boxes, KeyRound
} from "lucide-react";
import { cn } from "@/lib/utils";
import { endpoints } from "@/lib/api";
import { useModules } from "@/hooks/useModules";
import { declaredModules } from "@/lib/modules";
import { useAuthStore, useIsAdmin } from "@/store/auth";
import { ThemeToggle } from "@/components/Theme/ThemeToggle";
import { APP_NAME, APP_TAGLINE, APP_VERSION } from "@/lib/appMeta";
import {
  Avatar, AvatarFallback
} from "@/components/ui/avatar";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem,
  DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

const navItems = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, adminOnly: false },
  { to: "/assets", label: "Assets", icon: ListTree, adminOnly: false },
  { to: "/phishing", label: "Phishing", icon: ShieldAlert, adminOnly: false },
  { to: "/breaches", label: "Breaches", icon: AlertTriangle, adminOnly: false },
  { to: "/reports", label: "Reports", icon: FileBarChart, adminOnly: false },
  // Available to every role: this is the account's own second factor, not a
  // platform setting.
  { to: "/security", label: "My security", icon: KeyRound, adminOnly: false },
  { to: "/users", label: "Users", icon: Users, adminOnly: true },
  { to: "/audit", label: "Audit Log", icon: ShieldCheck, adminOnly: true },
  { to: "/settings", label: "Settings", icon: Settings2, adminOnly: true },
];

/**
 * Navigation entries for modules declared on the core.
 *
 * Modules are data, so a module declared after this build gets a link (and a
 * page) without a frontend change. Built-in modules keep their own entries and
 * are excluded here.
 */
function moduleNavItems(modules: ReturnType<typeof declaredModules>) {
  return modules
    .filter((module) => module.enabled)
    .map((module) => ({
      to: `/modules/${module.id}`,
      label: module.label,
      icon: Boxes,
      adminOnly: false,
    }));
}

export function AppLayout() {
  const { user, logout } = useAuthStore();
  const isAdmin = useIsAdmin();
  const { data: registry } = useModules();
  // Registry-driven entries sit with the collection pages, before the
  // admin-only section, so the sidebar never reorders unexpectedly.
  const declared = moduleNavItems(declaredModules(registry?.modules));
  const adminStart = navItems.findIndex((item) => item.adminOnly);
  const allNavItems = [
    ...navItems.slice(0, adminStart < 0 ? navItems.length : adminStart),
    ...declared,
    ...navItems.slice(adminStart < 0 ? navItems.length : adminStart),
  ];
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const mobileCloseButtonRef = useRef<HTMLButtonElement>(null);

  // Move focus into the drawer when it opens and hand it back on close. The
  // menu button must NOT be focused on mount: doing so steals focus from the
  // page on every load.
  useEffect(() => {
    if (!mobileNavOpen) return;
    mobileCloseButtonRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMobileNavOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [mobileNavOpen]);

  const closeMobileNav = useCallback(() => {
    setMobileNavOpen(false);
    mobileMenuButtonRef.current?.focus();
  }, []);

  // Reflect the current section in the browser tab: the layout renders one
  // header for every route, so the title is the only navigation feedback the
  // browser itself provides.
  useEffect(() => {
    const match = allNavItems.find((item) => location.pathname.startsWith(item.to));
    document.title = match ? `${match.label} · ${APP_NAME}` : APP_NAME;
  }, [location.pathname]);

  const handleLogout = () => {
    // Locally first, because the operator asked for it and that must not depend
    // on the API being reachable. Revoking server-side follows immediately: the
    // refresh cookie is what every later load asks the API about, so a
    // browser-only sign-out would be undone by the reload that follows it.
    logout();
    void endpoints.logout();
    navigate("/login");
  };

  const initials = user?.email
    ? user.email.slice(0, 2).toUpperCase()
    : "U";

  return (
    <div className="min-h-screen flex bg-background">
      {/* Mobile drawer */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={closeMobileNav} aria-hidden="true" />
          <aside
            role="dialog"
            aria-label="Mobile navigation"
            aria-modal="true"
            className="relative w-64 max-w-[80vw] bg-sidebar border border-sidebar-border flex flex-col z-10 shadow-2xl"
          >
            <div className="h-16 flex items-center justify-between px-5 border-b border-sidebar-border">
              <div className="flex items-center gap-2">
                <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-green-500 to-green-600 flex items-center justify-center shadow-lg">
                  <ShieldCheck className="w-5 h-5 text-white" />
                </div>
                <div>
                  <div className="font-bold text-sidebar-foreground text-sm leading-tight">{APP_NAME}</div>
                  <div className="text-[11px] text-sidebar-foreground/60 leading-tight">{APP_TAGLINE}</div>
                </div>
              </div>
              <Button ref={mobileCloseButtonRef} variant="ghost" size="icon" onClick={closeMobileNav} aria-label="Close menu">
                <X className="w-5 h-5" />
              </Button>
            </div>

            <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
              {allNavItems.map(({ to, label, icon: Icon, adminOnly }) => {
                if (adminOnly && !isAdmin) return null;
                return (
                  <NavLink
                    key={to}
                    to={to}
                    onClick={closeMobileNav}
                    className={({ isActive }) => cn(
                      "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                      "text-sidebar-foreground/80 hover:text-sidebar-foreground hover:bg-sidebar-accent",
                      isActive && "bg-sidebar-primary text-sidebar-primary-foreground hover:bg-sidebar-primary hover:text-sidebar-primary-foreground"
                    )}
                  >
                    <Icon className="w-4 h-4" />
                    <span className="font-medium">{label}</span>
                  </NavLink>
                );
              })}
            </nav>

            <div className="p-3 border-t border-sidebar-border">
              <div className="px-3 py-2 rounded-md bg-sidebar-accent/40">
                <div className="text-[11px] text-sidebar-foreground/50 uppercase tracking-wider mb-1">Version</div>
                <div className="text-sm font-semibold text-sidebar-foreground">{APP_VERSION}</div>
              </div>
            </div>
          </aside>
        </div>
      )}

      {/* Desktop sidebar */}
      <aside className="hidden md:flex w-64 shrink-0 bg-sidebar border-r border-sidebar-border flex-col">
        <div className="h-16 flex items-center gap-2 px-5 border-b border-sidebar-border">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-green-500 to-green-600 flex items-center justify-center shadow-lg">
            <ShieldCheck className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="font-bold text-sidebar-foreground text-sm leading-tight">{APP_NAME}</div>
            <div className="text-[11px] text-sidebar-foreground/60 leading-tight">{APP_TAGLINE}</div>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {allNavItems.map(({ to, label, icon: Icon, adminOnly }) => {
            if (adminOnly && !isAdmin) return null;
            return (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) => cn(
                  "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
                  "text-sidebar-foreground/80 hover:text-sidebar-foreground hover:bg-sidebar-accent",
                  isActive && "bg-sidebar-primary text-sidebar-primary-foreground hover:bg-sidebar-primary hover:text-sidebar-primary-foreground"
                )}
              >
                <Icon className="w-4 h-4" />
                <span className="font-medium">{label}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="p-3 border-t border-sidebar-border">
          <div className="px-3 py-2 rounded-md bg-sidebar-accent/40">
            <div className="text-[11px] text-sidebar-foreground/50 uppercase tracking-wider mb-1">Version</div>
            <div className="text-sm font-semibold text-sidebar-foreground">{APP_VERSION}</div>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 border-b border-border bg-card/40 backdrop-blur-sm flex items-center justify-between px-4 sm:px-6 shrink-0">
          <div className="flex items-center gap-3">
            <Button
              ref={mobileMenuButtonRef}
              variant="ghost"
              size="icon"
              className="md:hidden"
              onClick={() => setMobileNavOpen(true)}
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </Button>
            {/* Not a heading: each page renders its own h1, and a second h1 in
                the shell makes the document outline ambiguous. */}
            <span className="text-base font-semibold text-foreground">{APP_NAME} Platform</span>
          </div>

          <div className="flex items-center gap-3">
            <ThemeToggle />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" className="gap-3 h-9 pl-1 pr-3 hover:bg-accent">
                  <Avatar className="w-8 h-8 border border-border">
                    <AvatarFallback className="bg-primary/15 text-primary text-xs font-semibold">
                      {initials}
                    </AvatarFallback>
                  </Avatar>
                  <div className="text-left hidden sm:block">
                    <div className="text-sm font-medium leading-tight">{user ? user.email : "Guest"}</div>
                    <div className="text-[11px] text-muted-foreground capitalize leading-tight">{user?.role || "—"}</div>
                  </div>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56">
                <DropdownMenuLabel>
                  <div className="text-sm font-medium">{user?.email}</div>
                  <div className="text-xs text-muted-foreground capitalize mt-0.5">Role: {user?.role}</div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleLogout} className="text-destructive focus:text-destructive cursor-pointer">
                  <LogOut className="w-4 h-4 mr-2" />
                  Logout
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <Separator />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto animate-in">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
