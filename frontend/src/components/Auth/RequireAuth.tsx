import { Navigate, useLocation, useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuthStore } from "@/store/auth";
import type { UserRole } from "@/types/api";
import { toast } from "@/components/ui/use-toast";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";

interface RequireAuthProps {
  children: ReactNode;
  allowedRoles?: UserRole[];
}

const ALL_ROLES: UserRole[] = ["admin", "analyst", "viewer"];

export function RequireAuth({ children, allowedRoles = ALL_ROLES }: RequireAuthProps) {
  const { user, token, isHydrated } = useAuthStore();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  useEffect(() => {
    if (isHydrated && user && !allowedRoles.includes(user.role)) {
      toast({
        variant: "destructive",
        title: "Access denied",
        description: "You do not have permission to access this page.",
      });
    }
  }, [isHydrated, user, allowedRoles]);

  if (!isHydrated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 rounded-full border-4 border-primary/30 border-t-primary animate-spin" />
          <p className="text-sm text-muted-foreground">Loading session...</p>
        </div>
      </div>
    );
  }

  if (!token || !user) {
    return <Navigate to="/login" replace />;
  }

  // Credentials that have not been put in order are not a permission problem and
  // not a session problem: the API refuses every route but one, so rendering the
  // requested screen would only produce a page of failed requests. Checked from
  // the session's own flags, which is what covers the case the redirect event
  // cannot — an administrator resetting this password while the tab is already
  // open, leaving a signed-in client that believes it has nothing pending.
  //
  // The deployment policy belongs in the same check. `mfa_required_by_policy` is
  // computed by the API from `REQUIRE_MFA_FOR_ADMINS` and whether this account has
  // a factor, and while it is set the API allows nothing but the enrolment
  // endpoints — for an administrator it is the same kind of situation as a
  // temporary password, so it takes the same route.
  const onboardingPending =
    user.must_change_password || user.must_enrol_mfa || user.mfa_required_by_policy;
  if (onboardingPending && pathname !== "/onboarding") {
    return <Navigate to="/onboarding" replace />;
  }

  if (!allowedRoles.includes(user.role)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-6">
        <div className="max-w-md w-full text-center space-y-4 p-8 border border-border rounded-2xl bg-card shadow-lg">
          <div className="mx-auto w-16 h-16 rounded-full bg-destructive/15 flex items-center justify-center">
            <svg className="w-8 h-8 text-destructive" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-foreground">403 — Forbidden</h1>
          <p className="text-muted-foreground">
            Your account does not have sufficient permissions to view this page.
            Required role: <span className="font-mono text-foreground">{allowedRoles.join(", ")}</span>
          </p>
          <Button onClick={() => navigate("/dashboard")}>
            Go to Dashboard
          </Button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
