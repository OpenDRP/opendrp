import { useEffect } from "react";
import { Routes, Route, Navigate, useLocation, useNavigate } from "react-router-dom";
import { AppLayout } from "@/components/Layout/AppLayout";
import { RequireAuth } from "@/components/Auth/RequireAuth";
import { useAuthStore } from "@/store/auth";
import { endpoints } from "@/lib/api";
import { toast } from "@/components/ui/use-toast";

import LoginPage from "@/pages/LoginPage";
import DashboardPage from "@/pages/DashboardPage";
import AssetsPage from "@/pages/AssetsPage";
import PhishingPage from "@/pages/PhishingPage";
import BreachesPage from "@/pages/BreachesPage";
import ReportsPage from "@/pages/ReportsPage";
import SecurityPage from "@/pages/SecurityPage";
import OnboardingPage from "@/pages/OnboardingPage";
import ModulePage from "@/pages/ModulePage";
import SettingsPage from "@/pages/SettingsPage";
import UsersPage from "@/pages/UsersPage";
import AuditPage from "@/pages/AuditPage";
import NotFoundPage from "@/pages/NotFoundPage";

/** The `/logout` route: end the session here and at the API, then show the form.
 *
 *  The revocation is not optional. Every later load asks the API whether this
 *  browser is still signed in, so clearing only the client would be undone by the
 *  first reload after the operator believed they had signed out. The local clear
 *  comes first, so that reaching this route always signs out even when the call
 *  fails.
 */
function LogoutHandler() {
  const navigate = useNavigate();
  const logout = useAuthStore((s) => s.logout);
  useEffect(() => {
    logout();
    void endpoints.logout();
    navigate("/login", { replace: true });
  }, [logout, navigate]);
  return null;
}

/** Listens for 401 events from the Axios interceptor and navigates via React Router
 *  to avoid a hard location.href redirect that causes a white screen.
 *
 *  The interceptor only emits this event for a session that was actually in
 *  use, so it is safe to explain why the operator is back at the sign-in page.
 */
function UnauthorizedRedirect() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  useEffect(() => {
    const handler = () => {
      // A 401 raised while already on the sign-in page is a rejected attempt,
      // not an expired session — the page shows its own message for that.
      if (pathname !== "/login") {
        toast({
          variant: "destructive",
          title: "Session expired",
          description: "You were signed out because the session could no longer be verified. Sign in again to continue.",
        });
      }
      navigate("/login", { replace: true });
    };
    window.addEventListener("auth:unauthorized", handler);
    return () => window.removeEventListener("auth:unauthorized", handler);
  }, [navigate, pathname]);
  return null;
}

/** Sends a session to the page that puts its credentials in order.
 *
 *  Two 403s mean "this account owes something before the rest of the platform
 *  opens", and both are policy gates rather than permission errors:
 *
 *  * `auth:onboarding-required` — a password assigned *for* this account, or a
 *    second factor cleared for it (`app/api/deps.py`);
 *  * `auth:mfa-required` — `REQUIRE_MFA_FOR_ADMINS=true` and an administrator
 *    without an enrolled factor, which refuses admin routes only.
 *
 *  Both land on `/onboarding`, which is neither an admin route nor part of the
 *  application shell, and which is on the API's allowlist while either gate is up.
 *  The two are otherwise different in the trail — the second is audited because an
 *  administrator acting without a factor is a security signal — and they differ in
 *  what the operator is told happened, which is why the event decides the toast.
 *  Which *step* is needed is not decided here: the API computes both gates on the
 *  user it returns, so the page reads them rather than being told.
 *
 *  Navigating when already there is skipped: the page's own error handling
 *  explains a failed step, and a redirect on top of it would replace that message
 *  with a toast about a redirect the operator cannot escape.
 */
function OnboardingRedirect() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  useEffect(() => {
    const handler = (reason: "onboarding" | "mfa") => () => {
      if (pathname === "/onboarding") return;
      toast({
        variant: "destructive",
        title: reason === "mfa" ? "Second factor required" : "Finish setting up your account",
        description:
          reason === "mfa"
            ? "This installation requires administrators to use an authenticator app. Enrol one here to reach the rest of the platform."
            : "This account has to replace a password set by somebody else before the rest of the platform opens.",
      });
      navigate("/onboarding", { replace: true });
    };
    const onboarding = handler("onboarding");
    const mfa = handler("mfa");
    window.addEventListener("auth:onboarding-required", onboarding);
    window.addEventListener("auth:mfa-required", mfa);
    return () => {
      window.removeEventListener("auth:onboarding-required", onboarding);
      window.removeEventListener("auth:mfa-required", mfa);
    };
  }, [navigate, pathname]);
  return null;
}

export default function App() {
  return (
    <>
      {/* Renders null — listens for auth:unauthorized event from the Axios interceptor
          and navigates via React Router so we avoid location.href (white screen). */}
      <UnauthorizedRedirect />
      {/* Same shape, for a 403 that is a policy gate rather than a permission. */}
      <OnboardingRedirect />

      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/logout" element={<LogoutHandler />} />

        {/* Outside the application shell on purpose: an account that owes a
            credential can reach nothing else, and a navigation bar full of
            screens it cannot open would be an invitation to file a support
            ticket. The page offers sign-out, which is the one other thing a
            session in this state should be able to do. */}
        <Route
          path="/onboarding"
          element={
            <RequireAuth>
              <OnboardingPage />
            </RequireAuth>
          }
        />

        <Route
          element={
            <RequireAuth>
              <AppLayout />
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="phishing" element={<PhishingPage />} />
          <Route path="breaches" element={<BreachesPage />} />
          <Route path="reports" element={<ReportsPage />} />
          {/* Every role, not only administrators: an analyst's account is worth
              as much to an attacker as an admin's, and the second factor has to
              be enroleable by whoever owns the account. */}
          <Route path="security" element={<SecurityPage />} />
          {/* Modules declared as data render from their own declaration. */}
          <Route path="modules/:moduleId" element={<ModulePage />} />
          <Route
            path="users"
            element={
              <RequireAuth allowedRoles={["admin"]}>
                <UsersPage />
              </RequireAuth>
            }
          />
          <Route
            path="audit"
            element={
              <RequireAuth allowedRoles={["admin"]}>
                <AuditPage />
              </RequireAuth>
            }
          />
          <Route
            path="settings"
            element={
              <RequireAuth allowedRoles={["admin"]}>
                <SettingsPage />
              </RequireAuth>
            }
          />
        </Route>

        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </>
  );
}
