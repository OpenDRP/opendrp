import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Loader2, LogOut, ShieldCheck } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useAuthStore } from "@/store/auth";
import { MfaEnrolment } from "@/components/Auth/MfaEnrolment";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "@/components/ui/use-toast";

/**
 * The page that puts a credential in order, and the only one reachable while one
 * is out of order (see app/api/deps.py).
 *
 * Two situations land here, and they can arrive together:
 *
 * * **A password somebody else chose.** An administrator created the account or
 *   reset it, so the password is in a chat message, a ticket or a shell history.
 *   The account holder replaces it with one only they know.
 * * **A second factor that was removed for this account.** Recovery must not be a
 *   downgrade, so the factor is enrolled again before anything else opens.
 * * **A second factor this installation requires and this account does not have.**
 *   `REQUIRE_MFA_FOR_ADMINS` applies to administrator accounts, and the API
 *   computes it per response (`mfa_required_by_policy`) instead of storing it on
 *   the account, because it is a property of the deployment. It is the same gate
 *   as the other two: while it is set, nothing but the enrolment endpoints opens,
 *   so it is the first sign-in that asks for a factor rather than the first admin
 *   page.
 *
 * The order is the server's, not the page's: the enrolment endpoints re-check the
 * password, so while a temporary one is in force they are refused. Replacing the
 * password first is therefore the only sequence that works — and the only one that
 * makes sense, since the factor would otherwise be bound to a credential its owner
 * is about to discard.
 */
export default function OnboardingPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const user = useAuthStore((s) => s.user);
  const setUser = useAuthStore((s) => s.setUser);
  const setSession = useAuthStore((s) => s.setSession);
  const logout = useAuthStore((s) => s.logout);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  // The authoritative flags. The store's copy can predate an administrator's
  // reset — that is exactly the case where the API starts refusing a session that
  // believes it has nothing pending — and this endpoint is reachable while the
  // gate is up, so it is also what corrects the store.
  const me = useQuery({ queryKey: ["auth-me"], queryFn: endpoints.me });

  useEffect(() => {
    if (me.data) setUser(me.data);
  }, [me.data, setUser]);

  const changePassword = useMutation({
    mutationFn: () => endpoints.changePassword(currentPassword, newPassword),
    onSuccess: (data) => {
      // The API rotates the session with the password: the old refresh cookie was
      // just revoked, so keeping the old token would break the next request.
      setSession(data);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setFormError(null);
      // `/auth/me` answered before this change, and the answer is cached: leaving it
      // there would let a return to this page within the cache's lifetime restore
      // the account's *old* flags into the store and re-open a step that is done.
      void queryClient.invalidateQueries({ queryKey: ["auth-me"] });
      toast({
        title: "Password changed",
        description: "Your other sessions were signed out. Keep this one — it is the only one left.",
      });
      // Straight into the platform when nothing else is owed, so finishing the
      // flow is one action rather than one action plus a click. A factor is owed
      // whenever the account was cleared for one (`must_enrol_mfa`) or the
      // deployment requires one and this account has none — the API computes the
      // latter on the user it just returned, so the page does not have to guess.
      if (data.user.must_enrol_mfa !== true && data.user.mfa_required_by_policy !== true) {
        navigate("/dashboard", { replace: true });
      }
    },
    onError: (error) => {
      setFormError(describeApiError(error, "Could not change the password."));
    },
  });

  if (!user) {
    return null;
  }

  const passwordPending = user.must_change_password === true;
  const mfaPending = user.must_enrol_mfa === true;
  // The deployment policy is not a flag on the account: the API computes it from
  // the installation's setting and whether this account has a factor, and it is
  // therefore already true on the response that signed this session in. Which of
  // the two reasons applies only changes what the step explains — never whether
  // a factor has to be enrolled.
  const policyMfa = user.mfa_required_by_policy === true;
  const mfaStep = mfaPending || policyMfa;
  // Until the flags are known, neither step can be chosen: rendering "nothing
  // pending" and then asking for a password a moment later is worse than waiting.
  const resolving = me.isLoading && !passwordPending && !mfaPending && !policyMfa;

  const submitPassword = (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    if (!currentPassword) {
      setFormError("Enter the password you signed in with.");
      return;
    }
    if (newPassword.length < 12) {
      setFormError("The new password must be at least 12 characters long.");
      return;
    }
    if (!/[A-Z]/.test(newPassword)) {
      setFormError("The new password must contain at least one uppercase letter (A-Z).");
      return;
    }
    if (!/[0-9]/.test(newPassword)) {
      setFormError("The new password must contain at least one digit (0-9).");
      return;
    }
    if (newPassword !== confirmPassword) {
      setFormError("The two new passwords do not match.");
      return;
    }
    if (newPassword === currentPassword) {
      setFormError("The new password must be different from the current one.");
      return;
    }
    changePassword.mutate();
  };

  const finishMfaStep = async () => {
    // The flag clears server-side when the code verifies; the store has to be
    // told, or the route guard would send this account straight back here.
    try {
      const fresh = await endpoints.me();
      setUser(fresh);
    } catch {
      // The next request re-reads it anyway; failing to refresh must not strand
      // the operator on a page whose work is done.
    }
    toast({
      title: "Account ready",
      description: "Your credentials are in order. Welcome to the platform.",
    });
    navigate("/dashboard", { replace: true });
  };

  const signOut = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-2xl space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <KeyRound className="w-6 h-6 text-primary" />
              Your account needs one step
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              {user.email} · the rest of the platform opens as soon as this is done
            </p>
          </div>
          <Button variant="ghost" onClick={signOut}>
            <LogOut className="w-4 h-4 mr-2" />
            Sign out
          </Button>
        </div>

        {resolving ? (
          <Card>
            <CardContent className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" /> Checking what this account still owes...
            </CardContent>
          </Card>
        ) : passwordPending ? (
          <Card>
            <CardHeader>
              <CardTitle as="h2" className="text-lg">
                Choose your own password
              </CardTitle>
              <CardDescription>
                The password you signed in with was set for you — by the installation wizard, the
                administrator CLI, or an administrator resetting it. Whoever typed it still knows it,
                so it stops working for you here.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* noValidate: the messages belong in the product language and in one
                  place, not in OS-language browser bubbles. */}
              <form onSubmit={submitPassword} noValidate className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="current-password">Current (temporary) password</Label>
                  <Input
                    id="current-password"
                    type="password"
                    autoComplete="current-password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    disabled={changePassword.isPending}
                    autoFocus
                  />
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="new-password">New password</Label>
                    <Input
                      id="new-password"
                      type="password"
                      autoComplete="new-password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      disabled={changePassword.isPending}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="confirm-password">Repeat new password</Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      autoComplete="new-password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      disabled={changePassword.isPending}
                    />
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">
                  At least 12 characters, with one uppercase letter and one digit. Changing the
                  password signs out every other session of this account.
                </p>
                {formError && <p className="text-sm text-destructive">{formError}</p>}
                <Button type="submit" disabled={changePassword.isPending}>
                  {changePassword.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                  Save new password
                </Button>
              </form>
              <p className="text-xs text-muted-foreground mt-4">
                Do not have the temporary password? It has to come from whoever reset the account:
                ask your administrator to reset it again and tell you the value, then sign in with
                that one to choose your own here.
              </p>
            </CardContent>
          </Card>
        ) : mfaStep ? (
          <Card>
            <CardHeader>
              <CardTitle as="h2" className="text-lg flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-primary" />
                Enrol an authenticator app
              </CardTitle>
              <CardDescription>
                {mfaPending
                  ? "The second factor on this account was cleared for you — a lost device, or an administrator resetting it. A new one is required before the rest of the platform opens, so a recovery never leaves the account weaker than it was."
                  : "This installation requires administrators to use an authenticator app. Enrol one here to reach the rest of the platform."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <MfaEnrolment onEnrolled={finishMfaStep} autoFocusCode />
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader>
              <CardTitle as="h2" className="text-lg">
                Nothing is pending
              </CardTitle>
              <CardDescription>
                This account has no password change waiting and no factor to enrol. You can continue
                to the platform — voluntary changes stay on My security.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button onClick={() => navigate("/dashboard", { replace: true })}>
                Continue to the platform
              </Button>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
