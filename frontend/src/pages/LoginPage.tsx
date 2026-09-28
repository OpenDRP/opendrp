import { useEffect, useState } from "react";
import { useNavigate, useLocation, Navigate } from "react-router";
import { ShieldCheck, Eye, EyeOff, Loader2 } from "lucide-react";
import { describeApiError } from "@/lib/api";
import { APP_NAME, APP_TAGLINE } from "@/lib/appMeta";
import { useAuthStore } from "@/store/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "@/components/ui/use-toast";

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, token, isHydrated } = useAuthStore();

  // Intentionally empty: no demo/default credentials are pre-filled on a
  // production surface (stale defaults mislead operators).
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  // The second factor is requested only after the API has verified the password
  // and said a code is required. Asking up front would tell anyone who types an
  // address whether that account uses MFA.
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [useRecoveryCode, setUseRecoveryCode] = useState(false);

  const from = (location.state as { from?: string })?.from || "/dashboard";

  useEffect(() => {
    document.title = `Sign in · ${APP_NAME}`;
  }, []);

  if (isHydrated && token) {
    return <Navigate to={from} replace />;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = email.trim();
    if (!trimmed || !password) {
      toast({ variant: "destructive", title: "Validation error", description: "Email and password are required." });
      return;
    }
    if (mfaRequired && (useRecoveryCode ? !recoveryCode.trim() : !mfaCode.trim())) {
      toast({
        variant: "destructive",
        title: "Validation error",
        description: useRecoveryCode ? "Enter a recovery code." : "Enter the six-digit code from your authenticator app.",
      });
      return;
    }
    // Deliberately permissive: internal deployments use names such as
    // user@corp.local, so the server keeps the final say on the address shape.
    if (!/^[^\s@]+@[^\s@]+$/.test(trimmed)) {
      toast({
        variant: "destructive",
        title: "Validation error",
        description: "Enter an email address in the form user@example.com or user@corp.local.",
      });
      return;
    }

    setLoading(true);
    try {
      const signedIn = mfaRequired
        ? useRecoveryCode
          ? await login(trimmed, password, undefined, recoveryCode.trim())
          : await login(trimmed, password, mfaCode.trim())
        : await login(trimmed, password);
      // An account that owes a credential step goes straight to the page that
      // asks for it: `from` would only render screens the API is about to refuse,
      // and the route guard would bounce the operator here a moment later anyway.
      //
      // The third case is the deployment policy: `REQUIRE_MFA_FOR_ADMINS` with no
      // factor enrolled on an administrator account. The API computes that on the
      // user it just returned, so a fresh sign-in knows about it without waiting
      // for a route to be refused first — which is the difference between being
      // asked for a second factor at the first sign-in and being asked the first
      // time somebody opens an admin page.
      if (
        signedIn.must_change_password ||
        signedIn.must_enrol_mfa ||
        signedIn.mfa_required_by_policy
      ) {
        toast({
          title: "One step left",
          description: signedIn.must_change_password
            ? "This account has to set its own password before the platform opens."
            : signedIn.must_enrol_mfa
              ? "A new authenticator app has to be enrolled before the platform opens."
              : "This installation requires administrators to use an authenticator app. Enrol one to reach the rest of the platform.",
        });
        navigate("/onboarding", { replace: true });
        return;
      }
      toast({ title: "Welcome back", description: "You have successfully signed in." });
      navigate(from, { replace: true });
    } catch (err: any) {
      const status = err?.response?.status;
      // `detail` can be a string or a list of validation objects; it must be
      // flattened before it reaches a React node (see describeApiError).
      const description = describeApiError(err, "Invalid email or password.");

      // The API asks for a code only after the password verified, so this is a
      // prompt rather than a failure: keep the typed credentials and reveal the
      // field instead of making the operator re-enter everything.
      if (status === 401 && description.includes("MFA code required")) {
        setMfaRequired(true);
        setMfaCode("");
        toast({
          title: "Second factor required",
          description: "Enter the current code from your authenticator app.",
        });
      } else {
        // A rejected code is a rejected sign-in, and a stale code has to be
        // replaced rather than resubmitted.
        if (mfaRequired && status === 401) setMfaCode("");
        toast({
          variant: "destructive",
          title: status === 429 ? "Too many sign-in attempts" : "Sign in failed",
          description,
        });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background to-muted/40 p-4">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 rounded-full bg-primary/10 blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 rounded-full bg-primary/5 blur-3xl" />
      </div>

      <div className="relative w-full max-w-md">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 w-16 h-16 rounded-2xl bg-gradient-to-br from-green-500 to-green-600 flex items-center justify-center shadow-2xl shadow-primary/30 motion-safe:animate-pulse-glow">
            <ShieldCheck className="w-9 h-9 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-foreground tracking-tight">{APP_NAME}</h1>
          <p className="text-sm text-muted-foreground mt-1">{APP_TAGLINE}</p>
        </div>

        <Card className="border-border/60 shadow-xl bg-card/90 backdrop-blur">
          <CardHeader>
            <CardTitle as="h2" className="text-xl">Sign in</CardTitle>
            <CardDescription>Enter your credentials to access the platform.</CardDescription>
          </CardHeader>
          <CardContent>
            {/* noValidate: keep all validation messages in the product language
                and in one place instead of OS-language browser bubbles. */}
            <form onSubmit={handleSubmit} noValidate className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  autoComplete="email"
                  placeholder="user@example.com"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    // A different account may not have a second factor: drop the
                    // prompt rather than demanding a code for someone else.
                    setMfaRequired(false);
                    setMfaCode("");
                    setRecoveryCode("");
                    setUseRecoveryCode(false);
                  }}
                  disabled={loading}
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password">Password</Label>
                </div>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    placeholder="••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={loading}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    disabled={loading}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {mfaRequired && (
                <div className="space-y-2">
                  <Label htmlFor="mfa-code">Authenticator code</Label>
                  <Input
                    id="mfa-code"
                    // `one-time-code` lets a mobile browser or password manager
                    // offer the current code; inputMode keeps a numeric keypad.
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="123456"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                    disabled={loading}
                    autoFocus
                  />
                  <p className="text-xs text-muted-foreground">
                    Six digits from the app you enrolled. If the code is rejected, check your device clock.
                  </p>
                  <button type="button" className="text-xs text-primary underline" onClick={() => { setUseRecoveryCode((value) => !value); setMfaCode(""); setRecoveryCode(""); }}>
                    {useRecoveryCode ? "Use authenticator code" : "Use a recovery code instead"}
                  </button>
                  {useRecoveryCode && <Input aria-label="Recovery code" autoComplete="one-time-code" value={recoveryCode} onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())} placeholder="Recovery code" />}
                </div>
              )}

              <Button type="submit" className="w-full h-10" disabled={loading}>
                {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                {loading ? "Signing in..." : "Sign in"}
              </Button>

            </form>
          </CardContent>
        </Card>

        <p className="text-center text-xs text-muted-foreground mt-4">
          Password resets are performed by a platform administrator.
        </p>
        <p className="text-center text-xs text-muted-foreground mt-6">
          © {new Date().getFullYear()} {APP_NAME}. All rights reserved.
        </p>
      </div>
    </div>
  );
}
