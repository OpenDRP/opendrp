import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { LucideIcon } from "lucide-react";
import {
  KeyRound,
  ShieldCheck,
  ShieldOff,
  ShieldAlert,
  Loader2,
  Copy,
  LogOut,
  LogIn,
  Globe,
  MailCheck,
  History,
} from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { auditCategory, auditTone, describeAuditEntry } from "@/lib/audit";
import { formatDateTime } from "@/lib/datetime";
import { useAuthStore } from "@/store/auth";
import { MfaEnrolment } from "@/components/Auth/MfaEnrolment";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/components/ui/use-toast";

/**
 * Second-factor self-service.
 *
 * Reached by every role, which is why the page exists separately from
 * Settings: an analyst's account deserves the same protection as an
 * administrator's, and the enrolment path must not be admin-only for that to be
 * true.
 *
 * The enrolment block itself lives in components/Auth/MfaEnrolment because the
 * onboarding page hosts the same flow when a factor was cleared for an account.
 * What stays here is what only this page offers: turning the factor *off*, which
 * needs the password and a live code together.
 */
/**
 * The icon and the emphasis a listed event gets.
 *
 * A refusal has to be distinguishable from a routine line at a glance: this list
 * is where an account holder notices a sign-in they did not make, and "Second
 * factor refused" reading like "Session refreshed" is what makes that harder.
 */
const EVENT_ICONS: Record<string, LucideIcon> = {
  "auth.login.success": LogIn,
  "auth.login.failure": ShieldAlert,
  "auth.login.locked": ShieldAlert,
  "auth.mfa.success": ShieldCheck,
  "auth.mfa.failure": ShieldAlert,
  "auth.mfa.enrolled": ShieldCheck,
  "auth.mfa.disabled": ShieldOff,
  "auth.password.changed": KeyRound,
  "auth.password.change_failed": ShieldAlert,
  "auth.session.revoked": LogOut,
  "auth.sessions.revoked_others": LogOut,
  "auth.logout": LogOut,
  "auth.refresh.failure": MailCheck,
};

const TONE_CLASSES: Record<string, string> = {
  danger: "text-destructive border-destructive/40 bg-destructive/10",
  warning: "text-yellow-500 border-yellow-500/30 bg-yellow-500/10",
  neutral: "text-muted-foreground border-border bg-muted/40",
};

function EventIcon({ action }: { action: string }) {
  const Icon = EVENT_ICONS[action] ?? Globe;
  const tone = auditTone(action);
  return (
    <span
      aria-hidden="true"
      className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full border ${TONE_CLASSES[tone]}`}
    >
      <Icon className="h-3.5 w-3.5" />
    </span>
  );
}

/**
 * The account's own security history.
 *
 * The action codes are the platform's filter vocabulary, not a sentence: they are
 * named for the audit trail (`auth.mfa.enrolled`), which is why the row leads
 * with what happened and keeps the code beside it for anyone comparing this page
 * with the audit log. `lib/audit.ts` owns the wording so the two pages cannot
 * describe the same event differently.
 */
function SecurityActivityList() {
  const activity = useQuery({ queryKey: ["security-activity"], queryFn: endpoints.securityActivity });

  if (activity.isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading recent activity...
      </div>
    );
  }
  if (activity.isError) {
    return (
      <p className="text-sm text-destructive">
        Could not read recent activity: {describeApiError(activity.error, "request failed")}
      </p>
    );
  }
  if (!activity.data?.length) {
    return (
      <p className="text-sm text-muted-foreground">
        Nothing recorded yet. Sign-ins, second-factor changes and password changes appear here.
      </p>
    );
  }

  return (
    <ul className="space-y-1">
      {activity.data.map((event) => (
        <li
          key={event.id}
          className="flex items-start justify-between gap-3 border-b py-2 text-sm last:border-b-0"
        >
          <div className="flex min-w-0 items-start gap-3">
            <EventIcon action={event.action} />
            <div className="min-w-0">
              <div className="text-foreground">{describeAuditEntry(event)}</div>
              <div className="font-mono text-[11px] text-muted-foreground">{event.action}</div>
            </div>
          </div>
          <div className="shrink-0 text-right text-xs text-muted-foreground">
            <div>{formatDateTime(event.timestamp)}</div>
            {event.ip_address ? <div className="font-mono">{event.ip_address}</div> : null}
          </div>
        </li>
      ))}
    </ul>
  );
}

export default function SecurityPage() {
  const qc = useQueryClient();
  const user = useAuthStore((s) => s.user);

  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);

  const status = useQuery({
    queryKey: ["mfa-status"],
    queryFn: endpoints.mfaStatus,
  });

  const changePassword = useMutation({
    mutationFn: () => endpoints.changePassword(currentPassword, newPassword),
    onSuccess: (data) => {
      useAuthStore.getState().setSession(data);
      setCurrentPassword(""); setNewPassword(""); setConfirmPassword("");
      toast({ title: "Password changed", description: "Other sessions were signed out." });
      void qc.invalidateQueries({ queryKey: ["security-activity"] });
    },
    onError: (error) => toast({ variant: "destructive", title: "Could not change password", description: describeApiError(error) }),
  });

  const sessions = useQuery({ queryKey: ["auth-sessions"], queryFn: endpoints.listSessions });
  // The list holds usable sessions only, so "others" is what revoking would
  // actually sign out — a button that reports zero there is the honest state.
  const otherSessions = sessions.data?.filter((session) => !session.current).length ?? 0;
  // Both revocations refresh the activity list too: the session that was here a
  // moment ago is now an event in it, and the card that explains why a session
  // ended is the one below this list.
  const afterRevoke = () => {
    void qc.invalidateQueries({ queryKey: ["auth-sessions"] });
    void qc.invalidateQueries({ queryKey: ["security-activity"] });
  };
  const revokeOthers = useMutation({
    mutationFn: endpoints.revokeOtherSessions,
    onSuccess: () => { afterRevoke(); toast({ title: "Other sessions revoked" }); },
  });
  const revokeOne = useMutation({
    mutationFn: endpoints.revokeSession,
    onSuccess: afterRevoke,
  });
  const rotateRecovery = useMutation({
    mutationFn: () => endpoints.mfaRotateRecoveryCodes(password, code),
    onSuccess: (data) => { setRecoveryCodes(data.codes); setPassword(""); setCode(""); toast({ title: "Recovery codes generated", description: "Save them now. They will not be shown again." }); },
    onError: (error) => toast({ variant: "destructive", title: "Could not generate recovery codes", description: describeApiError(error) }),
  });

  const disable = useMutation({
    mutationFn: () => endpoints.mfaDisable(password, code),
    onSuccess: () => {
      setCode("");
      setPassword("");
      void qc.invalidateQueries({ queryKey: ["mfa-status"] });
      toast({
        title: "Second factor disabled",
        description: "Sign-in will ask for your password only until you enrol again.",
      });
    },
    onError: (error) => {
      toast({
        variant: "destructive",
        title: "Could not disable the second factor",
        description: describeApiError(error, "Your password and a current code are both required."),
      });
    },
  });

  const enabled = status.data?.enabled === true;
  const busy = disable.isPending || changePassword.isPending || rotateRecovery.isPending;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
            <KeyRound className="w-6 h-6 text-primary" />
            My security
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {user?.email} · second-factor state for your own account
          </p>
        </div>
        {!status.isLoading && (
          <Badge
            className={
              enabled
                ? "bg-green-500/15 text-green-500 border-green-500/30"
                : "bg-yellow-500/15 text-yellow-500 border-yellow-500/30"
            }
          >
            {enabled ? "Two-factor enabled" : "Password only"}
          </Badge>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle as="h2" className="text-lg flex items-center gap-2">
            {enabled ? <ShieldCheck className="w-5 h-5 text-green-500" /> : <ShieldOff className="w-5 h-5 text-yellow-500" />}
            Authenticator app (TOTP)
          </CardTitle>
          <CardDescription>
            A six-digit code from your phone in addition to your password. It is what stops a stolen
            or re-used password from being enough on its own.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {status.isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading second-factor state...
            </div>
          ) : status.isError ? (
            <p className="text-sm text-destructive">
              Could not read the second-factor state: {describeApiError(status.error, "request failed")}
            </p>
          ) : enabled ? (
            <>
              <p className="text-sm text-muted-foreground">
                Enabled {status.data?.enabled_at ? formatDateTime(status.data.enabled_at) : ""}. Enter a
                current code and your password to turn it off.
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="disable-password">Password</Label>
                  <Input
                    id="disable-password"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={busy}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="disable-code">Authenticator code</Label>
                  <Input
                    id="disable-code"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                    disabled={busy}
                  />
                </div>
              </div>
              <Button
                variant="destructive"
                disabled={busy || !password || code.length !== 6}
                onClick={() => disable.mutate()}
              >
                {disable.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Disable two-factor authentication
              </Button>
              <p className="text-xs text-muted-foreground">
                Lost the device? An administrator can clear the factor for you (recorded in the audit
                log), and enrolling a new one is required at your next sign-in. If you are the last
                administrator, run
                <span className="font-mono"> python -m scripts.manage_admin mfa-off -e {user?.email}</span> on the host.
              </p>
            </>
          ) : (
            <MfaEnrolment />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle as="h2">Change password</CardTitle><CardDescription>Choose a new password at any time. Your other sessions are revoked.</CardDescription></CardHeader>
        <CardContent>
          <form className="space-y-3" onSubmit={(event) => { event.preventDefault(); if (newPassword !== confirmPassword) { toast({ variant: "destructive", title: "Passwords do not match" }); return; } changePassword.mutate(); }}>
            <div className="grid gap-3 sm:grid-cols-3">
              <Input aria-label="Current password" type="password" autoComplete="current-password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password" />
              <Input aria-label="New password" type="password" autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password" />
              <Input aria-label="Repeat new password" type="password" autoComplete="new-password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="Repeat new password" />
            </div>
            <p className="text-xs text-muted-foreground">At least 12 characters, including one uppercase letter and one digit.</p>
            <Button type="submit" disabled={busy || !currentPassword || !newPassword || !confirmPassword}>Change password</Button>
          </form>
        </CardContent>
      </Card>

      {enabled && <Card>
        <CardHeader><CardTitle as="h2">Recovery codes</CardTitle><CardDescription>Use one code instead of an authenticator code if you lose your device. Each code works once.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          {recoveryCodes.length > 0 ? <><div className="grid grid-cols-2 gap-2 rounded-md border p-3 font-mono text-sm">{recoveryCodes.map((item) => <code key={item}>{item}</code>)}</div><p className="text-xs text-destructive">Copy or print these now. They will disappear when you leave this page.</p><Button variant="outline" onClick={() => void navigator.clipboard?.writeText(recoveryCodes.join("\\n"))}><Copy className="w-4 h-4" />Copy codes</Button></> : <><p className="text-xs text-muted-foreground">Generating a new set invalidates all previous codes. Re-authenticate to continue.</p><Button variant="outline" disabled={busy || !password || code.length !== 6} onClick={() => rotateRecovery.mutate()}>Generate new recovery codes</Button></>}
        </CardContent>
      </Card>}

      <Card>
        <CardHeader>
          <CardTitle as="h2">Active sessions</CardTitle>
          <CardDescription>
            Where this account is signed in right now. Revoke a device you no longer recognize;
            tokens are never displayed, and a session you end appears in Recent security activity
            below rather than staying in this list.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {sessions.isLoading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading sessions...
            </div>
          ) : sessions.isError ? (
            <p className="text-sm text-destructive">
              Could not read the session list: {describeApiError(sessions.error, "request failed")}
            </p>
          ) : (
            <>
              {sessions.data?.length ? (
                sessions.data.map((session) => (
                  <div
                    key={session.id}
                    className="flex items-center justify-between gap-3 rounded-md border p-3 text-sm"
                  >
                    <div>
                      <div>{session.current ? "This browser" : "Another signed-in device"}</div>
                      <div className="text-xs text-muted-foreground">
                        Signed in {formatDateTime(session.created_at)}
                        {session.last_used_at ? ` · last used ${formatDateTime(session.last_used_at)}` : ""}
                      </div>
                    </div>
                    {!session.current && (
                      <Button size="sm" variant="destructive" onClick={() => revokeOne.mutate(session.id)}>
                        <LogOut className="w-4 h-4" />Revoke
                      </Button>
                    )}
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground">
                  This browser is the only signed-in session.
                </p>
              )}
              <Button
                variant="outline"
                disabled={revokeOthers.isPending || otherSessions === 0}
                onClick={() => revokeOthers.mutate()}
              >
                Sign out other sessions {otherSessions > 0 ? `(${otherSessions})` : ""}
              </Button>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle as="h2" className="flex items-center gap-2">
            <History className="h-5 w-5 text-muted-foreground" />
            Recent security activity
          </CardTitle>
          <CardDescription>
            Only events belonging to this account are shown, newest first. The line under each entry
            is its audit action, which is what the audit log and a support request name it by.
          </CardDescription>
        </CardHeader>
        <CardContent><SecurityActivityList /></CardContent>
      </Card>
    </div>
  );
}
