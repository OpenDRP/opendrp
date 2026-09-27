import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Loader2 } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "@/components/ui/use-toast";

/**
 * Second-factor enrolment, as a block any page can host.
 *
 * Two pages need this exact flow — the security page (voluntary, any role) and
 * the onboarding page (required, because a factor was cleared for this account) —
 * and they must not drift into two implementations of a security control. It is
 * also the flow with an invariant worth keeping in one place: the secret is
 * generated first and only becomes a factor once a code from it verifies, so an
 * interrupted enrolment leaves the account exactly as it was rather than locked
 * behind a factor nobody can produce.
 *
 * The password is required by both API calls, and re-entered here rather than
 * assumed from the session: a borrowed session must not be enough to attach an
 * authenticator to an account, which is what would turn a stolen token into
 * permanent access.
 */
export function MfaEnrolment({
  onEnrolled,
  autoFocusCode = false,
}: {
  /** Called after the factor is enabled, once the client state is refreshed. */
  onEnrolled?: () => void;
  /** Ask the browser for focus on the code field (used on a dedicated page). */
  autoFocusCode?: boolean;
}) {
  const qc = useQueryClient();

  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  // The pending secret, held only in memory and only between the two steps.
  const [pendingSecret, setPendingSecret] = useState<{ secret: string; uri: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [qrUrl, setQrUrl] = useState<string | null>(null);

  const startEnrolment = useMutation({
    mutationFn: () => endpoints.mfaSetup(password),
    onSuccess: (data) => {
      setPendingSecret({ secret: data.secret, uri: data.otpauth_uri });
      if (endpoints.mfaQr) {
        void endpoints.mfaQr().then((blob) => setQrUrl(URL.createObjectURL(blob))).catch(() => setQrUrl(null));
      }
      toast({
        title: "Add the secret to your authenticator app",
        description: "Enter the six-digit code it shows to finish enrolling.",
      });
    },
    onError: (error) => {
      toast({
        variant: "destructive",
        title: "Could not start enrolment",
        description: describeApiError(error, "Check your password and try again."),
      });
    },
  });

  const confirmEnrolment = useMutation({
    mutationFn: () => endpoints.mfaEnable(password, code),
    onSuccess: (data) => {
      setRecoveryCodes(data.recovery_codes ?? []);
      setPendingSecret(null);
      setCode("");
      setPassword("");
      void qc.invalidateQueries({ queryKey: ["mfa-status"] });
      toast({
        title: "Second factor enabled",
        description: data.recovery_codes?.length ? "Save your recovery codes before leaving this page." : "The next sign-in will ask for a code from your app.",
      });
      if (!data.recovery_codes?.length) onEnrolled?.();
    },
    onError: (error) => {
      toast({
        variant: "destructive",
        title: "That code was not accepted",
        description: describeApiError(error, "Check the device clock and try the current code."),
      });
    },
  });

  const busy = startEnrolment.isPending || confirmEnrolment.isPending;

  const copySecret = async () => {
    if (!pendingSecret) return;
    try {
      await navigator.clipboard.writeText(pendingSecret.secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied; the secret is on screen and selectable,
      // which is why this is not treated as an error.
    }
  };

  if (recoveryCodes.length > 0) {
    return (
      <div className="space-y-4">
        <h3 className="font-semibold">Save your recovery codes</h3>
        <p className="text-sm text-muted-foreground">Each code works once if you lose access to your authenticator. They are shown only now.</p>
        <div className="grid grid-cols-2 gap-2 rounded-md border p-3 font-mono text-sm">{recoveryCodes.map((item) => <code key={item}>{item}</code>)}</div>
        <Button variant="outline" onClick={() => void navigator.clipboard?.writeText(recoveryCodes.join("\\n"))}><Copy className="w-4 h-4 mr-2" />Copy recovery codes</Button>
        <Button onClick={() => { setRecoveryCodes([]); onEnrolled?.(); }}>I saved the codes</Button>
      </div>
    );
  }

  if (pendingSecret) {
    return (
      <div className="space-y-4">
        <div className="space-y-2">
          <Label>Secret for manual entry</Label>
          <div className="flex items-center gap-2">
            <code className="flex-1 rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-sm break-all">
              {pendingSecret.secret}
            </code>
            <Button type="button" variant="outline" size="icon" onClick={copySecret} aria-label="Copy secret">
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            </Button>
          </div>
          {qrUrl && <img src={qrUrl} alt="Authenticator setup QR code" className="h-48 w-48 rounded-md border bg-white p-2" />}
          <p className="text-xs text-muted-foreground">
            Scan the QR code or add this secret to your authenticator app manually:
          </p>
          <code className="block rounded-md border border-border bg-muted/40 px-3 py-2 font-mono text-xs break-all">
            {pendingSecret.uri}
          </code>
        </div>
        <div className="space-y-2">
          <Label htmlFor="confirm-code">Code from the app</Label>
          <Input
            id="confirm-code"
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123456"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            disabled={busy}
            autoFocus={autoFocusCode}
          />
        </div>
        <div className="flex gap-2">
          <Button disabled={busy || code.length !== 6} onClick={() => confirmEnrolment.mutate()}>
            {confirmEnrolment.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Confirm and enable
          </Button>
          <Button
            variant="ghost"
            disabled={busy}
            onClick={() => {
              if (qrUrl) URL.revokeObjectURL(qrUrl);
              setQrUrl(null);
              setPendingSecret(null);
              setCode("");
            }}
          >
            Cancel
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Nothing is enabled until this step succeeds, so cancelling leaves your account exactly as
          it was.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Confirm your password to start enrolling. You will be shown a secret to add to an
        authenticator app, and asked for one generated code to finish.
      </p>
      <div className="space-y-2">
        <Label htmlFor="setup-password">Password</Label>
        <Input
          id="setup-password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
        />
      </div>
      <Button disabled={busy || !password} onClick={() => startEnrolment.mutate()}>
        {startEnrolment.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
        Start enrolment
      </Button>
      <p className="text-xs text-muted-foreground">
        The password is required again here on purpose: a borrowed session must not be enough to
        attach a new authenticator to your account.
      </p>
    </div>
  );
}
