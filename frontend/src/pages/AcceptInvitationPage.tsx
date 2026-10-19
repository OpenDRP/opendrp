import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { KeyRound } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/**
 * The public page an invitation links to.
 *
 * The token is the only credential this page has, and it is spent by the accept
 * call. The password is typed here and nowhere else — the administrator who
 * created the account never sees it, which is the point of the invitation
 * (U-7). A weak password is refused by the API with its own message and does
 * not consume the link.
 */
export default function AcceptInvitationPage() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [accepted, setAccepted] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      await endpoints.acceptInvitation(token, password);
      setAccepted(true);
    } catch (failure: unknown) {
      setError(describeApiError(failure, "This invitation is invalid or has expired."));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="w-5 h-5" />
            {accepted ? "Password set" : "Choose your password"}
          </CardTitle>
          <CardDescription>
            {accepted
              ? "Your account is ready. Sign in with the password you just chose."
              : "This link works once. After you set a password, sign in with it — nobody else has it."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {accepted ? (
            <Link to="/login">
              <Button className="w-full">Go to sign in</Button>
            </Link>
          ) : !token ? (
            <p className="text-sm text-destructive">
              This page needs an invitation link. Ask your administrator to send a
              new one.
            </p>
          ) : (
            <form onSubmit={submit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="invitation-password">New password</Label>
                <Input
                  id="invitation-password"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  required
                />
                <p className="text-xs text-muted-foreground">
                  At least 12 characters, with an uppercase letter and a digit.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="invitation-confirm">Repeat password</Label>
                <Input
                  id="invitation-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  required
                />
              </div>
              {error ? <p className="text-sm text-destructive">{error}</p> : null}
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Setting password..." : "Set password"}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
