import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
import { useIsAdmin, useIsAnalystPlus } from "@/store/auth";
import type { TLSCertificate, TLSCertificateSighting, TLSSightingVerdict } from "@/types/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "@/components/ui/use-toast";

/**
 * The two verdicts an operator reaches for, and what each one means for the next
 * sweep. `expected` says the platform is looking at a copy of our service it
 * already knows about; `confirmed_foreign` accepts that someone else is serving a
 * certificate of ours, which is the finding the module exists to produce.
 *
 * `confirmed_foreign` is first because it is the decision that needs a record:
 * the sweeps keep the question open until somebody answers it.
 */
const VERDICTS: { value: TLSSightingVerdict; label: string; question: string; hint: string }[] = [
  {
    value: "confirmed_foreign",
    label: "Confirm foreign",
    question: "Confirm this deployment is foreign?",
    hint: "Someone else serves this certificate of ours; treat the key as exposed and investigate the address.",
  },
  {
    value: "expected",
    label: "Expected",
    question: "Mark this deployment as expected?",
    hint: "We know why it is there: our own second site, a partner appliance or a CDN the business uses deliberately.",
  },
];

/** The label and explanation a pending decision is described with. */
function verdictEntry(verdict: TLSSightingVerdict) {
  return VERDICTS.find((item) => item.value === verdict);
}

/** Reads the scored signals into one line. Every key is optional by design. */
function signalSummary(sighting: TLSCertificateSighting): string {
  const signals = sighting.signals ?? {};
  const text = (key: string) => (typeof signals[key] === "string" ? (signals[key] as string) : null);
  const list = (key: string) => (Array.isArray(signals[key]) ? (signals[key] as unknown[]).map(String) : []);
  const parts: string[] = [];
  const org = text("org");
  if (org) parts.push(org);
  if (signals["asn"] !== undefined && signals["asn"] !== null) parts.push(`AS${String(signals["asn"])}`);
  const rules = list("rules");
  if (rules.length) parts.push(`rule ${rules.join(", ")}`);
  const sources = list("sources");
  if (sources.length) parts.push(`sources ${sources.join(", ")}`);
  const echo = list("echo");
  if (echo.length) parts.push(`echoes ${echo.join(", ")}`);
  const exception = text("exception");
  if (exception) parts.push(`exception ${exception}`);
  return parts.join(" · ");
}

function verdictBadge(verdict: TLSSightingVerdict) {
  if (verdict === "confirmed_foreign") return <Badge variant="destructive">Confirmed foreign</Badge>;
  if (verdict === "candidate") return <Badge variant="outline">Needs review</Badge>;
  return <Badge variant="secondary">{verdict.replaceAll("_", " ")}</Badge>;
}

/**
 * Certificate deployment review (DNS & TLS intelligence, Design B).
 *
 * The question this answers is not "which certificates exist" but "is a
 * certificate of ours served somewhere that is not ours". A certificate seen on a
 * foreign address is a copy of our service, and the row names the address, the
 * organisation and the signals that decided it, so a reviewer can judge the
 * evidence rather than trust a score.
 *
 * Nothing here contacts a foreign host: every fact comes from evidence a provider
 * already collected or from our own probe of our own assets. The verdict is what
 * keeps the feature usable over time — a sighting a human has judged is not
 * re-alerted on every sweep — and it is written to the audit trail.
 */
export default function CertificateTriage() {
  const canReview = useIsAnalystPlus();
  const isAdmin = useIsAdmin();
  const qc = useQueryClient();
  const [foreignOnly, setForeignOnly] = useState(true);
  /** The sighting and its certificate fingerprint, since the exception is per certificate. */
  const [reviewing, setReviewing] = useState<{
    sighting: TLSCertificateSighting;
    fingerprint: string;
    verdict: TLSSightingVerdict;
  } | null>(null);
  const [allowing, setAllowing] = useState<{ sighting: TLSCertificateSighting; fingerprint: string } | null>(null);
  const [removingException, setRemovingException] = useState<string | null>(null);

  const certificates = useQuery({
    queryKey: ["tls-certificates", foreignOnly],
    queryFn: () => endpoints.listTLSCertificates({ foreign_only: foreignOnly, page: 1, size: 25 }),
    staleTime: 20_000,
  });
  const exceptions = useQuery({
    queryKey: ["tls-certificate-exceptions"],
    queryFn: endpoints.listCertificateExceptions,
    staleTime: 20_000,
  });

  const review = useMutation({
    mutationFn: ({ sighting, verdict }: { sighting: TLSCertificateSighting; verdict: TLSSightingVerdict }) =>
      endpoints.reviewTLSSighting(sighting.id, { verdict, note: null }),
    onSuccess: (_result, variables) => {
      qc.invalidateQueries({ queryKey: ["tls-certificates"] });
      setReviewing(null);
      toast({
        title: "Verdict recorded",
        description: `${variables.sighting.ip ?? variables.sighting.subject ?? "This sighting"} is marked ${variables.verdict.replaceAll("_", " ")}. The rules stay quiet about it until a new source or address makes it a new question.`,
      });
    },
    onError: (error: unknown) =>
      toast({ variant: "destructive", title: "Could not record the verdict", description: describeApiError(error) }),
  });

  const addException = useMutation({
    mutationFn: ({ sighting, fingerprint }: { sighting: TLSCertificateSighting; fingerprint: string }) =>
      endpoints.createCertificateException({
        match_kind: "fingerprint",
        match_value: fingerprint,
        reason: `Allowed from the certificate review of ${sighting.ip ?? sighting.subject ?? fingerprint}`,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tls-certificate-exceptions"] });
      qc.invalidateQueries({ queryKey: ["tls-certificates"] });
      setAllowing(null);
      toast({ title: "Scope exception added", description: "This fingerprint no longer produces a foreign-deployment alert." });
    },
    onError: (error: unknown) =>
      toast({ variant: "destructive", title: "Could not add the exception", description: describeApiError(error) }),
  });

  const removeException = useMutation({
    mutationFn: (id: string) => endpoints.deleteCertificateException(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tls-certificate-exceptions"] });
      setRemovingException(null);
      toast({ title: "Scope exception removed", description: "The rules will judge this identity again on the next sweep." });
    },
    onError: (error: unknown) =>
      toast({ variant: "destructive", title: "Could not remove the exception", description: describeApiError(error) }),
  });

  const items: TLSCertificate[] = certificates.data?.items ?? [];
  const foreignCount = items.reduce((total, item) => total + item.foreign_sightings, 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-primary" />
          Certificate deployments
        </CardTitle>
        <CardDescription>
          {foreignCount} sighting(s) of our certificates on an address that is not ours among the {items.length} certificate(s) shown, of
          {` ${certificates.data?.total ?? 0}`} known. A certificate we serve appearing somewhere else is a copy of our service, and the row names the address, the
          organisation and the signals behind the score. Nothing here contacts the foreign host: every fact comes from evidence a provider
          already collected, or from our own probe of our own assets. A verdict is written to the audit trail and keeps the rules quiet
          about that sighting; a scope exception silences a whole fingerprint for reasons such as shared hosting or a customer CDN. Both the certificate's
          expiry and an exception's end date are the stored UTC instants the audit trail records, not that instant in the reader's zone. {TIME_ZONE_HINT}.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Select value={foreignOnly ? "foreign" : "all"} onValueChange={(value) => setForeignOnly(value === "foreign")}>
          <SelectTrigger aria-label="Filter certificates" className="max-w-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="foreign">Only certificates seen abroad</SelectItem>
            <SelectItem value="all">All known certificates</SelectItem>
          </SelectContent>
        </Select>
        {certificates.isError && (
          <p role="alert" className="text-sm text-destructive">
            Certificate evidence could not be loaded; this is not evidence that our certificates are served only by us.
          </p>
        )}
        {certificates.isLoading && <p className="text-sm text-muted-foreground">Loading certificate evidence…</p>}
        {!certificates.isLoading && items.length === 0 && (
          <p className="text-sm text-muted-foreground">
            {foreignOnly
              ? "No certificate has been observed abroad. Identities appear once the TLS probe or Certificate Transparency has recorded one."
              : "No certificate has been recorded yet. The TLS probe and the Certificate Transparency sources feed this view."}
          </p>
        )}
        <div className="space-y-3">
          {items.map((identity) => (
            <div key={identity.id} className="rounded-md border p-3 text-sm space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs break-all">{identity.fingerprint_sha256}</span>
                <Badge variant="outline">{identity.origin.replaceAll("_", " ")}</Badge>
                <span className="text-muted-foreground">{identity.issuer_dn ?? "unknown issuer"}</span>
                <span className="text-muted-foreground">
                  expires {identity.not_after ? formatDateTime(identity.not_after) : "unknown"}
                </span>
              </div>
              {identity.san_dns.length > 0 && (
                <div className="font-mono text-xs text-muted-foreground break-all">{identity.san_dns.join(", ")}</div>
              )}
              <div className="space-y-1">
                {identity.sightings.map((sighting) => (
                  <div key={sighting.id} className="flex flex-wrap items-center gap-2">
                    {sighting.is_ours ? <Badge variant="secondary">Ours</Badge> : <Badge variant="destructive">Foreign</Badge>}
                    <span className="font-mono text-xs">
                      {sighting.ip ?? "no address"}
                      {sighting.port ? `:${sighting.port}` : ""}
                    </span>
                    {sighting.subject && <span className="font-mono text-xs">{sighting.subject}</span>}
                    <span className="text-xs text-muted-foreground">{sighting.source}</span>
                    {verdictBadge(sighting.verdict)}
                    {sighting.confidence > 0 && <span className="text-xs text-muted-foreground">confidence {sighting.confidence}</span>}
                    {signalSummary(sighting) !== "" && (
                      <span className="text-xs text-muted-foreground break-all">{signalSummary(sighting)}</span>
                    )}
                    {!sighting.is_ours && canReview && (
                      <span className="flex gap-1">
                        {VERDICTS.map((verdict) => (
                          <Button
                            key={verdict.value}
                            size="sm"
                            variant={verdict.value === "confirmed_foreign" ? "outline" : "ghost"}
                            title={verdict.hint}
                            onClick={() => setReviewing({ sighting, fingerprint: identity.fingerprint_sha256, verdict: verdict.value })}
                          >
                            {verdict.value === "confirmed_foreign" && <ShieldAlert className="h-4 w-4" />}
                            {verdict.label}
                          </Button>
                        ))}
                        {isAdmin && (
                          <Button size="sm" variant="ghost" title="Allow this certificate fingerprint everywhere" onClick={() => setAllowing({ sighting, fingerprint: identity.fingerprint_sha256 })}>
                            Allow fingerprint
                          </Button>
                        )}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        {exceptions.data && exceptions.data.length > 0 && (
          <div className="space-y-2 border-t pt-3">
            <div className="text-sm font-medium flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              Scope exceptions
            </div>
            <p className="text-xs text-muted-foreground">
              Identities the rules never alert on. An expired exception stops applying on its own; removing one makes the next sweep judge it again.
            </p>
            {exceptions.data.map((exception) => (
              <div key={exception.id} className="flex flex-wrap items-center gap-2 text-sm">
                <Badge variant="outline">{exception.match_kind}</Badge>
                <span className="font-mono text-xs break-all">{exception.match_value}</span>
                {exception.reason && <span className="text-muted-foreground">{exception.reason}</span>}
                <span className="text-xs text-muted-foreground">
                  {exception.expired
                    ? "expired"
                    : exception.expires_at
                      ? `until ${formatDateTime(exception.expires_at)}`
                      : "no end date"}
                </span>
                {isAdmin && (
                  <Button
                    size="icon"
                    variant="ghost"
                    className="text-destructive hover:text-destructive"
                    title="Remove scope exception"
                    aria-label={`Remove scope exception ${exception.match_value}`}
                    onClick={() => setRemovingException(exception.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
      <ConfirmDialog
        open={reviewing !== null}
        onOpenChange={(open) => {
          if (!open) setReviewing(null);
        }}
        title={reviewing ? (verdictEntry(reviewing.verdict)?.question ?? "Record this verdict?") : "Record this verdict?"}
        description={
          reviewing
            ? `${verdictEntry(reviewing.verdict)?.hint ?? ""} The decision is written to the audit trail, and the next sweep will not re-alert this sighting.`
            : undefined
        }
        confirmLabel="Record verdict"
        confirmLoading={review.isPending}
        onConfirm={() => {
          if (reviewing) review.mutate({ sighting: reviewing.sighting, verdict: reviewing.verdict });
        }}
        onCancel={() => setReviewing(null)}
      />
      <ConfirmDialog
        open={allowing !== null}
        onOpenChange={(open) => {
          if (!open) setAllowing(null);
        }}
        title="Allow this certificate fingerprint?"
        description={
          allowing
            ? `${allowing.fingerprint} will never produce a foreign-deployment alert again, on any address. Use it for a certificate that is genuinely shared — shared hosting, a CDN the business uses — rather than to silence one address, which a verdict does. The exception is recorded in the audit trail and can be removed here.`
            : undefined
        }
        confirmLabel="Allow certificate"
        confirmLoading={addException.isPending}
        onConfirm={() => {
          if (allowing) addException.mutate(allowing);
        }}
        onCancel={() => setAllowing(null)}
      />
      <ConfirmDialog
        open={removingException !== null}
        onOpenChange={(open) => {
          if (!open) setRemovingException(null);
        }}
        variant="destructive"
        title="Remove this scope exception?"
        description="The rules will judge this identity again on the next sweep, and a foreign deployment will alert."
        confirmLabel="Remove"
        confirmLoading={removeException.isPending}
        onConfirm={() => {
          if (removingException) removeException.mutate(removingException);
        }}
        onCancel={() => setRemovingException(null)}
      />
    </Card>
  );
}
