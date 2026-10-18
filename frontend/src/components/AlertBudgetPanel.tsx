import type { AlertBudgetChoice, AlertPolicy, BreachNoiseChoice } from "@/types/api";
import { Gauge } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { useFormContext } from "react-hook-form";

/** The four scored values of the budget. Each is a number the operator may leave
 * blank, and blank means "the deployment's `ALERT_*` value answers this one" — not
 * zero. The bounds mirror the API schema and the environment variables, so a typo
 * is a field message here rather than a `422` from the server. */
export const BUDGET_NUMBER_FIELDS = [
  {
    name: "alert_confidence_direct",
    label: "Direct alert score",
    min: 1,
    max: 100,
    hint: "At or above this score a candidate is alerted as soon as its signals are known.",
  },
  {
    name: "alert_confidence_digest",
    label: "Digest threshold",
    min: 0,
    max: 99,
    hint: "Between this score and the direct one, a candidate waits for the daily digest. Must stay below the direct score.",
  },
  {
    name: "alert_phishing_digest_hour_utc",
    label: "Digest hour (UTC)",
    min: 0,
    max: 23,
    hint: "The hour the daily digest runs at, on the quarter hour.",
  },
  {
    name: "alert_no_channel_retry_hours",
    label: "No-channel hold (hours)",
    min: 0,
    max: 8760,
    hint: "How long a finding no configured channel can receive is held before it is tried again. 0 consumes it immediately.",
  },
  {
    name: "alert_breach_digest_threshold",
    label: "Breach digest threshold",
    min: 0,
    max: 500,
    hint: "Past this many new breach incidents in one scan the rest wait for the daily digest. 0 reports one message per scan.",
  },
] as const;

/** The two switches. Three states rather than a switch, because "the deployment
 * decides" is a state and a switch cannot show it. */
export const BUDGET_TOGGLE_FIELDS = [
  {
    name: "alert_phishing_digest_enabled",
    label: "Daily digest",
    hint: "Off makes the budget binary: only candidates at or above the direct score are then delivered.",
  },
  {
    name: "alert_candidate_change_notifications",
    label: "Report candidate changes",
    hint: "A candidate that moves address, ports or brand is reported again.",
  },
] as const;

const CHOICE_LABELS: Record<AlertBudgetChoice, string> = {
  default: "Deployment default",
  on: "On",
  off: "Off",
};

/** The breach noise policy, as the four things an operator may state. "Deployment
 * default" is the row's own NULL, exactly as the switches above. */
const NOISE_CHOICE_LABELS: Record<BreachNoiseChoice, string> = {
  default: "Deployment default",
  store_only_spam: "Store spam and fabricated only",
  verified_only: "Only verified incidents",
  all: "Report everything",
};

type BudgetFieldName =
  | (typeof BUDGET_NUMBER_FIELDS)[number]["name"]
  | (typeof BUDGET_TOGGLE_FIELDS)[number]["name"]
  | "alert_breach_noise_policy";

/** Where the values in force came from, in the words an operator would use. */
function sourceSentence(policy: AlertPolicy): string {
  return policy.source === "settings"
    ? "Saved values answer where they are set; the deployment's environment answers the rest."
    : "Nothing is saved yet, so the deployment's environment answers every value below.";
}

function inForceLine(policy: AlertPolicy): string {
  // The middle band always exists in a resolved policy: the resolver refuses a
  // digest threshold at or above the direct one, so `digest … direct - 1` is not
  // an empty range here.
  const digest = policy.digest_enabled
    ? `digest at ${String(policy.digest_hour_utc).padStart(2, "0")}:15 UTC for scores ${policy.confidence_digest}–${policy.confidence_direct - 1}`
    : "no daily digest";
  const breach = [
    policy.breach_noise_policy === "all"
      ? "every breach incident reported"
      : policy.breach_noise_policy === "verified_only"
        ? "only verified breach incidents reported"
        : "spam and fabricated breach incidents stored silently",
    policy.breach_digest_threshold > 0
      ? `over ${policy.breach_digest_threshold} new incidents per scan → digest`
      : "every new incident reported per scan",
  ].join(" · ");
  return [
    `alerts at score ≥ ${policy.confidence_direct}`,
    digest,
    `list-only below ${policy.confidence_digest}`,
    `no-channel hold ${policy.no_channel_retry_hours}h`,
    policy.candidate_change_notifications ? "candidate changes reported" : "candidate changes not reported",
    breach,
  ].join(" · ");
}

/**
 * The alert budget's operator half (WI-13).
 *
 * Eight values decide how loud the channel is: where a candidate stops being a message
 * and starts being a line in the daily digest, below which it is list-only, whether
 * the digest runs and at which UTC hour, how long a finding no channel can receive
 * is held, whether a change to an already reported candidate is a second message,
 * which breach incidents are stored silently, and how many new ones one scan may
 * report before the rest wait for the digest.
 *
 * The panel edits what the installation *states*; the card above it says what is in
 * force, because the two differ wherever the operator left a field blank. That is
 * the whole reason both are on this page: a blank field is not zero, and the only
 * honest way to show "the deployment decides this one" is to say which value the
 * deployment decided.
 */
export function AlertBudgetPanel({ policy }: { policy?: AlertPolicy | null }) {
  // The page's form, rather than a `control` prop: the section is rendered inside
  // that form, and the fields it registers are the page's own settings keys. Passing
  // a control across the module boundary would mean naming the page's whole form
  // type here — which is the page's business, not this panel's.
  const form = useFormContext();

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Gauge className="w-4 h-4 text-primary" />
          Alert budget
        </CardTitle>
        <CardDescription>
          How loudly a scored phishing candidate is reported: immediately, in the daily digest,
          or in the list alone. A blank field is not zero — it is “not decided here”, and the
          deployment's own value keeps answering it.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {policy ? (
          <div className="rounded-lg border bg-muted/40 p-3 space-y-1 text-xs">
            <p className="font-medium">In force now: {inForceLine(policy)}</p>
            <p className="text-muted-foreground">{sourceSentence(policy)}</p>
            {policy.invalid.length > 0 && (
              <p className="text-destructive">
                A saved budget was refused because it does not hold together ({policy.invalid.join(", ")});
                the deployment's values above are what is routing. Save a consistent pair to use yours.
              </p>
            )}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            The budget in force could not be read. The fields below still save; they are only
            compared with the deployment's own values by the platform.
          </p>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {BUDGET_NUMBER_FIELDS.map((field) => (
            <FormField
              key={field.name}
              control={form.control}
              name={field.name as BudgetFieldName}
              render={({ field: controlled }) => (
                <FormItem>
                  <FormLabel>{field.label}</FormLabel>
                  <FormControl>
                    <Input
                      {...controlled}
                      value={controlled.value ?? ""}
                      type="number"
                      min={field.min}
                      max={field.max}
                      placeholder="deployment default"
                    />
                  </FormControl>
                  <p className="text-xs text-muted-foreground">{field.hint}</p>
                  <FormMessage />
                </FormItem>
              )}
            />
          ))}
        </div>

        <FormField
          control={form.control}
          name="alert_breach_noise_policy"
          render={({ field: controlled }) => (
            <FormItem>
              <FormLabel>Breach noise policy</FormLabel>
              <Select
                value={(controlled.value as BreachNoiseChoice) || "default"}
                onValueChange={controlled.onChange}
              >
                <FormControl>
                  <SelectTrigger aria-label="Breach noise policy">
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {(Object.keys(NOISE_CHOICE_LABELS) as BreachNoiseChoice[]).map((choice) => (
                    <SelectItem key={choice} value={choice}>
                      {NOISE_CHOICE_LABELS[choice]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                An incident the source itself labels spam or fabricated is always stored and
                visible in the list; this decides whether it also reaches the channel.
              </p>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {BUDGET_TOGGLE_FIELDS.map((field) => (
            <FormField
              key={field.name}
              control={form.control}
              name={field.name as BudgetFieldName}
              render={({ field: controlled }) => (
                <FormItem>
                  <FormLabel>{field.label}</FormLabel>
                  <Select
                    value={(controlled.value as AlertBudgetChoice) || "default"}
                    onValueChange={controlled.onChange}
                  >
                    <FormControl>
                      <SelectTrigger aria-label={field.label}>
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {(Object.keys(CHOICE_LABELS) as AlertBudgetChoice[]).map((choice) => (
                        <SelectItem key={choice} value={choice}>
                          {CHOICE_LABELS[choice]}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">{field.hint}</p>
                  <FormMessage />
                </FormItem>
              )}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
