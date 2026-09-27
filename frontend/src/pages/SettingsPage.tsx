import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { RefreshCw, Save, Mail, Key, Globe, MessageSquare, Send, Bell, Clock, Send as SendIcon, Boxes } from "lucide-react";
import { Control, useController } from "react-hook-form";
import { describeApiError, endpoints } from "@/lib/api";
import { issueConnectorToken, revokeConnectorToken } from "@/lib/connectors";
import { fetchModules, updateModule } from "@/lib/modules";
import type { RegistryModule } from "@/types/api";
import { formatDateTimeOrNever } from "@/lib/datetime";
import { humanizeKey } from "@/lib/labels";
import type { Connector, ConnectorConfigField, RuntimeConfiguration, TelegramChatValidationResponse } from "@/types/api";
import { ErrorState } from "@/components/ui/error-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "@/components/ui/use-toast";

const WEEKDAY_LABELS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const settingsSchema = z.object({
  telegram_bot_token: z.string().optional(),
  smtp_host: z.string().optional(),
  smtp_port: z.coerce.number().int().positive().optional().or(z.literal("").transform(() => undefined)),
  smtp_security_mode: z.enum(["starttls", "ssl", "plain"]),
  smtp_user: z.string().optional(),
  smtp_password: z.string().optional(),
  // Empty string is intentionally kept and submitted: the backend turns it
  // into null and clears the stored value. (Sending undefined would drop the
  // key from the JSON body and silently keep the old email.)
  smtp_from_email: z
    .string()
    .refine((v) => v === "" || v.includes("*") || v.includes("•") || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v), "Invalid email address")
    .optional(),
  alert_recipient_email: z
    .string()
    .refine((v) => v === "" || v.includes("*") || v.includes("•") || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v), "Invalid email address")
    .optional(),
  email_alerts_enabled: z.boolean(),
  telegram_alerts_enabled: z.boolean(),
  alert_email_user_ids: z.array(z.string()),
  telegram_chat_ids: z.string(), // newline/comma-separated in the UI, parsed server-side
  schedule_phishing_days: z.array(z.number().min(0).max(6)),
  schedule_phishing_hour: z.coerce.number().int().min(0).max(23),
  schedule_phishing_minute: z.coerce.number().int().min(0).max(59),
  schedule_breaches_days: z.array(z.number().min(0).max(6)),
  schedule_breaches_hour: z.coerce.number().int().min(0).max(23),
  schedule_breaches_minute: z.coerce.number().int().min(0).max(59),
});

type SettingsForm = z.infer<typeof settingsSchema>;

export default function SettingsPage() {
  const qc = useQueryClient();
  const [testTo, setTestTo] = useState("");
  const [telegramValidation, setTelegramValidation] = useState<TelegramChatValidationResponse | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["settings"],
    queryFn: endpoints.getSettings,
    staleTime: 60_000,
  });
  const { data: runtimeConfig } = useQuery<RuntimeConfiguration | null>({
    queryKey: ["settings-runtime"],
    queryFn: endpoints.getRuntimeConfiguration || (() => Promise.resolve(null)),
    staleTime: 60_000,
  });

  const form = useForm<SettingsForm>({
    resolver: zodResolver(settingsSchema),
    defaultValues: {
      telegram_bot_token: "",
      smtp_host: "",
      smtp_port: undefined,
      smtp_security_mode: "starttls",
      smtp_user: "",
      smtp_password: "",
      smtp_from_email: "",
      alert_recipient_email: "",
      email_alerts_enabled: false,
      telegram_alerts_enabled: false,
      alert_email_user_ids: [],
      telegram_chat_ids: "",
      schedule_phishing_days: [1, 2, 3, 4, 5],
      schedule_phishing_hour: 2,
      schedule_phishing_minute: 30,
      schedule_breaches_days: [1, 2, 3, 4, 5],
      schedule_breaches_hour: 3,
      schedule_breaches_minute: 30,
    },
    values: data ? {
      telegram_bot_token: data.telegram_bot_token || "",
      smtp_host: data.smtp_host || "",
      smtp_port: data.smtp_port,
      smtp_security_mode: data.smtp_security_mode || "starttls",
      smtp_user: data.smtp_user || "",
      smtp_password: data.smtp_password || "",
      smtp_from_email: data.smtp_from_email || "",
      alert_recipient_email: data.alert_recipient_email || "",
      email_alerts_enabled: !!data.email_alerts_enabled,
      telegram_alerts_enabled: !!data.telegram_alerts_enabled,
      alert_email_user_ids: data.alert_email_user_ids || [],
      telegram_chat_ids: (data.telegram_chat_ids || []).join("\n"),
      schedule_phishing_days: data.schedule_phishing?.days ?? [1, 2, 3, 4, 5],
      schedule_phishing_hour: data.schedule_phishing?.hour ?? 2,
      schedule_phishing_minute: data.schedule_phishing?.minute ?? 30,
      schedule_breaches_days: data.schedule_breaches?.days ?? [1, 2, 3, 4, 5],
      schedule_breaches_hour: data.schedule_breaches?.hour ?? 3,
      schedule_breaches_minute: data.schedule_breaches?.minute ?? 30,
    } : undefined,
  });

  const saveMut = useMutation({
    mutationFn: (v: SettingsForm) => endpoints.updateSettings(v),
    onSuccess: (r) => {
      qc.setQueryData(["settings"], r);
      qc.invalidateQueries({ queryKey: ["settings"] });
      toast({ title: "Settings saved" });
    },
    onError: (e: any) => {
      toast({ variant: "destructive", title: "Failed to save settings", description: describeApiError(e) });
    },
  });

  const testMailMut = useMutation({
    mutationFn: (to?: string) => endpoints.sendTestEmail(to || undefined),
    onSuccess: (r) => toast({ title: "Test email sent", description: `To: ${r.to}` }),
    onError: (e: any) => {
      toast({ variant: "destructive", title: "Test email failed", description: describeApiError(e) });
    },
  });

  const validateTgMut = useMutation({
    mutationFn: () => endpoints.validateTelegramChats(),
    onSuccess: (r: TelegramChatValidationResponse) => setTelegramValidation(r),
    onError: (e: any) => toast({ variant: "destructive", title: "Telegram validation failed", description: describeApiError(e) }),
  });

  const testTgMut = useMutation({
    mutationFn: (chatId?: string) => endpoints.sendTestTelegram(chatId || undefined),
    onSuccess: (r) => {
      setTelegramValidation({ valid: r.validated ?? r.sent, total: r.total, results: r.results || [] });
      const failed = (r.results || []).filter((x: any) => !x.ok);
      if (failed.length) {
        toast({ variant: "destructive", title: `Sent to ${r.sent}/${r.total} chats`, description: failed.map((f: any) => `${f.chat_id}: ${f.error}`).join("; ").slice(0, 300) });
      } else {
        toast({ title: `Test message sent to ${r.sent} chat(s)` });
      }
    },
    onError: (e: any) => {
      toast({ variant: "destructive", title: "Telegram test failed", description: describeApiError(e) });
    },
  });

  // Active platform users (any role) for the email-alerts checklist.
  const { data: usersBrief } = useQuery({
    queryKey: ["users-brief"],
    queryFn: endpoints.listUsersBrief,
    staleTime: 60_000,
  });

  // Connector registry (core + connector architecture).
  const { data: connectors } = useQuery({
    queryKey: ["connectors"],
    queryFn: endpoints.listConnectors,
    refetchInterval: 15_000,
  });

  const connectorStatusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: "enabled" | "disabled" }) =>
      endpoints.setConnectorStatus(id, status),
    onSuccess: (c: any) => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      toast({ title: `Connector ${c.name} ${c.status}` });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to update connector", description: describeApiError(e) }),
  });

  const connectorConfigMut = useMutation({
    mutationFn: ({ id, config }: { id: string; config: Record<string, unknown> }) =>
      endpoints.setConnectorConfig(id, config),
    onSuccess: (c: any) => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      toast({ title: `Connector ${c.name} configuration saved` });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to save connector config", description: describeApiError(e) }),
  });

  // The plaintext credential is returned exactly once, so it is held in memory
  // only long enough for the operator to copy it into the worker's environment.
  const [issuedToken, setIssuedToken] = useState<
    { name: string; token: string; rotated: boolean } | null
  >(null);

  const connectorTokenMut = useMutation({
    mutationFn: ({ id }: { id: string }) => issueConnectorToken(id),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      setIssuedToken({
        name: data.connector.name,
        token: data.token,
        rotated: data.rotated,
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to issue connector credential", description: describeApiError(e) }),
  });

  const connectorTokenRevokeMut = useMutation({
    mutationFn: ({ id }: { id: string }) => revokeConnectorToken(id),
    onSuccess: (conn) => {
      qc.invalidateQueries({ queryKey: ["connectors"] });
      setIssuedToken(null);
      toast({
        title: `Credential revoked for ${conn.name}`,
        description: "The connector entry and its job history were kept.",
      });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to revoke connector credential", description: describeApiError(e) }),
  });

  // The module registry: which kinds of findings this platform can collect and
  // store. Modules are data, so this list — not the code — decides what the
  // platform supports, and a disabled module stops accepting new connectors.
  const { data: moduleRegistry } = useQuery({
    queryKey: ["modules"],
    queryFn: fetchModules,
    staleTime: 60_000,
  });

  const moduleToggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateModule(id, { enabled }),
    onSuccess: (module) => {
      qc.invalidateQueries({ queryKey: ["modules"] });
      qc.invalidateQueries({ queryKey: ["connector-modules"] });
      toast({ title: `${module.label} ${module.enabled ? "enabled" : "disabled"}` });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Failed to update module", description: describeApiError(e) }),
  });

  const settingsPayload = (v: SettingsForm) => {
    const {
      schedule_phishing_days,
      schedule_phishing_hour,
      schedule_phishing_minute,
      schedule_breaches_days,
      schedule_breaches_hour,
      schedule_breaches_minute,
      ...fields
    } = v;
    return {
      ...fields,
      telegram_chat_ids: v.telegram_chat_ids || "",
      // Rebuild nested JSON payloads from flat form fields. Do not send the
      // presentation-only flat fields: the API deliberately rejects unknown
      // settings keys.
      schedule_phishing: { days: schedule_phishing_days, hour: schedule_phishing_hour, minute: schedule_phishing_minute },
      schedule_breaches: { days: schedule_breaches_days, hour: schedule_breaches_hour, minute: schedule_breaches_minute },
    } as any;
  };

  const onSubmit = (v: SettingsForm) => {
    saveMut.mutate(settingsPayload(v));
  };

  const validateTelegramFromForm = form.handleSubmit(async (v) => {
    await saveMut.mutateAsync(settingsPayload(v));
    await validateTgMut.mutateAsync();
  });

  const testTelegramFromForm = form.handleSubmit(async (v) => {
    // The test endpoint reads encrypted settings from the database. Persist the
    // current form first so "Send test message" is safe to use immediately after
    // entering a token/chat ID; previously it tested only the last saved values,
    // which made a newly configured channel report "not configured".
    try {
      await saveMut.mutateAsync(settingsPayload(v));
      await testTgMut.mutateAsync();
    } catch {
      // The mutation already presents the actionable error through its onError
      // handler. Do not leak a rejected promise from the form submit event.
    }
  });

  const testEmailFromForm = form.handleSubmit(async (v) => {
    // The test endpoint reads the encrypted SMTP settings from the database.
    // Save the current form first so a newly entered Mailtrap or SMTP
    // configuration is tested instead of the previous persisted values.
    try {
      await saveMut.mutateAsync(settingsPayload(v));
      await testMailMut.mutateAsync(testTo || undefined);
    } catch {
      // The mutation already presents the actionable error through its onError
      // handler. Do not leak a rejected promise from the form submit event.
    }
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Settings</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Configure integrations, notifications and SMTP delivery. Admin-only.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {runtimeConfig && (
        <Card className="border-dashed">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm">Applied runtime configuration</CardTitle>
            <CardDescription>
              Safe values read by this running backend container. If a changed `.env` value
              is absent here, recreate the service; a plain restart does not reload its environment.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2 text-xs">
            <Badge variant="outline">{runtimeConfig.app_env} · {runtimeConfig.version}</Badge>
            <Badge variant="outline">DB pool {runtimeConfig.database_pool.size}+{runtimeConfig.database_pool.max_overflow}</Badge>
            <Badge variant="outline">statement {runtimeConfig.timeouts.statement_ms} ms</Badge>
            <Badge variant="outline">command {runtimeConfig.timeouts.command_seconds} s</Badge>
            <Badge variant="outline">DNS {runtimeConfig.timeouts.outbound_dns_seconds} s</Badge>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <div className="grid gap-4">
          <Skeleton className="h-14 w-full rounded-lg" />
          <Skeleton className="h-[420px] w-full rounded-xl" />
        </div>
      ) : isError ? (
        /* Never render the form on a failed load: every field would start
           empty and saving would wipe the stored configuration. */
        <ErrorState
          title="Settings could not be loaded"
          description="Editing is disabled while the stored configuration is unknown, to avoid overwriting it with empty values."
          onRetry={() => refetch()}
        />
      ) : (
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Key className="w-4 h-4 text-primary" />
                  Connectors
                </CardTitle>
                <CardDescription>
                  Data-source workers registered with the platform, each authenticated with its own
                  credential. Disabled connectors receive no scan work.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {issuedToken && (
                  <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 space-y-1">
                    <p className="text-sm font-medium">
                      {issuedToken.rotated ? "New credential for" : "Credential for"}
                      {" "}
                      <span className="font-mono">{issuedToken.name}</span>
                    </p>
                    <p className="text-xs text-muted-foreground">
                      Shown once and stored only as a digest by the platform. Put it in that worker's
                      environment as <span className="font-mono">CONNECTOR_TOKEN</span> and recreate
                      the container — <span className="font-mono">restart</span> will not pick it up,
                      because its environment is fixed at creation. It cannot be retrieved again.
                    </p>
                    <code className="block break-all text-xs font-mono pt-1">{issuedToken.token}</code>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => setIssuedToken(null)}
                    >
                      Done
                    </Button>
                  </div>
                )}
                {(connectors || []).length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    No connectors are registered yet. Provision one on the core together with its
                    credential (see “Connector credentials” in the README), then start that worker
                    container: without a credential a worker cannot register or claim work.
                  </p>
                )}
                {(connectors || []).map((c: Connector) => (
                  <ConnectorRow
                    key={c.id}
                    conn={c}
                    onStatus={(status) => connectorStatusMut.mutate({ id: c.id, status })}
                    onConfig={(config) => connectorConfigMut.mutate({ id: c.id, config })}
                    onIssueToken={() => connectorTokenMut.mutate({ id: c.id })}
                    onRevokeToken={() => connectorTokenRevokeMut.mutate({ id: c.id })}
                    busy={
                      connectorStatusMut.isPending ||
                      connectorConfigMut.isPending ||
                      connectorTokenMut.isPending ||
                      connectorTokenRevokeMut.isPending
                    }
                  />
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Boxes className="w-4 h-4 text-primary" />
                  Modules
                </CardTitle>
                <CardDescription>
                  What kinds of findings this platform can collect. A module declares the
                  fields its connectors submit and how findings are deduplicated, so a new
                  data source is a declaration — not a code change. Disabling one stops new
                  connectors from registering for it.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {(moduleRegistry?.modules || []).length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    No modules are registered. This platform cannot store any findings until
                    at least one module exists.
                  </p>
                )}
                {(moduleRegistry?.modules || []).map((module: RegistryModule) => (
                  <div
                    key={module.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3"
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-sm">{module.label}</span>
                        <span className="text-xs font-mono text-muted-foreground">{module.id}</span>
                        {module.builtin && (
                          <Badge variant="outline" className="text-[10px]">built-in</Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground mt-0.5">
                        Contributes <span className="font-mono">{module.finding_kind}</span> findings
                        {module.storage === "generic"
                          ? ` · ${Object.keys(module.fields).length} declared fields`
                          : " · dedicated storage"}
                        {module.dedup_fields.length > 0
                          ? ` · deduplicated on ${module.dedup_fields.join(", ")}`
                          : ""}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-xs text-muted-foreground">
                        {module.enabled ? "Enabled" : "Disabled"}
                      </span>
                      <Switch
                        checked={module.enabled}
                        onCheckedChange={(value) =>
                          moduleToggleMut.mutate({ id: module.id, enabled: value })
                        }
                        disabled={moduleToggleMut.isPending}
                        aria-label={`Toggle module ${module.label}`}
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Bell className="w-4 h-4 text-primary" />
                  Alert channels
                </CardTitle>
                <CardDescription>
                  When a scan discovers something new, alerts are sent to the enabled channels below.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                {/* --- Email alerts --- */}
                <div className="rounded-lg border p-4 space-y-3">
                  <FormField control={form.control} name="email_alerts_enabled" render={({ field }) => (
                    <FormItem className="flex flex-row items-center justify-between">
                      <FormLabel className="!mb-0 font-medium">Email alerts</FormLabel>
                      <FormControl>
                        <Switch checked={!!field.value} onCheckedChange={field.onChange} aria-label="Enable email alerts" />
                      </FormControl>
                    </FormItem>
                  )} />
                  {form.watch("email_alerts_enabled") && (
                    <div className="space-y-3 pt-1">
                      <div>
                        <Label className="text-xs text-muted-foreground">Recipients (platform users)</Label>
                        <FormField control={form.control} name="alert_email_user_ids" render={({ field }) => (
                          <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2">
                            {(usersBrief || []).map((u: any) => {
                              const checked = (field.value || []).includes(u.id);
                              return (
                                <label key={u.id} className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm cursor-pointer hover:bg-accent/40">
                                  <input
                                    type="checkbox"
                                    className="accent-[hsl(var(--primary))]"
                                    checked={checked}
                                    onChange={(e) => {
                                      const cur = field.value || [];
                                      field.onChange(e.target.checked ? [...cur, u.id] : cur.filter((id: string) => id !== u.id));
                                    }}
                                  />
                                  <span className="truncate font-mono text-xs">{u.email}</span>
                                  <Badge variant="outline" className="ml-auto text-[10px] shrink-0">{u.role}</Badge>
                                </label>
                              );
                            })}
                            {(usersBrief || []).length === 0 && (
                              <span className="text-xs text-muted-foreground">No active users found.</span>
                            )}
                          </div>
                        )} />
                      </div>
                      <FormField control={form.control} name="alert_recipient_email" render={({ field }) => (
                        <FormItem>
                          <FormLabel>Additional recipient (optional)</FormLabel>
                          <p className="text-xs text-muted-foreground">Existing value is masked. Replace the mask only when changing it; leave it unchanged to keep the current address.</p>
                          <FormControl><Input {...field} type="email" placeholder="soc@example.com" /></FormControl>
                          <FormMessage />
                        </FormItem>
                      )} />
                    </div>
                  )}
                </div>

                {/* --- Telegram alerts --- */}
                <div className="rounded-lg border p-4 space-y-3">
                  <FormField control={form.control} name="telegram_alerts_enabled" render={({ field }) => (
                    <FormItem className="flex flex-row items-center justify-between">
                      <FormLabel className="!mb-0 font-medium">Telegram alerts</FormLabel>
                      <FormControl>
                        <Switch checked={!!field.value} onCheckedChange={field.onChange} aria-label="Enable telegram alerts" />
                      </FormControl>
                    </FormItem>
                  )} />
                  {form.watch("telegram_alerts_enabled") && (
                    <div className="space-y-3 pt-1">
                      <FormField control={form.control} name="telegram_chat_ids" render={({ field }) => (
                        <FormItem>
                          <FormLabel>Chat IDs (one per line)</FormLabel>
                          <FormControl>
                            <Textarea rows={3} {...field} onChange={(event) => { setTelegramValidation(null); field.onChange(event); }} placeholder={"-100123456789\n@soc_channel"} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )} />
                      <FormField control={form.control} name="telegram_bot_token" render={({ field }) => (
                        <FormItem>
                          <FormLabel>Bot token</FormLabel>
                          <FormControl><Input {...field} type="password" autoComplete="off" onChange={(event) => { setTelegramValidation(null); field.onChange(event); }} placeholder="123456:ABC-DEF..." /></FormControl>
                          <FormMessage />
                        </FormItem>
                      )} />
                      {telegramValidation && (
                        <div className="space-y-1 rounded-md border p-3 text-xs">
                          <div className="font-medium">Telegram chat validation: {telegramValidation.valid}/{telegramValidation.total} accessible</div>
                          {telegramValidation.results.map((result) => (
                            <div key={result.chat_id} className={result.ok ? "text-emerald-600" : "text-destructive"}>
                              {result.ok ? "✓" : "✗"} <span className="font-mono">{result.chat_id}</span> — {result.ok ? `${result.chat_type || "chat"} is accessible` : result.error}
                            </div>
                          ))}
                        </div>
                      )}
                      <div className="flex justify-end gap-2">
                        <Button type="button" variant="outline" size="sm" disabled={validateTgMut.isPending || saveMut.isPending || testTgMut.isPending} onClick={validateTelegramFromForm}>
                          {validateTgMut.isPending ? "Validating..." : "Validate chat IDs"}
                        </Button>
                        <Button type="button" variant="outline" size="sm" disabled={testTgMut.isPending || saveMut.isPending || validateTgMut.isPending} onClick={testTelegramFromForm}>
                          <SendIcon className="w-3.5 h-3.5 mr-2" />
                          {testTgMut.isPending ? "Sending..." : "Send test message"}
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Clock className="w-4 h-4 text-primary" />
                  Scan schedules
                </CardTitle>
                <CardDescription>
                  Automatic rescan times (UTC). Defaults run on weekdays at night.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <ScheduleRow
                  title="Phishing rescan"
                  description="Runs every enabled phishing connector against your monitored assets"
                  control={form.control}
                  daysName="schedule_phishing_days"
                  hourName="schedule_phishing_hour"
                  minuteName="schedule_phishing_minute"
                />
                <ScheduleRow
                  title="Breaches rescan"
                  description="Runs every enabled breach connector against your monitored mailboxes and domains"
                  control={form.control}
                  daysName="schedule_breaches_days"
                  hourName="schedule_breaches_hour"
                  minuteName="schedule_breaches_minute"
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Mail className="w-4 h-4 text-primary" />
                  SMTP (outbound email)
                </CardTitle>                  <CardDescription>
                  Outbound transport for email alert delivery. The security mode is explicit;
                  port 465 no longer silently changes the transport. Plain SMTP should only
                  be used for a trusted internal relay.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField control={form.control} name="smtp_host" render={({ field }) => (
                    <FormItem>
                      <FormLabel>Host</FormLabel>
                      <FormControl><Input {...field} placeholder="smtp.example.com" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )} />
                  <FormField control={form.control} name="smtp_port" render={({ field }) => (
                    <FormItem>
                      <FormLabel>Port</FormLabel>
                      <FormControl><Input {...field} value={field.value ?? ""} type="number" min={1} max={65535} placeholder="587" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )} />
                  <FormField control={form.control} name="smtp_security_mode" render={({ field }) => (
                    <FormItem>
                      <FormLabel>Security</FormLabel>
                      <Select value={field.value} onValueChange={field.onChange}>
                        <FormControl><SelectTrigger><SelectValue /></SelectTrigger></FormControl>
                        <SelectContent>
                          <SelectItem value="starttls">STARTTLS (recommended)</SelectItem>
                          <SelectItem value="ssl">Implicit TLS (SMTPS)</SelectItem>
                          <SelectItem value="plain">Plain SMTP (internal relay only)</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )} />
                  <FormField control={form.control} name="smtp_user" render={({ field }) => (
                    <FormItem>
                      <FormLabel>Username</FormLabel>
                      <FormControl><Input {...field} placeholder="smtp-user" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )} />
                  <FormField control={form.control} name="smtp_password" render={({ field }) => (
                    <FormItem>
                      <FormLabel>Password</FormLabel>
                      <FormControl><Input {...field} type="password" autoComplete="new-password" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )} />
                  <FormField control={form.control} name="smtp_from_email" render={({ field }) => (
                    <FormItem className="md:col-span-2">
                      <FormLabel>From address</FormLabel>
                      <p className="text-xs text-muted-foreground">Existing value is masked. Replace the mask only when changing it; leave it unchanged to keep the current address.</p>
                      <FormControl><Input {...field} type="email" placeholder="noreply@opendrp.example.com" /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )} />
                </div>

                <Separator />

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <Label htmlFor="test-email" className="!mb-0 whitespace-nowrap">Send test to</Label>
                    <Input
                      id="test-email"
                      type="email"
                      className="sm:max-w-xs"
                      placeholder="leave empty for default recipient"
                      value={testTo}
                      onChange={(e) => setTestTo(e.target.value)}
                    />
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    disabled={testMailMut.isPending || saveMut.isPending}
                    onClick={testEmailFromForm}
                  >
                    <Send className="w-4 h-4 mr-2" />
                    Send test email
                  </Button>
                </div>
              </CardContent>
            </Card>

            <div className="sticky bottom-6 z-20 pt-6">
              <div className="flex justify-end gap-3 p-3 rounded-xl border border-border bg-card/90 backdrop-blur shadow-lg">
                <Button type="submit" disabled={saveMut.isPending}>
                  <Save className="w-4 h-4 mr-2" />
                  {saveMut.isPending ? "Saving..." : "Save settings"}
                </Button>
              </div>
            </div>
          </form>
        </Form>
      )}
    </div>
  );
}

function ScheduleRow({
  title, description, control, daysName, hourName, minuteName,
}: {
  title: string;
  description: string;
  control: any;
  daysName: any;
  hourName: any;
  minuteName: any;
}) {
  const days = useController({ control, name: daysName }).field;
  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div>
        <div className="font-medium text-sm">{title}</div>
        <div className="text-xs text-muted-foreground">{description}</div>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {WEEKDAY_LABELS.map((label, idx) => {
          const cur: number[] = days.value || [];
          const checked = cur.includes(idx);
          return (
            <label
              key={idx}
              className={`px-2.5 py-1 rounded-md border text-xs cursor-pointer select-none transition-colors ${
                checked ? "bg-primary/15 border-primary/40 text-primary font-medium" : "text-muted-foreground hover:bg-accent/40"
              }`}
            >
              <input
                type="checkbox"
                className="sr-only"
                checked={checked}
                onChange={(e) => days.onChange(e.target.checked ? [...cur, idx].sort((a, b) => a - b) : cur.filter((d) => d !== idx))}
              />
              {label}
            </label>
          );
        })}
      </div>
      <div className="flex items-center gap-2">
        <HourMinuteSelect control={control} hourName={hourName} minuteName={minuteName} />
        <span className="text-xs text-muted-foreground">UTC</span>
      </div>
    </div>
  );
}

function HourMinuteSelect({ control, hourName, minuteName }: { control: any; hourName: any; minuteName: any }) {
  const hour = useController({ control, name: hourName }).field;
  const minute = useController({ control, name: minuteName }).field;
  return (
    <>
      <Select value={String(hour.value)} onValueChange={(v) => hour.onChange(Number(v))}>
        <SelectTrigger className="w-24 !h-8 text-xs" aria-label="Hour (UTC)"><SelectValue /></SelectTrigger>
        <SelectContent className="max-h-56">
          {Array.from({ length: 24 }, (_, h) => (
            <SelectItem key={h} value={String(h)} className="text-xs font-mono">{String(h).padStart(2, "0")}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      <span className="text-xs text-muted-foreground">:</span>
      <Select value={String(minute.value)} onValueChange={(v) => minute.onChange(Number(v))}>
        <SelectTrigger className="w-24 !h-8 text-xs" aria-label="Minute"><SelectValue /></SelectTrigger>
        <SelectContent className="max-h-56">
          {[0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55].map((m) => (
            <SelectItem key={m} value={String(m)} className="text-xs font-mono">{String(m).padStart(2, "0")}</SelectItem>
          ))}
        </SelectContent>
      </Select>
    </>
  );
}

/**
 * Per-connector settings form.
 *
 * The fields come from the connector's own manifest (`config_schema`), not from
 * a table in this file: a connector declares its settings at registration and
 * the form renders them, so a new data source is configurable the moment it
 * registers. Booleans render as toggles; other declared types render as a text
 * or number input that is saved on blur.
 */
function connectorFieldLabel(key: string, field: ConnectorConfigField): string {
  return field.label || humanizeKey(key);
}

function ConnectorRow({
  conn, onStatus, onConfig, onIssueToken, onRevokeToken, busy,
}: {
  conn: Connector;
  onStatus: (status: "enabled" | "disabled") => void;
  onConfig: (config: Record<string, unknown>) => void;
  onIssueToken: () => void;
  onRevokeToken: () => void;
  busy: boolean;
}) {
  const storedConfig: Record<string, unknown> = conn.config || {};
  const schema = conn.manifest?.config_schema || {};
  const declaredFields = Object.entries(schema);
  const seen = conn.last_seen_at ? formatDateTimeOrNever(conn.last_seen_at) : "never";
  // A connector is considered online when it checked in within the last 2 min.
  const online = conn.last_seen_at && (Date.now() - new Date(conn.last_seen_at).getTime()) < 120_000;

  const toggleCap = (key: string, value: boolean) => {
    // Merge into the stored object so keys this UI does not know about survive.
    onConfig({ ...storedConfig, [key]: value });
  };

  return (
    <div className="rounded-lg border p-4 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm font-mono">{conn.name}</span>
            <Badge variant="outline" className="text-[10px]">{conn.connector_type}</Badge>
            <span
              className={`inline-block w-2 h-2 rounded-full ${online ? "bg-emerald-500" : "bg-zinc-400"}`}
              title={online ? "Online" : "Offline"}
            />
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">
            v{conn.api_version || "?"} · last seen: {seen}
            {conn.last_error ? ` · last error: ${String(conn.last_error).slice(0, 160)}` : ""}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs text-muted-foreground">
            {conn.status === "enabled" ? "Enabled" : "Disabled"}
          </span>
          <Switch
            checked={conn.status === "enabled"}
            onCheckedChange={(v) => onStatus(v ? "enabled" : "disabled")}
            disabled={busy}
            aria-label={`Toggle ${conn.name}`}
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t text-xs">
        <span className="text-muted-foreground">
          {conn.has_token ? (
            <>
              Credential <span className="font-mono">{conn.token_prefix}…</span> ·{" "}
              {conn.token_last_used_at
                ? `last used ${formatDateTimeOrNever(conn.token_last_used_at)}`
                : "not used yet"}
            </>
          ) : (
            "No credential: this connector cannot authenticate or claim work yet."
          )}
        </span>
        <div className="flex items-center gap-2">
          <Button type="button" size="sm" variant="outline" onClick={onIssueToken} disabled={busy}>
            {conn.has_token ? "Rotate credential" : "Issue credential"}
          </Button>
          {conn.has_token && (
            <Button type="button" size="sm" variant="ghost" onClick={onRevokeToken} disabled={busy}>
              Revoke
            </Button>
          )}
        </div>
      </div>

      {declaredFields.length > 0 && conn.status === "enabled" && (
        <div className="flex flex-wrap gap-4 pt-1 border-t">
          {declaredFields.map(([key, field]) => {
            const stored = storedConfig[key];
            if (field.type === "bool") {
              const checked = typeof stored === "boolean" ? stored : field.default !== false;
              return (
                <label key={key} className="flex items-center gap-2 text-xs cursor-pointer mt-2">
                  <input
                    type="checkbox"
                    className="accent-[hsl(var(--primary))]"
                    checked={checked}
                    disabled={busy}
                    onChange={(e) => toggleCap(key, e.target.checked)}
                  />
                  {connectorFieldLabel(key, field)}
                </label>
              );
            }
            return (
              <label key={key} className="flex flex-col gap-1 text-xs mt-2">
                {connectorFieldLabel(key, field)}
                <Input
                  type={field.type === "str" ? "text" : "number"}
                  className="h-8 w-40"
                  defaultValue={stored === undefined || stored === null ? String(field.default ?? "") : String(stored)}
                  disabled={busy}
                  aria-label={connectorFieldLabel(key, field)}
                  // Saved on blur, not per keystroke: one request per edit.
                  onBlur={(e) => {
                    const next = e.target.value;
                    if (String(stored ?? "") === next) return;
                    onConfig({ ...storedConfig, [key]: next });
                  }}
                />
              </label>
            );
          })}
        </div>
      )}
    </div>
  );
}
