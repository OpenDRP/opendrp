import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SettingsPage from "@/pages/SettingsPage";

const {
  getSettingsMock,
  getAlertPolicyMock,
  updateSettingsMock,
  listUsersBriefMock,
  listConnectorsMock,
  listSourceAccountsMock,
  createSourceAccountMock,
  approveSourceAccountMock,
  setSourceAccountApiKeyMock,
  clearSourceAccountApiKeyMock,
  bindConnectorAccountMock,
  setConnectorStatusMock,
  setConnectorConfigMock,
  sendTestEmailMock,
  sendTestTelegramMock,
  validateTelegramChatsMock,
  toastMock,
} = vi.hoisted(() => ({
  getSettingsMock: vi.fn(),
  getAlertPolicyMock: vi.fn(),
  updateSettingsMock: vi.fn(),
  listUsersBriefMock: vi.fn(),
  listConnectorsMock: vi.fn(),
  listSourceAccountsMock: vi.fn(),
  createSourceAccountMock: vi.fn(),
  approveSourceAccountMock: vi.fn(),
  setSourceAccountApiKeyMock: vi.fn(),
  clearSourceAccountApiKeyMock: vi.fn(),
  bindConnectorAccountMock: vi.fn(),
  setConnectorStatusMock: vi.fn(),
  setConnectorConfigMock: vi.fn(),
  sendTestEmailMock: vi.fn(),
  sendTestTelegramMock: vi.fn(),
  validateTelegramChatsMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    getSettings: getSettingsMock,
    getAlertPolicy: getAlertPolicyMock,
    alertQueue: vi.fn().mockResolvedValue({ counts: {}, items: [] }),
    updateSettings: updateSettingsMock,
    listUsersBrief: listUsersBriefMock,
    listConnectors: listConnectorsMock,
    listSourceAccounts: listSourceAccountsMock,
    createSourceAccount: createSourceAccountMock,
    approveSourceAccount: approveSourceAccountMock,
    setSourceAccountApiKey: setSourceAccountApiKeyMock,
    clearSourceAccountApiKey: clearSourceAccountApiKeyMock,
    bindConnectorAccount: bindConnectorAccountMock,
    setConnectorStatus: setConnectorStatusMock,
    setConnectorConfig: setConnectorConfigMock,
    sendTestEmail: sendTestEmailMock,
    sendTestTelegram: sendTestTelegramMock,
    validateTelegramChats: validateTelegramChatsMock,
  },
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
  describeApiError: (error: any) => { const d = error?.response?.data?.detail; if (typeof d === "string") return d; if (Array.isArray(d)) return d.map((x: any) => x?.msg ?? String(x)).join("; "); return String(error?.message ?? error ?? ""); },
}));

const { issueConnectorTokenMock, revokeConnectorTokenMock } = vi.hoisted(() => ({
  issueConnectorTokenMock: vi.fn(),
  revokeConnectorTokenMock: vi.fn(),
}));

vi.mock("@/lib/connectors", () => ({
  issueConnectorToken: issueConnectorTokenMock,
  revokeConnectorToken: revokeConnectorTokenMock,
}));

const { fetchModulesMock, updateModuleMock } = vi.hoisted(() => ({
  fetchModulesMock: vi.fn(),
  updateModuleMock: vi.fn(),
}));

vi.mock("@/lib/modules", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/modules")>()),
  fetchModules: fetchModulesMock,
  updateModule: updateModuleMock,
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));

const settings = {
  id: "settings-1",
  version: 7,
  smtp_host: "smtp.example.com",
  smtp_port: 587,
  smtp_user: "smtp-user",
  smtp_from_email: "noreply@example.com",
  alert_recipient_email: "soc@example.com",
  email_alerts_enabled: false,
  telegram_alerts_enabled: false,
  alert_email_user_ids: [],
  telegram_chat_ids: [],
  schedule_phishing: { days: [1, 2, 3, 4, 5], hour: 2, minute: 30 },
  schedule_breaches: { days: [1, 2, 3, 4, 5], hour: 3, minute: 30 },
  schedule_dns_security: { days: [1, 2, 3, 4, 5], hour: 4, minute: 0 },
  schedules: { code_leak: { days: [2, 4], hour: 7, minute: 15 } },
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <SettingsPage />
    </QueryClientProvider>,
  );
}

describe("SettingsPage", () => {
  beforeEach(() => {
    getSettingsMock.mockReset().mockResolvedValue(settings);
    // The alert budget in force (WI-13): what the page shows next to the six
    // stored values, since a value nobody saved is the deployment's.
    getAlertPolicyMock.mockReset().mockResolvedValue({
      confidence_direct: 60,
      confidence_digest: 30,
      digest_enabled: true,
      digest_hour_utc: 6,
      no_channel_retry_hours: 24,
      candidate_change_notifications: true,
      source: "environment",
      invalid: [],
    });
    updateSettingsMock.mockReset().mockResolvedValue(settings);
    listUsersBriefMock.mockReset().mockResolvedValue([
      { id: "user-1", email: "admin@example.com", role: "admin" },
    ]);
    listSourceAccountsMock.mockReset().mockResolvedValue([]);
    createSourceAccountMock.mockReset().mockResolvedValue({ id: "new-account" });
    approveSourceAccountMock.mockReset().mockResolvedValue({ id: "account-1", policy: { approved: true, requests_per_minute: 10, daily_budget: 100 } });
    bindConnectorAccountMock.mockReset().mockResolvedValue({});
    listConnectorsMock.mockReset().mockResolvedValue([
      {
        id: "connector-1",
        name: "shodan",
        connector_type: "phishing",
        status: "enabled",
        api_version: "1",
        config: { scan_ssl_text: true, scan_http_title: true, scan_favicon: true },
      },
    ]);
    setConnectorStatusMock.mockReset().mockResolvedValue({ name: "shodan", status: "disabled" });
    setConnectorConfigMock.mockReset().mockResolvedValue({ name: "shodan" });
    issueConnectorTokenMock.mockReset();
    revokeConnectorTokenMock.mockReset();
    fetchModulesMock.mockReset().mockResolvedValue({
      modules: [
        {
          id: "phishing",
          label: "Phishing",
          finding_kind: "phishing",
          asset_types: ["domain"],
          fields: {},
          dedup_fields: ["phishing_domain"],
          title_field: "phishing_domain",
          storage: "table",
          enabled: true,
          builtin: true,
        },
        {
          id: "code_leak",
          label: "Code leaks",
          description: "Secrets in public repositories.",
          finding_kind: "code_leak",
          asset_types: ["domain"],
          fields: { repository: { type: "str" }, secret_kind: { type: "str" } },
          dedup_fields: ["repository", "secret_kind"],
          title_field: "repository",
          storage: "generic",
          enabled: true,
          builtin: false,
        },
      ],
      generated_at: "2026-01-01T00:00:00Z",
    });
    updateModuleMock.mockReset().mockResolvedValue({ id: "code_leak", label: "Code leaks", enabled: false });
    sendTestEmailMock.mockReset().mockResolvedValue({ to: "soc@example.com" });
    sendTestTelegramMock.mockReset().mockResolvedValue({ sent: 1, total: 1, validated: 1, validation_failed: 0, results: [{ chat_id: "14283692", ok: true }] });
    validateTelegramChatsMock.mockReset().mockResolvedValue({ valid: 1, total: 1, results: [{ chat_id: "14283692", ok: true, chat_type: "private" }] });
    toastMock.mockReset();
  });

  it("loads settings and connector state without exposing loading skeleton", async () => {
    renderPage();

    expect(await screen.findByRole("heading", { name: "Settings" })).toBeInTheDocument();
    expect(await screen.findByDisplayValue("smtp.example.com")).toBeInTheDocument();
    expect(screen.getByText("shodan")).toBeInTheDocument();
    expect(screen.getByText(/SDK v1/)).toBeInTheDocument();
    expect(screen.getByText("Connectors")).toBeInTheDocument();
    expect(screen.getByText("DNS Security rescan")).toBeInTheDocument();
    expect(screen.getByText("Code leaks schedule")).toBeInTheDocument();
    expect(screen.getByText("Code leaks schedule")).toBeInTheDocument();
    expect(getSettingsMock).toHaveBeenCalledTimes(1);
    // A connector without a credential cannot authenticate: say so, and offer
    // the action that fixes it instead of pretending it is simply offline.
    expect(screen.getByText(/No credential/)).toBeInTheDocument();
  });

  it("labels connector SDK versions and handles missing registration versions explicitly", async () => {
    listConnectorsMock.mockResolvedValue([
      {
        id: "netlas-dns-security",
        name: "netlas-dns-security-default",
        connector_type: "dns",
        status: "disabled",
        api_version: null,
        provider: "netlas",
        readiness: { credentials_configured: false, credential_state: "unknown", capabilities: [] },
      },
    ]);
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");
    expect(screen.getByText("SDK version not reported · last seen: never")).toBeInTheDocument();
    expect(screen.queryByText("v? · last seen: never")).not.toBeInTheDocument();
  });

  it("stores a provider API key write-only and shows only its hint", async () => {
    setSourceAccountApiKeyMock.mockReset().mockResolvedValue({ id: "account-1", has_api_key: true, api_key_hint: "****9999" });
    clearSourceAccountApiKeyMock.mockReset().mockResolvedValue({ id: "account-1", has_api_key: false, api_key_hint: null });
    listConnectorsMock.mockResolvedValue([{ id: "netlas-one", name: "netlas-exposure", connector_type: "exposure", status: "disabled", provider: "netlas", has_token: true }]);
    listSourceAccountsMock.mockResolvedValue([{ id: "account-1", source_id: "netlas", name: "default", credential_ref: "NETLAS_API_TOKEN", policy: { approved: false }, access_state: "unknown", has_api_key: true, api_key_hint: "****1234" }]);
    renderPage();
    expect(await screen.findByText("API key stored (****1234)")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("default API key"), { target: { value: "new-secret-9999" } });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    await waitFor(() => expect(setSourceAccountApiKeyMock).toHaveBeenCalledWith("account-1", "new-secret-9999"));
    expect(screen.getByLabelText("default API key")).toHaveValue("");
    expect(document.body.textContent).not.toContain("new-secret-9999");
    fireEvent.click(screen.getByRole("button", { name: "Remove key" }));
    await waitFor(() => expect(clearSourceAccountApiKeyMock).toHaveBeenCalledWith("account-1"));
    // Four sequential render-and-wait steps over the whole settings page. It runs
    // in about a second unwrapped and passed five under instrumentation, which is
    // why the test above it already carries this budget: without it, a full
    // `test:coverage` run intermittently timed out here while the same test passed
    // in isolation.
  }, 15000);

  it("creates and approves a provider account quota explicitly", async () => {
    listConnectorsMock.mockResolvedValue([{ id: "netlas-one", name: "netlas-exposure", connector_type: "exposure", status: "disabled", provider: "netlas", has_token: true }]);
    listSourceAccountsMock.mockResolvedValue([{ id: "account-1", source_id: "netlas", name: "default", credential_ref: "NETLAS_API_KEY", policy: { approved: false }, access_state: "unknown" }]);
    renderPage();
    fireEvent.change(await screen.findByLabelText("New account provider"), { target: { value: "netlas" } });
    fireEvent.change(screen.getByLabelText("New account name"), { target: { value: "account-2" } });
    fireEvent.change(screen.getByLabelText("Credential reference"), { target: { value: "NETLAS_API_KEY_SECOND" } });
    fireEvent.click(screen.getByRole("button", { name: "Create account" }));
    await waitFor(() => expect(createSourceAccountMock).toHaveBeenCalledWith({ source_id: "netlas", name: "account-2", credential_ref: "NETLAS_API_KEY_SECOND" }));
    expect(screen.getByText(/secret ref: NETLAS_API_KEY/)).toBeInTheDocument();
    expect(screen.getByLabelText("Credential reference")).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Approve quota" })[0]);
    await waitFor(() => expect(approveSourceAccountMock).toHaveBeenCalledWith("account-1", { approved: true, requests_per_minute: 10, daily_budget: 100 }));
    fireEvent.change(screen.getByLabelText("Account for netlas-exposure"), { target: { value: "account-1" } });
    await waitFor(() => expect(bindConnectorAccountMock).toHaveBeenCalledWith("netlas-one", "account-1"));
  }, 15000);

  it("allows explicit first validation for configured online providers without validating during setup", async () => {
    const user = userEvent.setup();
    listConnectorsMock.mockResolvedValue([{
      id: "netlas-exposure-id", name: "netlas-exposure", connector_type: "exposure", status: "disabled", provider: "netlas", quota_group: "default", has_token: true,
      last_seen_at: new Date().toISOString(), readiness: { credentials_configured: true, credential_state: "unknown", capabilities: ["hostname", "ip"] },
    }]);
    renderPage();
    await screen.findByRole("heading", { name: "Opt-in intelligence setup" });
    expect(screen.getByText(/Provider key: unknown/)).toBeInTheDocument();
    expect(screen.getByText(/configured but not yet validated/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Enable for first validation" }));
    await waitFor(() => expect(setConnectorStatusMock).toHaveBeenCalledWith("netlas-exposure-id", "enabled"));
  });

  it.each([
    ["invalid", true],
    ["unsupported", true],
    ["unknown", false],
  ])("does not offer provider opt-in for %s credentials or an offline worker", async (credentialState, online) => {
    listConnectorsMock.mockResolvedValue([{
      id: "netlas-exposure-id", name: "netlas-exposure", connector_type: "exposure", status: "disabled", provider: "netlas", quota_group: "default", has_token: true,
      last_seen_at: online ? new Date().toISOString() : "2020-01-01T00:00:00Z",
      readiness: { credentials_configured: true, credential_state: credentialState, capabilities: ["hostname", "ip"] },
    }]);
    renderPage();
    await screen.findByRole("heading", { name: "Opt-in intelligence setup" });
    expect(screen.queryByRole("button", { name: /Enable/ })).not.toBeInTheDocument();
    expect(setConnectorStatusMock).not.toHaveBeenCalled();
  });

  it("does not offer opt-in when a worker advertises no capabilities", async () => {
    listConnectorsMock.mockResolvedValue([{
      id: "netlas-phishing-id", name: "netlas-phishing", connector_type: "phishing", status: "disabled", provider: "netlas", quota_group: "default", has_token: true,
      last_seen_at: new Date().toISOString(), readiness: { credentials_configured: true, credential_state: "unknown", capabilities: [] },
    }]);
    renderPage();
    await screen.findByRole("heading", { name: "Opt-in intelligence setup" });
    expect(screen.getByText(/advertises no supported capabilities/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Enable/ })).not.toBeInTheDocument();
    expect(setConnectorStatusMock).not.toHaveBeenCalled();
  });

  it("shows normalized provider access failures and blocks enabling until fixed", async () => {
    listConnectorsMock.mockResolvedValue([{
      id: "netlas-exposure-id", name: "netlas-exposure", connector_type: "exposure", status: "disabled", provider: "netlas", quota_group: "default", has_token: true,
      last_seen_at: new Date().toISOString(), readiness: { credentials_configured: true, credential_state: "unknown", provider_error: "credits_exhausted", capabilities: ["ip"] },
    }]);
    renderPage();
    await screen.findByRole("heading", { name: "Opt-in intelligence setup" });
    expect(screen.getByText("Provider API: credits exhausted")).toBeInTheDocument();
    expect(screen.getByText(/correct the provider account, credits, network access, or API key/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Enable/ })).not.toBeInTheDocument();
    expect(setConnectorStatusMock).not.toHaveBeenCalled();
  });

  it("enables a provider immediately when credentials are already validated", async () => {
    const user = userEvent.setup();
    listConnectorsMock.mockResolvedValue([{
      id: "netlas-exposure-id", name: "netlas-exposure", connector_type: "exposure", status: "disabled", provider: "netlas", quota_group: "default", has_token: true,
      last_seen_at: new Date().toISOString(), readiness: { credentials_configured: true, credential_state: "valid", capabilities: ["hostname", "ip"] },
    }]);
    renderPage();
    await screen.findByRole("heading", { name: "Opt-in intelligence setup" });
    await user.click(screen.getByRole("button", { name: "Enable this source" }));
    await waitFor(() => expect(setConnectorStatusMock).toHaveBeenCalledWith("netlas-exposure-id", "enabled"));
  });

  it("lists the module registry and toggles a declared module", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");

    // The registry is what the platform can collect: declared modules show
    // their fields and deduplication, built-ins are marked as such.
    expect(screen.getByText("Code leaks")).toBeInTheDocument();
    expect(screen.getByText("built-in")).toBeInTheDocument();
    expect(screen.getByText(/2 declared fields/)).toBeInTheDocument();
    expect(screen.getByText(/deduplicated on repository, secret_kind/)).toBeInTheDocument();

    await user.click(screen.getByRole("switch", { name: "Toggle module Code leaks" }));
    await waitFor(() =>
      expect(updateModuleMock).toHaveBeenCalledWith("code_leak", { enabled: false }),
    );
  });

  it("issues a connector credential and states that it is shown once", async () => {
    const user = userEvent.setup();
    issueConnectorTokenMock.mockResolvedValue({
      connector: {
        id: "connector-1",
        name: "shodan",
        has_token: true,
        token_prefix: "opendrp_shodan_",
      },
      token: "opendrp_shodan_secret-value",
      rotated: false,
    });
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");

    await user.click(screen.getByRole("button", { name: "Issue credential" }));

    await waitFor(() => expect(issueConnectorTokenMock).toHaveBeenCalledWith("connector-1"));
    expect(await screen.findByText("opendrp_shodan_secret-value")).toBeInTheDocument();
    expect(screen.getByText(/Shown once/)).toBeInTheDocument();
  });

  it("asks before revoking a connector credential, then keeps the connector", async () => {
    const user = userEvent.setup();
    listConnectorsMock.mockResolvedValue([
      {
        id: "connector-1",
        name: "shodan",
        connector_type: "phishing",
        status: "enabled",
        api_version: "1",
        has_token: true,
        token_prefix: "opendrp_shodan_",
      },
    ]);
    revokeConnectorTokenMock.mockResolvedValue({ id: "connector-1", name: "shodan" });
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");

    // The button sits beside "Rotate credential"; a misclick would stop the
    // worker claiming work until a new token is issued and its container recreated.
    await user.click(screen.getByRole("button", { name: "Revoke" }));
    expect(revokeConnectorTokenMock).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(/can no longer claim work/)).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Revoke credential" }));

    await waitFor(() => expect(revokeConnectorTokenMock).toHaveBeenCalledWith("connector-1"));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Credential revoked for shodan" }),
    );
  });

  it("reads and keeps a schedule minute the API allows off the five-minute grid", async () => {
    // The API accepts 0..59; the control used to offer only a five-minute grid. A
    // stored 17 was not drawable, so it rendered blank — and Radix answers a value
    // it cannot resolve with `onValueChange("")`, which this form stores as 0 and
    // marks dirty. That made the next save of an *unrelated* field move the scan.
    getSettingsMock.mockResolvedValue({
      ...settings,
      schedule_phishing: { days: [1, 2, 3, 4, 5], hour: 2, minute: 17 },
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");

    // The phishing schedule is the first one rendered, so its minute control is
    // the first "Minute" trigger on the page.
    expect(screen.getAllByLabelText("Minute")[0]).toHaveTextContent("17");

    await user.click(screen.getByRole("switch", { name: "Enable email alerts" }));
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() => expect(updateSettingsMock).toHaveBeenCalled());
    const payload = updateSettingsMock.mock.calls[0][0];
    // Nothing touched the schedule, so nothing about it may travel — least of all
    // a minute the page invented while rendering it.
    expect(payload).not.toHaveProperty("schedule_phishing");
    expect(payload).not.toHaveProperty("schedule_phishing_minute");
  });

  it("saves notification settings and reports connector status changes", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");

    await user.click(screen.getByRole("switch", { name: "Enable email alerts" }));
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(updateSettingsMock).toHaveBeenCalledWith(
        expect.objectContaining({
          email_alerts_enabled: true,
          expected_version: 7,
        }),
      ),
    );

    expect(updateSettingsMock.mock.calls[0][0]).not.toHaveProperty("schedule_dns_security");
    expect(updateSettingsMock.mock.calls[0][0]).not.toHaveProperty("schedules");
    await user.click(screen.getByRole("switch", { name: "Toggle shodan" }));
    await waitFor(() =>
      expect(setConnectorStatusMock).toHaveBeenCalledWith("connector-1", "disabled"),
    );
  });

  it("preserves disabled schedules on unrelated saves and explicitly enables them", async () => {
    getSettingsMock.mockResolvedValue({ ...settings, schedule_phishing: null, schedule_breaches: null, schedule_dns_security: null });
    const user = userEvent.setup();
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");
    expect(screen.getByRole("switch", { name: "Enable phishing schedule" })).not.toBeChecked();
    await user.click(screen.getByRole("switch", { name: "Enable email alerts" }));
    await user.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(updateSettingsMock).toHaveBeenCalledWith({ email_alerts_enabled: true, expected_version: 7 }));
    await user.click(screen.getByRole("switch", { name: "Enable phishing schedule" }));
    await user.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(updateSettingsMock).toHaveBeenLastCalledWith(expect.objectContaining({ schedule_phishing: { days: [1, 2, 3, 4, 5], hour: 2, minute: 30 } })));
  });

  it("saves newly entered Telegram settings before sending a test message", async () => {
    const user = userEvent.setup();
    sendTestTelegramMock.mockResolvedValue({ sent: 1, total: 1, results: [] });
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");

    await user.click(screen.getByRole("switch", { name: "Enable telegram alerts" }));
    await user.type(screen.getByLabelText("Chat IDs (one per line)"), "14283692");
    await user.type(screen.getByLabelText("Bot token"), "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    await user.click(screen.getByRole("button", { name: "Send test message" }));

    await waitFor(() => expect(updateSettingsMock).toHaveBeenCalledWith(
      expect.objectContaining({
        telegram_alerts_enabled: true,
        telegram_chat_ids: "14283692",
        telegram_bot_token: "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      }),
    ));
    await waitFor(() => expect(sendTestTelegramMock).toHaveBeenCalledWith(undefined));
  });

  it("validates Telegram chats and renders per-chat diagnostics", async () => {
    const user = userEvent.setup();
    validateTelegramChatsMock.mockResolvedValue({
      valid: 1,
      total: 2,
      results: [
        { chat_id: "14283692", ok: true, chat_type: "private" },
        { chat_id: "-100123456789", ok: false, error_code: "chat_not_found", error: "Telegram cannot find this chat or the bot cannot access it." },
      ],
    });
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");
    await user.click(screen.getByRole("switch", { name: "Enable telegram alerts" }));
    await user.type(screen.getByLabelText("Chat IDs (one per line)"), "14283692,-100123456789");
    await user.type(screen.getByLabelText("Bot token"), "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    await user.click(screen.getByRole("button", { name: "Validate chat IDs" }));

    await waitFor(() => expect(validateTelegramChatsMock).toHaveBeenCalledWith());
    expect(await screen.findByText(/1\/2 accessible/)).toBeInTheDocument();
    expect(screen.getByText(/chat_not_found|Telegram cannot find this chat/)).toBeInTheDocument();
  });

  // Seven fields typed through `userEvent`, each keystroke a re-render of this
  // page: under the parallel suite run this is the heaviest interaction here, so
  // it takes the same explicit budget as the quota test above instead of the
  // suite's five-second default. No assertion is relaxed to fit in it.
  it(
    "saves newly entered SMTP settings before sending a test email",
    async () => {
      const user = userEvent.setup();
      renderPage();
    await screen.findByDisplayValue("smtp.example.com");

      await user.clear(screen.getByLabelText("Host"));
      await user.type(screen.getByLabelText("Host"), "smtp.sandbox.mailtrap.io");
      await user.clear(screen.getByLabelText("Port"));
      await user.type(screen.getByLabelText("Port"), "2525");
      await user.clear(screen.getByLabelText("Username"));
      await user.type(screen.getByLabelText("Username"), "mailtrap-user");
      await user.type(screen.getByLabelText("Password"), "mailtrap-password");
      await user.clear(screen.getByLabelText("From address"));
      await user.type(screen.getByLabelText("From address"), "from@example.com");
      await user.type(screen.getByLabelText("Send test to"), "to@example.com");
      await user.click(screen.getByRole("button", { name: "Send test email" }));

      await waitFor(() => expect(updateSettingsMock).toHaveBeenCalledWith(
        expect.objectContaining({
          smtp_host: "smtp.sandbox.mailtrap.io",
          smtp_port: 2525,
          smtp_user: "mailtrap-user",
          smtp_password: "mailtrap-password",
          smtp_from_email: "from@example.com",
        }),
      ));
      await waitFor(() => expect(sendTestEmailMock).toHaveBeenCalledWith("to@example.com"));
      expect(updateSettingsMock.mock.invocationCallOrder[0]).toBeLessThan(
        sendTestEmailMock.mock.invocationCallOrder[0],
      );
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Test email sent" }),
      );
    },
    15000,
  );

  // The render plus the typed fields run past the 5 s default on a loaded CI
  // runner; the neighbour above carries the same bound for the same reason.
  it("surfaces SMTP test-email errors", async () => {
    const user = userEvent.setup();
    sendTestEmailMock.mockRejectedValueOnce({ response: { data: { detail: "SMTP unavailable" } } });
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");
    await user.type(screen.getByLabelText("Send test to"), "security@example.com");
    await user.click(screen.getByRole("button", { name: "Send test email" }));
    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive", title: "Test email failed" }),
      ),
    );
  }, 15000);
});
