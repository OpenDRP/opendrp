import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SettingsPage from "@/pages/SettingsPage";

const {
  getSettingsMock,
  updateSettingsMock,
  listUsersBriefMock,
  listConnectorsMock,
  setConnectorStatusMock,
  setConnectorConfigMock,
  sendTestEmailMock,
  sendTestTelegramMock,
  validateTelegramChatsMock,
  toastMock,
} = vi.hoisted(() => ({
  getSettingsMock: vi.fn(),
  updateSettingsMock: vi.fn(),
  listUsersBriefMock: vi.fn(),
  listConnectorsMock: vi.fn(),
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
    updateSettings: updateSettingsMock,
    listUsersBrief: listUsersBriefMock,
    listConnectors: listConnectorsMock,
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
    updateSettingsMock.mockReset().mockResolvedValue(settings);
    listUsersBriefMock.mockReset().mockResolvedValue([
      { id: "user-1", email: "admin@example.com", role: "admin" },
    ]);
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
    expect(screen.getByText("Connectors")).toBeInTheDocument();
    expect(getSettingsMock).toHaveBeenCalledTimes(1);
    // A connector without a credential cannot authenticate: say so, and offer
    // the action that fixes it instead of pretending it is simply offline.
    expect(screen.getByText(/No credential/)).toBeInTheDocument();
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

  it("revokes a connector credential without dropping the connector", async () => {
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

    await user.click(screen.getByRole("button", { name: "Revoke" }));

    await waitFor(() => expect(revokeConnectorTokenMock).toHaveBeenCalledWith("connector-1"));
    expect(toastMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Credential revoked for shodan" }),
    );
  });

  it("saves notification settings and reports connector status changes", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByDisplayValue("smtp.example.com");

    await user.click(screen.getByRole("switch", { name: "Enable email alerts" }));
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(updateSettingsMock).toHaveBeenCalledWith(
        expect.objectContaining({ email_alerts_enabled: true }),
      ),
    );

    await user.click(screen.getByRole("switch", { name: "Toggle shodan" }));
    await waitFor(() =>
      expect(setConnectorStatusMock).toHaveBeenCalledWith("connector-1", "disabled"),
    );
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

  it("saves newly entered SMTP settings before sending a test email", async () => {
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
  });

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
  });
});
