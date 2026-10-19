import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SettingsPage from "@/pages/SettingsPage";

/**
 * The alert budget section of the Settings page (WI-13).
 *
 * Six values decide how loud the channel is, and the section has to keep three
 * different states of each one apart: not stated (the deployment's `ALERT_*`
 * environment answers it), on, and off. These tests pin the part a careless UI gets
 * wrong — that a blank field is *not* zero, that only what the operator changed is
 * submitted, and that a value in force is shown even though the row that stores it
 * is empty.
 */

const {
  getSettingsMock,
  updateSettingsMock,
  getAlertPolicyMock,
  listUsersBriefMock,
  listConnectorsMock,
  listSourceAccountsMock,
  toastMock,
} = vi.hoisted(() => ({
  getSettingsMock: vi.fn(),
  updateSettingsMock: vi.fn(),
  getAlertPolicyMock: vi.fn(),
  listUsersBriefMock: vi.fn(),
  listConnectorsMock: vi.fn(),
  listSourceAccountsMock: vi.fn(),
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
    createSourceAccount: vi.fn(),
    approveSourceAccount: vi.fn(),
    setSourceAccountApiKey: vi.fn(),
    clearSourceAccountApiKey: vi.fn(),
    bindConnectorAccount: vi.fn(),
    setConnectorStatus: vi.fn(),
    setConnectorConfig: vi.fn(),
    sendTestEmail: vi.fn(),
    sendTestTelegram: vi.fn(),
    validateTelegramChats: vi.fn(),
  },
  flattenErrorDetail: (detail: unknown) => String(detail ?? ""),
  describeApiError: (error: any) => {
    const d = error?.response?.data?.detail;
    if (typeof d === "string") return d;
    return String(error?.message ?? error ?? "");
  },
}));

vi.mock("@/lib/connectors", () => ({
  issueConnectorToken: vi.fn(),
  revokeConnectorToken: vi.fn(),
}));

vi.mock("@/lib/modules", () => ({
  fetchModules: vi.fn().mockResolvedValue({ modules: [], generated_at: "2026-01-01T00:00:00Z" }),
  updateModule: vi.fn(),
}));

vi.mock("@/components/ui/use-toast", () => ({ toast: toastMock }));

// Radix Select does not open in jsdom (it needs pointer capture), so the
// primitives render as a native select — the same substitution the phishing
// sort/score tests use, and it keeps the panel's own value/onChange wiring
// under test.
vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: any) => (
    <select value={value} onChange={(event) => onValueChange(event.target.value)}>
      {children}
    </select>
  ),
  SelectTrigger: () => null,
  SelectValue: () => null,
  SelectContent: ({ children }: any) => <>{children}</>,
  SelectItem: ({ value, children }: any) => <option value={value}>{children}</option>,
}));

/** The stored row: nothing stated yet, which is what a fresh installation holds. */
const settingsRow = {
  id: "settings-1",
  version: 7,
  smtp_host: "smtp.example.com",
  smtp_port: 587,
  smtp_security_mode: "starttls",
  email_alerts_enabled: false,
  telegram_alerts_enabled: false,
  alert_email_user_ids: [],
  telegram_chat_ids: [],
  alert_confidence_direct: null,
  alert_confidence_digest: null,
  alert_phishing_digest_enabled: null,
  alert_phishing_digest_hour_utc: null,
  alert_no_channel_retry_hours: null,
  alert_candidate_change_notifications: null,
  schedules: {},
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

/** What is in force before anything is saved: the deployment's own values. */
const environmentPolicy = {
  confidence_direct: 60,
  confidence_digest: 30,
  digest_enabled: true,
  digest_hour_utc: 6,
  no_channel_retry_hours: 24,
  candidate_change_notifications: true,
  source: "environment" as const,
  invalid: [],
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

/** The panel's two switches: the selects whose options are the on/off pair.
 *
 * Identified by the option set rather than by position, because the panel holds
 * other tri-state selects — the breach noise policy is also "a value, or not decided
 * here" — and document order is what a later field would reorder. Only these two
 * carry the on/off pair, and `BUDGET_TOGGLE_FIELDS` keeps the digest switch first.
 */
function budgetSwitches(): HTMLSelectElement[] {
  return Array.from(document.querySelectorAll("select")).filter((node) =>
    Array.from((node as HTMLSelectElement).options).some((option) => option.value === "on"),
  ) as HTMLSelectElement[];
}

async function loaded() {
  renderPage();
  await screen.findByDisplayValue("smtp.example.com");
}

describe("SettingsPage alert budget", () => {
  beforeEach(() => {
    getSettingsMock.mockReset().mockResolvedValue(settingsRow);
    getAlertPolicyMock.mockReset().mockResolvedValue(environmentPolicy);
    updateSettingsMock.mockReset().mockResolvedValue(settingsRow);
    listUsersBriefMock.mockReset().mockResolvedValue([]);
    listConnectorsMock.mockReset().mockResolvedValue([]);
    listSourceAccountsMock.mockReset().mockResolvedValue([]);
    toastMock.mockReset();
  });

  it("shows blank fields as the deployment's answer and says what is in force", async () => {
    await loaded();

    expect(screen.getByText("Alert budget")).toBeInTheDocument();
    // Blank, not zero: an input nobody has filled in must not read as a decision.
    expect(screen.getByLabelText("Direct alert score")).toHaveValue(null);
    expect(screen.getByLabelText("Digest threshold")).toHaveValue(null);
    expect(screen.getByLabelText("No-channel hold (hours)")).toHaveValue(null);
    expect(screen.getByLabelText("Digest hour (UTC)")).toHaveValue(null);

    // The value that is actually routing is the environment's, and the page says so
    // rather than leaving the operator to guess what a blank field means.
    expect(await screen.findByText(/alerts at score ≥ 60/)).toBeInTheDocument();
    expect(screen.getByText(/digest at 06:15 UTC for scores 30–59/)).toBeInTheDocument();
    expect(screen.getByText(/Nothing is saved yet/)).toBeInTheDocument();
  });

  it("submits only the edited value, as the number the API stores", async () => {
    const user = userEvent.setup();
    await loaded();

    fireEvent.change(screen.getByLabelText("Direct alert score"), { target: { value: "45" } });
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(updateSettingsMock).toHaveBeenCalledWith({
        alert_confidence_direct: 45,
        expected_version: 7,
      }),
    );
  });

  it("clears an override when the field is left blank", async () => {
    getSettingsMock.mockResolvedValue({
      ...settingsRow,
      alert_confidence_direct: 45,
      alert_confidence_digest: 15,
    });
    getAlertPolicyMock.mockResolvedValue({
      ...environmentPolicy,
      confidence_direct: 45,
      confidence_digest: 15,
      source: "settings" as const,
    });
    const user = userEvent.setup();
    await loaded();

    expect(screen.getByLabelText("Direct alert score")).toHaveValue(45);
    expect(await screen.findByText(/Saved values answer where they are set/)).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Direct alert score"), { target: { value: "" } });
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(updateSettingsMock).toHaveBeenCalledWith({
        alert_confidence_direct: null,
        expected_version: 7,
      }),
    );
  });

  it("sends the switch states as the row's three states", async () => {
    const user = userEvent.setup();
    await loaded();

    const [digest] = budgetSwitches();
    expect(digest).toHaveValue("default");

    fireEvent.change(digest, { target: { value: "off" } });
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(updateSettingsMock).toHaveBeenCalledWith({
        alert_phishing_digest_enabled: false,
        expected_version: 7,
      }),
    );
  });

  it("returns a stated switch to the deployment's value", async () => {
    getSettingsMock.mockResolvedValue({
      ...settingsRow,
      alert_phishing_digest_enabled: true,
      alert_candidate_change_notifications: false,
    });
    const user = userEvent.setup();
    await loaded();

    const [digest, changes] = budgetSwitches();
    expect(digest).toHaveValue("on");
    expect(changes).toHaveValue("off");

    fireEvent.change(digest, { target: { value: "default" } });
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(updateSettingsMock).toHaveBeenCalledWith({
        alert_phishing_digest_enabled: null,
        expected_version: 7,
      }),
    );
  });

  it("refuses to send an out-of-range score", async () => {
    const user = userEvent.setup();
    await loaded();

    const score = screen.getByLabelText("Direct alert score") as HTMLInputElement;
    fireEvent.change(score, { target: { value: "120" } });
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    // The bounds are the API's own: the input carries them, so an obvious typo is
    // stopped on the field rather than becoming a `422` that reads like the platform
    // is broken, and nothing is sent.
    expect(score.validity.rangeOverflow).toBe(true);
    expect(updateSettingsMock).not.toHaveBeenCalled();
  });

  it("names a saved budget that was refused instead of hiding it", async () => {
    getAlertPolicyMock.mockResolvedValue({
      ...environmentPolicy,
      invalid: ["confidence_digest", "confidence_direct"],
    });
    await loaded();

    const warning = await screen.findByText(/does not hold together/);
    expect(warning).toHaveTextContent("confidence_digest");
    expect(warning).toHaveTextContent("confidence_direct");
    expect(warning).toHaveTextContent(/deployment's values above are what is routing/);
  });

  it("still edits and saves when the budget in force cannot be read", async () => {
    getAlertPolicyMock.mockRejectedValue(new Error("unavailable"));
    const user = userEvent.setup();
    await loaded();

    expect(
      await screen.findByText(/The budget in force could not be read/),
    ).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Digest hour (UTC)"), { target: { value: "3" } });
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() =>
      expect(updateSettingsMock).toHaveBeenCalledWith({
        alert_phishing_digest_hour_utc: 3,
        expected_version: 7,
      }),
    );
  });
});
