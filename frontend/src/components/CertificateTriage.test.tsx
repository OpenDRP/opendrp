import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import CertificateTriage from "@/components/CertificateTriage";
import { useAuthStore } from "@/store/auth";

const mocks = vi.hoisted(() => ({
  certificates: vi.fn(),
  exceptions: vi.fn(),
  review: vi.fn(),
  allow: vi.fn(),
  removeException: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("@/lib/api", () => ({
  endpoints: {
    listTLSCertificates: mocks.certificates,
    listCertificateExceptions: mocks.exceptions,
    reviewTLSSighting: mocks.review,
    createCertificateException: mocks.allow,
    deleteCertificateException: mocks.removeException,
  },
  describeApiError: (error: Error) => error.message,
}));
vi.mock("@/components/ui/use-toast", () => ({ toast: mocks.toast }));

const FOREIGN_SIGHTING = {
  id: "sighting-1",
  subject: "mail.example.com",
  ip: "198.51.100.7",
  port: 443,
  source: "ctlogs",
  is_ours: false,
  confidence: 80,
  signals: { org: "Example Hosting BV", asn: 64512, rules: ["R1"], sources: ["ctlogs", "virustotal"] },
  verdict: "candidate" as const,
  first_seen_at: "2026-01-01T00:00:00Z",
  last_seen_at: "2026-02-01T00:00:00Z",
  reviewed_at: null,
  review_note: null,
};

const OUR_SIGHTING = {
  ...FOREIGN_SIGHTING,
  id: "sighting-2",
  ip: "203.0.113.10",
  is_ours: true,
  confidence: 0,
  signals: {},
  verdict: "candidate" as const,
};

const CERTIFICATE = {
  id: "identity-1",
  fingerprint_sha256: "ab".repeat(32),
  fingerprint_sha1: null,
  spki_sha256: null,
  serial_hex: null,
  subject_dn: "CN=mail.example.com",
  issuer_dn: "CN=Example CA",
  not_before: "2025-12-01T00:00:00Z",
  not_after: "2026-12-01T00:00:00Z",
  san_dns: ["mail.example.com"],
  key_algo: "rsa-2048",
  origin: "our_probe",
  first_seen_at: "2025-12-01T00:00:00Z",
  last_seen_at: "2026-02-01T00:00:00Z",
  sightings: [OUR_SIGHTING, FOREIGN_SIGHTING],
  foreign_sightings: 1,
};

const EXCEPTION = {
  id: "exception-1",
  match_kind: "fingerprint" as const,
  match_value: "cd".repeat(32),
  reason: "Shared hosting",
  created_by: "user-1",
  expires_at: null,
  expired: false,
  created_at: "2026-01-01T00:00:00Z",
};

function renderCard(role: "admin" | "analyst" | "viewer" = "admin") {
  useAuthStore.setState({
    user: {
      id: "user-1",
      email: "user@example.com",
      role,
      is_active: true,
      rate_limit_minutes: 0,
      created_at: "2026-01-01",
      updated_at: "2026-01-01",
    },
    token: "test",
    isHydrated: true,
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <CertificateTriage />
    </QueryClientProvider>,
  );
}

describe("CertificateTriage", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocks.certificates.mockResolvedValue({ items: [CERTIFICATE], total: 1, page: 1, size: 25, pages: 1 });
    mocks.exceptions.mockResolvedValue([]);
    mocks.review.mockResolvedValue({ id: "sighting-1", verdict: "confirmed_foreign", reviewed_at: "2026-02-02T00:00:00Z" });
    mocks.allow.mockResolvedValue({ id: "exception-1" });
    mocks.removeException.mockResolvedValue(undefined);
  });

  it("names the foreign address, the organisation and the rules behind the score", async () => {
    renderCard();
    expect(await screen.findByText("198.51.100.7:443")).toBeInTheDocument();
    expect(screen.getByText("Foreign")).toBeInTheDocument();
    expect(screen.getByText("Ours")).toBeInTheDocument();
    // A copy of our service is only actionable if the reviewer can see why the
    // platform thinks so, rather than being asked to trust a bare score.
    expect(screen.getByText(/Example Hosting BV · AS64512 · rule R1 · sources ctlogs, virustotal/)).toBeInTheDocument();
    expect(screen.getByText("confidence 80")).toBeInTheDocument();
    expect(mocks.certificates).toHaveBeenCalledWith({ foreign_only: true, page: 1, size: 25 });
  });

  it("records a verdict only after the operator confirms it", async () => {
    const user = userEvent.setup();
    renderCard();
    await user.click(await screen.findByRole("button", { name: "Confirm foreign" }));
    expect(mocks.review).not.toHaveBeenCalled();
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Confirm this deployment is foreign?")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Record verdict" }));
    await waitFor(() =>
      expect(mocks.review).toHaveBeenCalledWith("sighting-1", { verdict: "confirmed_foreign", note: null }),
    );
    expect(mocks.toast).toHaveBeenCalledWith(
      expect.objectContaining({ description: expect.stringContaining("The rules stay quiet about it") }),
    );
  });

  it("does not offer a verdict on a sighting that is ours", async () => {
    renderCard();
    const ours = await screen.findByText("203.0.113.10:443");
    const row = ours.closest("div")!;
    expect(within(row).queryByRole("button", { name: "Confirm foreign" })).not.toBeInTheDocument();
  });

  it("keeps the fingerprint exception for administrators only", async () => {
    const page = renderCard("analyst");
    expect(await screen.findByText("198.51.100.7:443")).toBeInTheDocument();
    // An analyst can judge one sighting; silencing a whole certificate is a scope
    // decision, so it stays with the administrator role.
    expect(screen.queryByRole("button", { name: "Allow fingerprint" })).not.toBeInTheDocument();
    page.unmount();
    renderCard("admin");
    expect(await screen.findByRole("button", { name: "Allow fingerprint" })).toBeInTheDocument();
  });

  it("allows a fingerprint for the whole certificate, and says so before doing it", async () => {
    const user = userEvent.setup();
    renderCard();
    await user.click(await screen.findByRole("button", { name: "Allow fingerprint" }));
    const dialog = screen.getByRole("dialog");
    expect(mocks.allow).not.toHaveBeenCalled();
    expect(within(dialog).getByText(/never produce a foreign-deployment alert again, on any address/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Allow certificate" }));
    await waitFor(() =>
      expect(mocks.allow).toHaveBeenCalledWith({
        match_kind: "fingerprint",
        match_value: "ab".repeat(32),
        reason: expect.stringContaining("198.51.100.7"),
      }),
    );
  });

  it("lists scope exceptions and lets an administrator withdraw one", async () => {
    mocks.exceptions.mockResolvedValue([EXCEPTION]);
    const user = userEvent.setup();
    renderCard();
    expect(await screen.findByText("Shared hosting")).toBeInTheDocument();
    expect(screen.getByText(/no end date/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: `Remove scope exception ${EXCEPTION.match_value}` }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(mocks.removeException).toHaveBeenCalledWith("exception-1"));
  });

  it("says a failed load is not evidence that our certificates are safe", async () => {
    mocks.certificates.mockRejectedValue(new Error("boom"));
    renderCard();
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /this is not evidence that our certificates are served only by us/i,
    );
  });

  it("reports the foreign count instead of an unqualified all-clear, and says what it is counting", async () => {
    renderCard();
    // The count is over the page that is on screen, so the sentence says so: a
    // number that silently covered only the first page would read as a total.
    expect(
      await screen.findByText(
        /1 sighting\(s\) of our certificates on an address that is not ours among the 1 certificate\(s\) shown, of 1 known/,
      ),
    ).toBeInTheDocument();
  });

  it("says the dates it prints are UTC", async () => {
    renderCard();
    // The card prints a certificate's expiry and an exception's end date; the
    // time-zone contract is that the reader is told which zone they are in.
    expect(await screen.findByText(/All times are UTC/)).toBeInTheDocument();
  });
});
