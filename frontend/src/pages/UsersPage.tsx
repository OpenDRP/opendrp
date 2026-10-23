import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Pencil, Trash2, RefreshCw, Check, X, ShieldAlert, ShieldCheck, ShieldOff, Eye, UserRound, RotateCcw, Download, MonitorSmartphone, Power, MailPlus, Copy, Send } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useAuthStore } from "@/store/auth";
import { formatNumber } from "@/lib/utils";
import { TIME_ZONE_HINT, formatDateTime, formatDateTimeOrNever } from "@/lib/datetime";
import type { User, UserRole } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";
import { toast } from "@/components/ui/use-toast";

const ROLES: UserRole[] = ["admin", "analyst", "viewer"];

const roleIcon: Record<UserRole, any> = {
  admin: ShieldAlert,
  analyst: ShieldCheck,
  viewer: Eye,
};

const roleTone: Record<UserRole, string> = {
  admin: "bg-red-500/15 text-red-500 border-red-500/30",
  analyst: "bg-blue-500/15 text-blue-500 border-blue-500/30",
  viewer: "bg-gray-500/15 text-gray-500 border-gray-500/30",
};

interface UserFormState {
  email: string;
  password: string;
  full_name: string;
  role: UserRole;
  /** Minutes between two manual actions of the same scope (0 = unlimited). */
  /** Kept as a string so an empty field stays distinguishable from "0". */
  rateLimitMinutes: string;
  resetPassword?: boolean;
  newPassword?: string;
}

const emptyForm: UserFormState = {
  email: "",
  password: "",
  full_name: "",
  role: "viewer",
  rateLimitMinutes: "0",
  resetPassword: false,
  newPassword: "",
};

const RATE_LIMIT_MAX_MINUTES = 1440;

/**
 * Interpret the rate-limit field.
 *
 * An empty field means "no limit" on purpose. A negative value is rejected
 * instead of being coerced — silently turning "-5" into 0 would remove the
 * limit the administrator meant to tighten. Values above the ceiling are
 * capped at the ceiling and reported back (`capped`) so the UI can say so.
 */
function parseRateLimit(
  raw: string,
): { value: number; capped: boolean } | { error: string } {
  const trimmed = raw.trim();
  if (trimmed === "") return { value: 0, capped: false };
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed)) return { error: "Rate limit must be a number of minutes." };
  if (parsed < 0) return { error: "Rate limit cannot be negative. Use 0 for no limit." };
  const value = Math.trunc(parsed);
  if (value > RATE_LIMIT_MAX_MINUTES) {
    return { value: RATE_LIMIT_MAX_MINUTES, capped: true };
  }
  return { value, capped: false };
}

function describeRateLimit(minutes: number): string {
  if (!minutes) return "Unlimited";
  if (minutes % 1440 === 0) return minutes === 1440 ? "Once per day" : `${minutes / 1440}× per day`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} h`;
  return `Every ${minutes} min`;
}

/** Save a response the server already rendered, without a second request. */
function saveBlob(content: Blob, filename: string) {
  if (typeof URL.createObjectURL !== "function") return;
  const url = URL.createObjectURL(content);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/** The three support cuts (U-3); `all` means no extra condition. */
type SupportView = "all" | "onboarding" | "no-mfa" | "locked";

export default function UsersPage() {
  const qc = useQueryClient();
  const currentUser = useAuthStore(s => s.user);

  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [roleFilter, setRoleFilter] = useState<UserRole | undefined>();
  const [activeFilter, setActiveFilter] = useState<boolean | undefined>();
  // `false` is the access-review question ("never signed in"), not "no filter":
  // `undefined` means every account regardless of sign-in history.
  const [signedInFilter, setSignedInFilter] = useState<boolean | undefined>();
  const [supportView, setSupportView] = useState<SupportView>("all");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [sessionsUser, setSessionsUser] = useState<User | null>(null);
  const [bulkConfirm, setBulkConfirm] = useState<"activate" | "deactivate" | null>(null);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteName, setInviteName] = useState("");
  const [inviteRole, setInviteRole] = useState<UserRole>("viewer");
  const [inviteResult, setInviteResult] = useState<{
    email: string;
    token: string;
    expires_at: string;
    email_scheduled: boolean;
  } | null>(null);
  const [resendUser, setResendUser] = useState<User | null>(null);

  const [dialogOpen, setDialogOpen] = useState(false);
  const [editing, setEditing] = useState<User | null>(null);
  const [form, setForm] = useState<UserFormState>({ ...emptyForm });

  const [deactivateOpen, setDeactivateOpen] = useState(false);
  const [deactivatingUser, setDeactivatingUser] = useState<User | null>(null);
  const [togglingUserId, setTogglingUserId] = useState<string | null>(null);

  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletingUser, setDeletingUser] = useState<User | null>(null);

  const [mfaResetOpen, setMfaResetOpen] = useState(false);
  const [mfaResetUser, setMfaResetUser] = useState<User | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["users", page, size, debouncedSearch, roleFilter, activeFilter, signedInFilter, supportView],
    queryFn: () => endpoints.listUsers({
      page,
      size,
      role: roleFilter,
      is_active: activeFilter,
      signed_in: signedInFilter,
      requires_onboarding: supportView === "onboarding" ? true : undefined,
      mfa_enrolled: supportView === "no-mfa" ? false : undefined,
      locked: supportView === "locked" ? true : undefined,
      search: debouncedSearch || undefined,
    }),
    staleTime: 15_000,
    // Keep the last result visible while a new page/filter is loading instead
    // of briefly presenting an empty user directory as a real result.
    placeholderData: (previousData) => previousData,
  });

  // The batch route applies whatever ids it is handed, so a selection that
  // outlives the list it was made in is a batch over accounts the operator can no
  // longer see — the same rule the assets page follows. The dependencies are
  // exactly the query key: a change of page, size or filter drops the selection,
  // and a refresh of the same view keeps it.
  useEffect(() => {
    setSelectedIds([]);
  }, [page, size, debouncedSearch, roleFilter, activeFilter, signedInFilter, supportView]);

  const createMut = useMutation({
    mutationFn: (d: UserFormState) => endpoints.createUser({
      email: d.email.trim(),
      password: d.password,
      full_name: d.full_name || undefined,
      role: d.role,
      rate_limit_minutes: rateLimitOf(d),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setDialogOpen(false);
      resetForm();
      toast({ title: "User created" });
    },
    onError: (e: any) => {
      toast({
        variant: "destructive",
        title: "Failed to create user",
        description: describeApiError(e),
      });
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, d }: { id: string; d: UserFormState }) => {
      const payload: any = {
        email: d.email.trim(),
        full_name: d.full_name || undefined,
        role: d.role,
        rate_limit_minutes: rateLimitOf(d),
      };
      // Backend UserUpdate expects `new_password` (snake_case). Sending `password`
      // would be silently ignored by Pydantic and the reset would never happen.
      if (d.resetPassword && d.newPassword) payload.new_password = d.newPassword;
      return endpoints.updateUser(id, payload);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setDialogOpen(false);
      resetForm();
      toast({ title: "User updated" });
    },
    onError: (e: any) => {
      const status = e?.response?.status;
      if (status === 409) {
        toast({ variant: "destructive", title: "Cannot demote last admin", description: describeApiError(e, "At least one admin must remain.") });
      } else {
        toast({ variant: "destructive", title: "Failed to update user", description: describeApiError(e) });
      }
    },
  });

  const toggleActiveMut = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      endpoints.updateUser(id, { is_active }),
    onSuccess: (_result, vars) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setTogglingUserId(null);
      // The dialog stays up until the answer arrives, so a refusal is read where
      // the decision was made rather than as a toast after it disappeared.
      setDeactivateOpen(false);
      setDeactivatingUser(null);
      toast({ title: vars.is_active ? "User activated" : "User deactivated" });
    },
    onError: (e: any) => {
      setTogglingUserId(null);
      const status = e?.response?.status;
      if (status === 409) {
        toast({ variant: "destructive", title: "Cannot modify last admin", description: describeApiError(e, "At least one active admin must remain.") });
      } else {
        toast({ variant: "destructive", title: "Update failed", description: describeApiError(e) });
      }
    },
  });

  const mfaResetMut = useMutation({
    mutationFn: (id: string) => endpoints.resetUserMfa(id),
    onSuccess: (_result, _id) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setMfaResetOpen(false);
      setMfaResetUser(null);
      toast({
        title: "Second factor cleared",
        description:
          "The account will be asked to enrol a new authenticator at its next sign-in, before the rest of the platform opens.",
      });
    },
    onError: (e: any) => {
      toast({
        variant: "destructive",
        title: "Could not clear the second factor",
        description: describeApiError(e, "Only another account's factor can be cleared from here."),
      });
    },
  });

  const unlockMut = useMutation({
    mutationFn: (id: string) => endpoints.unlockUser(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      toast({
        title: "Account unlocked",
        description:
          "The failed sign-in counter is cleared. The password, role and second factor are unchanged.",
      });
    },
    onError: (e: any) => {
      // The API refuses an account that is not locked any more, which is what a
      // stale table and a colleague's simultaneous click both look like. Saying
      // so is more useful than a generic failure toast.
      const status = e?.response?.status;
      toast({
        variant: "destructive",
        title: status === 409 ? "Nothing to unlock" : "Could not unlock the account",
        description: describeApiError(e, "This account is no longer locked."),
      });
    },
  });

  const sessions = useQuery({
    queryKey: ["user-sessions", sessionsUser?.id],
    queryFn: () => endpoints.listUserSessions(sessionsUser!.id),
    enabled: sessionsUser !== null,
    staleTime: 5_000,
  });

  const revokeSessionsMut = useMutation({
    mutationFn: (id: string) => endpoints.revokeUserSessions(id),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["user-sessions"] });
      qc.invalidateQueries({ queryKey: ["users"] });
      toast({
        title: "Sessions ended",
        description:
          result.revoked === 1
            ? "One session was signed out."
            : `${result.revoked} sessions were signed out.`,
      });
    },
    onError: (e: any) => {
      toast({
        variant: "destructive",
        title: "Could not end the sessions",
        description: describeApiError(e, "Use the sessions page for your own account."),
      });
    },
  });

  const bulkMut = useMutation({
    mutationFn: (operation: "activate" | "deactivate") =>
      endpoints.bulkUsers({ operation, user_ids: selectedIds }),
    onSuccess: (result, operation) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setSelectedIds([]);
      setBulkConfirm(null);
      toast({
        title: operation === "deactivate" ? "Accounts deactivated" : "Accounts activated",
        description:
          `${result.changed} changed` +
          (result.skipped ? `, ${result.skipped} already in that state` : "") +
          (result.revoked_sessions ? `, ${result.revoked_sessions} sessions ended` : "") +
          ".",
      });
    },
    onError: (e: any) => {
      const status = e?.response?.status;
      toast({
        variant: "destructive",
        title: status === 409 ? "Bulk action refused" : "Bulk action failed",
        description: describeApiError(e, "Nothing was changed."),
      });
    },
  });

  const inviteMut = useMutation({
    mutationFn: () =>
      endpoints.inviteUser({
        email: inviteEmail.trim(),
        role: inviteRole,
        full_name: inviteName.trim() || undefined,
      }),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setInviteResult({
        email: inviteEmail.trim(),
        token: result.invitation_token,
        expires_at: result.expires_at,
        email_scheduled: result.email_scheduled,
      });
    },
    onError: (e: any) => {
      toast({
        variant: "destructive",
        title: "Could not create the invitation",
        description: describeApiError(e),
      });
    },
  });

  const resendMut = useMutation({
    mutationFn: (user: User) => endpoints.reissueInvitation(user.id),
    onSuccess: (result, user) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setResendUser(null);
      setInviteResult({
        email: user.email,
        token: result.invitation_token,
        expires_at: result.expires_at,
        email_scheduled: result.email_scheduled,
      });
      setInviteOpen(true);
    },
    onError: (e: any) => {
      setResendUser(null);
      toast({
        variant: "destructive",
        title: "Could not reissue the invitation",
        description: describeApiError(e),
      });
    },
  });

  function closeInvite() {
    setInviteOpen(false);
    setInviteResult(null);
    setInviteEmail("");
    setInviteName("");
    setInviteRole("viewer");
  }

  const inviteUrl = inviteResult
    ? `${window.location.origin}/accept-invitation?token=${encodeURIComponent(inviteResult.token)}`
    : "";

  async function copyInviteLink() {
    try {
      await navigator.clipboard?.writeText(inviteUrl);
      toast({ title: "Link copied", description: "Send it to the account owner over a channel you trust." });
    } catch {
      toast({ variant: "destructive", title: "Could not copy", description: "Select the link and copy it manually." });
    }
  }

  const [exporting, setExporting] = useState(false);

  async function handleExport() {
    setExporting(true);
    try {
      const blob = await endpoints.exportUsers({
        search: debouncedSearch || undefined,
        role: roleFilter,
        is_active: activeFilter,
        signed_in: signedInFilter,
        requires_onboarding: supportView === "onboarding" ? true : undefined,
        mfa_enrolled: supportView === "no-mfa" ? false : undefined,
        locked: supportView === "locked" ? true : undefined,
        format: "csv",
      });
      saveBlob(blob, "users.csv");
      toast({ title: "Export ready", description: "users.csv downloaded." });
    } catch (error: unknown) {
      toast({ variant: "destructive", title: "Export failed", description: describeApiError(error) });
    } finally {
      setExporting(false);
    }
  }

  const deleteMut = useMutation({
    mutationFn: (id: string) => endpoints.deleteUser(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setDeleteOpen(false);
      setDeletingUser(null);
      toast({ title: "User deleted" });
    },
    onError: (e: any) => {
      const status = e?.response?.status;
      if (status === 409) {
        toast({ variant: "destructive", title: "Cannot delete user", description: describeApiError(e, "Cannot delete your own account or the last admin.") });
      } else {
        toast({ variant: "destructive", title: "Delete failed", description: describeApiError(e) });
      }
    },
  });

  /** Rate limit to persist: a stray empty/negative value must never silently
   *  become "unlimited", so invalid input is rejected before submission. */
  function rateLimitOf(d: UserFormState): number {
    const parsed = parseRateLimit(d.rateLimitMinutes);
    return "value" in parsed ? parsed.value : 0;
  }


  function resetForm() {
    setEditing(null);
    setForm({ ...emptyForm });
  }

  function openCreate() {
    resetForm();
    setDialogOpen(true);
  }

  function openEdit(u: User) {
    setEditing(u);
    setForm({
      email: u.email,
      password: "",
      full_name: u.full_name || "",
      role: u.role,
      rateLimitMinutes: String(u.rate_limit_minutes ?? 0),
      resetPassword: false,
      newPassword: "",
    });
    setDialogOpen(true);
  }

  function submit() {
    if (!form.email) {
      toast({ variant: "destructive", title: "Validation", description: "Email is required." });
      return;
    }
    if (!editing && !form.password) {
      toast({ variant: "destructive", title: "Validation", description: "Password is required to create a user." });
      return;
    }
    if (form.resetPassword && !form.newPassword) {
      toast({ variant: "destructive", title: "Validation", description: "New password required when reset is checked." });
      return;
    }
    const rateLimit = parseRateLimit(form.rateLimitMinutes);
    if ("error" in rateLimit) {
      toast({ variant: "destructive", title: "Validation", description: rateLimit.error });
      return;
    }
    if (editing) {
      updateMut.mutate({ id: editing.id, d: form });
    } else {
      createMut.mutate(form);
    }
  }

  const rateLimitInput = parseRateLimit(form.rateLimitMinutes);
  const rateLimitValue = "value" in rateLimitInput ? rateLimitInput.value : 0;
  const rateLimitCapped = "capped" in rateLimitInput && rateLimitInput.capped;
  // Viewers read findings but cannot trigger a rescan, so the rate limit only
  // governs their report generation.

  function handleToggleActive(u: User) {
    if (u.is_active) {
      setDeactivatingUser(u);
      setDeactivateOpen(true);
    } else {
      setTogglingUserId(u.id);
      toggleActiveMut.mutate({ id: u.id, is_active: true });
    }
  }

  const columns: DataTableColumn<User>[] = [
    {
      key: "email",
      title: "Email",
      width: 260,
      minWidth: 200,
      render: (u) => (
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <UserRound className="w-4 h-4 text-primary" />
          </div>
          <div className="font-medium text-sm truncate">{u.email}</div>
        </div>
      ),
    },
    {
      key: "full_name",
      title: "Full Name",
      width: 180,
      minWidth: 120,
      render: (u) => u.full_name || <span className="text-muted-foreground text-xs">—</span>,
    },
    {
      key: "role",
      title: "Role",
      width: 140,
      minWidth: 120,
      render: (u) => {
        const Icon = roleIcon[u.role];
        return (
          <Badge variant="outline" className={roleTone[u.role]}>
            <Icon className="w-3 h-3 mr-1" />
            <span className="capitalize">{u.role}</span>
          </Badge>
        );
      },
    },
    {
      key: "rate_limit_minutes",
      title: "Rate limit",
      width: 150,
      minWidth: 130,
      render: (u) => (
        <span className="text-sm text-muted-foreground">
          {describeRateLimit(u.rate_limit_minutes ?? 0)}
        </span>
      ),
    },
    {
      key: "is_active",
      title: "Status",
      width: 130,
      minWidth: 120,
      render: (u) => {
        const isLocked = u.locked_until && new Date(u.locked_until).getTime() > Date.now();
        return (
          <div className="flex flex-col gap-1">
            <Badge variant="outline" className={u.is_active ? "border-green-500/30 text-green-500 bg-green-500/10" : "border-muted text-muted-foreground bg-muted/30"}>
              {u.is_active ? <Check className="w-3 h-3 mr-1 inline" /> : <X className="w-3 h-3 mr-1 inline" />}
              {u.is_active ? "Active" : "Inactive"}
            </Badge>
            {isLocked && (
              <div className="flex items-center gap-1.5">
                <Badge
                  variant="outline"
                  className="border-red-500/30 text-red-500 bg-red-500/10 text-[10px]"
                  title={`Temporarily locked due to failed login attempts until ${formatDateTime(u.locked_until!)}`}
                >
                  Locked (Brute-force)
                </Badge>
                {/* The lockout is the control working, so the way out is next to
                    the state rather than in a support note: an operator releasing
                    it is a decision about this account, not a settings change. */}
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 px-2 text-xs"
                  onClick={() => unlockMut.mutate(u.id)}
                  disabled={unlockMut.isPending && unlockMut.variables === u.id}
                  title="Clear the failed sign-in counter and lift the lockout. The password, role and second factor are not touched."
                >
                  {unlockMut.isPending && unlockMut.variables === u.id ? "Unlocking..." : "Unlock"}
                </Button>
              </div>
            )}
          </div>
        );
      },
    },
    {
      key: "security",
      title: "Security",
      width: 210,
      minWidth: 180,
      // Two facts a support call turns on, in one column: whether the account has
      // a second factor, and whether it still owes a credential step from the last
      // administrator action. Without them an operator cannot tell a user who has
      // not signed in yet from one who is stuck.
      render: (u) => {
        const pending = [
          u.must_change_password ? "new password" : null,
          u.must_enrol_mfa ? "new second factor" : null,
          u.mfa_required_by_policy ? "MFA required by policy" : null,
        ].filter(Boolean) as string[];
        return (
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge
              variant="outline"
              className={
                u.totp_enabled_at
                  ? "border-green-500/30 text-green-500 bg-green-500/10"
                  : "border-muted text-muted-foreground bg-muted/30"
              }
              title={u.totp_enabled_at ? `Second factor enabled ${formatDateTime(u.totp_enabled_at)}` : "No second factor enrolled"}
            >
              {u.totp_enabled_at ? "2FA" : "password only"}
            </Badge>
            {u.invitation_expires_at ? (
              <Badge
                variant="outline"
                className="border-sky-500/30 text-sky-500 bg-sky-500/10"
                title={`Invitation expires ${formatDateTime(u.invitation_expires_at)}`}
              >
                invited
              </Badge>
            ) : null}
            {pending.length > 0 && (
              <Badge
                variant="outline"
                className="border-amber-500/30 text-amber-500 bg-amber-500/10"
                title="The account has to complete this at its next sign-in; until then the API refuses everything except the onboarding page. MFA by policy is controlled by REQUIRE_MFA_FOR_ADMINS."
              >
                pending: {pending.join(" + ")}
              </Badge>
            )}
          </div>
        );
      },
    },
    {
      key: "last_login_at",
      title: "Last sign-in",
      width: 170,
      minWidth: 150,
      // "never" and "just now" are different answers, so the empty case is
      // written out rather than left blank.
      render: (u) => (
        <span className={u.last_login_at ? "text-sm text-muted-foreground" : "text-sm text-amber-500"}>
          {formatDateTimeOrNever(u.last_login_at)}
        </span>
      ),
    },
    {
      key: "created_at",
      title: "Created At",
      width: 160,
      minWidth: 140,
      render: (u) => <span className="text-sm text-muted-foreground">{formatDateTime(u.created_at)}</span>,
    },
    {
      key: "actions",
      title: "Actions",
      width: 200,
      minWidth: 180,
      align: "right",
      render: (u) => {
        const isSelf = currentUser?.id === u.id;
        return (
          <div className="inline-flex items-center gap-1 justify-end">
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleToggleActive(u)}
              disabled={togglingUserId === u.id || (isSelf && u.is_active)}
              title={isSelf ? "You cannot deactivate yourself" : undefined}
            >
              {togglingUserId === u.id ? "Updating..." : u.is_active ? "Deactivate" : "Activate"}
            </Button>
            <Button size="icon" variant="ghost" onClick={() => openEdit(u)} title="Edit user" aria-label="Edit user">
              <Pencil className="w-4 h-4" />
            </Button>
            {u.invitation_expires_at ? (
              <Button
                size="icon"
                variant="ghost"
                onClick={() => setResendUser(u)}
                title="Replace the invitation link (the old one stops working)"
                aria-label="Resend invitation"
              >
                <Send className="w-4 h-4" />
              </Button>
            ) : null}
            <Button
              size="icon"
              variant="ghost"
              onClick={() => setSessionsUser(u)}
              title="Show this account's sessions and end them"
              aria-label="Show sessions"
            >
              <MonitorSmartphone className="w-4 h-4" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              onClick={() => { setMfaResetUser(u); setMfaResetOpen(true); }}
              title={
                isSelf
                  ? "Use the recovery command on the host to clear your own second factor"
                  : u.totp_enabled_at
                    ? "Clear the second factor (the account enrols a new one at next sign-in)"
                    : "No second factor enrolled"
              }
              aria-label="Clear second factor"
              disabled={isSelf || !u.totp_enabled_at}
            >
              <ShieldOff className="w-4 h-4" />
            </Button>
            <Button
              size="icon"
              variant="ghost"
              className="text-destructive hover:text-destructive"
              onClick={() => { setDeletingUser(u); setDeleteOpen(true); }}
              title={isSelf ? "You cannot delete your own account" : "Delete user"}
              aria-label={isSelf ? "You cannot delete your own account" : "Delete user"}
              disabled={isSelf}
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">Users</h1>
          <p className="text-muted-foreground text-sm mt-1">Manage user accounts, roles and access to the platform.</p>
          <p className="text-xs text-muted-foreground mt-1">{TIME_ZONE_HINT}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={handleExport} disabled={exporting}>
            <Download className="w-4 h-4 mr-2" />
            {exporting ? "Exporting..." : "Export CSV"}
          </Button>
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Button variant="outline" onClick={() => { closeInvite(); setInviteOpen(true); }}>
            <MailPlus className="w-4 h-4 mr-2" />
            Invite user
          </Button>
          <Button onClick={openCreate}>
            <Plus className="w-4 h-4 mr-2" />
            Create user
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Filters</CardTitle>
          <CardDescription>
            Total users: <span className="font-semibold text-foreground">{formatNumber(data?.total ?? 0)}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="relative md:col-span-2">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input className="pl-9" placeholder="Search by email or name..." value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
            </div>
            <Select value={roleFilter || "all"} onValueChange={(v: string) => { setRoleFilter(v === "all" ? undefined : (v as UserRole)); setPage(1); }}>
              <SelectTrigger aria-label="Filter by role"><SelectValue placeholder="Role" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All roles</SelectItem>
                {ROLES.map(r => <SelectItem key={r} value={r} className="capitalize">{r}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={activeFilter === undefined ? "all" : activeFilter ? "active" : "inactive"} onValueChange={(v: string) => { setActiveFilter(v === "all" ? undefined : v === "active"); setPage(1); }}>
              <SelectTrigger aria-label="Filter by status"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
              </SelectContent>
            </Select>
            <Select value={signedInFilter === undefined ? "all" : signedInFilter ? "signed-in" : "never"} onValueChange={(v: string) => { setSignedInFilter(v === "all" ? undefined : v === "signed-in"); setPage(1); }}>
              <SelectTrigger aria-label="Filter by sign-in history"><SelectValue placeholder="Sign-in" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Any sign-in history</SelectItem>
                <SelectItem value="signed-in">Has signed in</SelectItem>
                <SelectItem value="never">Never signed in</SelectItem>
              </SelectContent>
            </Select>
            {/* The three slices support asks for, in the list they are already
                looking at — a separate counters panel would be a second query
                and would show zeros while the first one is loading (U-3). */}
            <Select value={supportView} onValueChange={(v: string) => { setSupportView(v as SupportView); setPage(1); }}>
              <SelectTrigger aria-label="Filter by support view"><SelectValue placeholder="Support view" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">Every account</SelectItem>
                <SelectItem value="onboarding">Owes onboarding</SelectItem>
                <SelectItem value="no-mfa">No second factor</SelectItem>
                <SelectItem value="locked">Locked out</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {selectedIds.length > 0 && (
        <Card>
          <CardContent className="flex flex-wrap items-center gap-2 p-4" role="region" aria-label="Bulk actions">
            <span className="text-sm font-medium mr-2">{selectedIds.length} selected</span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setBulkConfirm("deactivate")}
              disabled={bulkMut.isPending}
            >
              <Power className="w-4 h-4 mr-1" />
              Deactivate selected
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setBulkConfirm("activate")}
              disabled={bulkMut.isPending}
            >
              Activate selected
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelectedIds([])} disabled={bulkMut.isPending}>
              Clear selection
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-4">
          <PaginatedDataTable
            columns={columns}
            rows={data?.items ?? []}
            selectable
            selectedIds={selectedIds}
            onSelectedChange={setSelectedIds}
            getRowLabel={(row) => row.email}
            total={data?.total ?? 0}
            page={page}
            pageSize={size}
            onPageChange={setPage}
            onPageSizeChange={(s) => { setSize(s); setPage(1); }}
            storageKey="users-table-widths-v1"
            loading={isLoading}
            isError={isError}
            errorDescription="The user list could not be loaded. Sign-in rules and roles below the table may be out of date."
            onRetry={() => refetch()}
            emptyText="No users match the current search."
          />
        </CardContent>
      </Card>

      <ConfirmDialog
        open={deactivateOpen}
        onOpenChange={(open) => {
          if (!open && toggleActiveMut.isPending) return;
          setDeactivateOpen(open);
          if (!open) setDeactivatingUser(null);
        }}
        variant="destructive"
        title="Deactivate user?"
        description={deactivatingUser ? (
          <>User <span className="font-semibold">{deactivatingUser.email}</span> will lose access to the platform. They can be re-activated later.</>
        ) : "This user will lose access."}
        confirmLabel="Deactivate"
        confirmLoading={toggleActiveMut.isPending}
        onConfirm={() => {
          if (deactivatingUser) {
            setTogglingUserId(deactivatingUser.id);
            toggleActiveMut.mutate({ id: deactivatingUser.id, is_active: false });
          }
        }}
        onCancel={() => setDeactivatingUser(null)}
      >
        {toggleActiveMut.isError && (
          <p role="alert" className="text-sm text-destructive">
            {describeApiError(toggleActiveMut.error, "The account could not be deactivated.")}
          </p>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={(open) => {
          if (!open && deleteMut.isPending) return;
          setDeleteOpen(open);
          if (!open) setDeletingUser(null);
        }}
        variant="destructive"
        title="Permanently delete user?"
        description={deletingUser ? (
          <>Permanently remove <span className="font-semibold">{deletingUser.email}</span> and all of their sessions. Reports they generated are kept, and their email address is freed. This cannot be undone — use <span className="font-semibold">Deactivate</span> instead to keep the account recoverable.</>
        ) : "This action cannot be undone."}
        confirmLabel="Delete permanently"
        confirmLoading={deleteMut.isPending}
        onConfirm={() => {
          if (deletingUser) deleteMut.mutate(deletingUser.id);
        }}
        onCancel={() => setDeletingUser(null)}
      >
        {deleteMut.isError && (
          <p role="alert" className="text-sm text-destructive">
            {describeApiError(deleteMut.error, "The account could not be deleted.")}
          </p>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={mfaResetOpen}
        onOpenChange={(open) => {
          if (!open && mfaResetMut.isPending) return;
          setMfaResetOpen(open);
          if (!open) setMfaResetUser(null);
        }}
        variant="destructive"
        title="Clear this account's second factor?"
        description={mfaResetUser ? (
          <>The authenticator enrolled for <span className="font-semibold">{mfaResetUser.email}</span> stops working immediately. The account keeps its password, but a new second factor is required at its next sign-in before the rest of the platform opens. Use this for a lost device — the account cannot remove its own factor.</>
        ) : "The second factor will be cleared."}
        confirmLabel="Clear second factor"
        confirmLoading={mfaResetMut.isPending}
        onConfirm={() => {
          if (mfaResetUser) mfaResetMut.mutate(mfaResetUser.id);
        }}
        onCancel={() => setMfaResetUser(null)}
      >
        {mfaResetMut.isError && (
          <p role="alert" className="text-sm text-destructive">
            {describeApiError(mfaResetMut.error, "The second factor could not be cleared.")}
          </p>
        )}
      </ConfirmDialog>

      <Dialog open={inviteOpen} onOpenChange={(open) => { if (!open) closeInvite(); }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{inviteResult ? "Invitation link" : "Invite a user"}</DialogTitle>
            <DialogDescription>
              {inviteResult
                ? "This link works once. The account keeps only its digest, so it cannot be shown again — copy it now if you need it."
                : "The account is created without a password you know. The owner chooses one from the link, so no temporary password travels through chat or mail."}
            </DialogDescription>
          </DialogHeader>
          {inviteResult ? (
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label htmlFor="invitation-link">Link for {inviteResult.email}</Label>
                <div className="flex gap-2">
                  <Input id="invitation-link" readOnly value={inviteUrl} onFocus={(event) => event.target.select()} />
                  <Button type="button" variant="outline" onClick={copyInviteLink} aria-label="Copy invitation link">
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  Expires {formatDateTime(inviteResult.expires_at)}.
                  {" "}
                  {inviteResult.email_scheduled
                    ? "The platform also queued this link by email."
                    : "No email was queued (SMTP or a public origin is not configured) — send the link yourself."}
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label htmlFor="invite-email">Email</Label>
                <Input
                  id="invite-email"
                  type="email"
                  value={inviteEmail}
                  onChange={(event) => setInviteEmail(event.target.value)}
                  placeholder="user@example.com"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="invite-name">Full name <span className="text-muted-foreground">(optional)</span></Label>
                <Input id="invite-name" value={inviteName} onChange={(event) => setInviteName(event.target.value)} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="invite-role">Role</Label>
                <Select value={inviteRole} onValueChange={(value: string) => setInviteRole(value as UserRole)}>
                  <SelectTrigger id="invite-role"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {ROLES.map((role) => (
                      <SelectItem key={role} value={role} className="capitalize">{role}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}
          <DialogFooter>
            {inviteResult ? (
              <Button onClick={closeInvite}>Done</Button>
            ) : (
              <>
                <Button variant="outline" onClick={closeInvite}>Cancel</Button>
                <Button
                  onClick={() => inviteMut.mutate()}
                  disabled={inviteMut.isPending || !inviteEmail.trim()}
                >
                  {inviteMut.isPending ? "Creating..." : "Create invitation"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={resendUser !== null}
        onOpenChange={(open) => { if (!open) setResendUser(null); }}
        title="Replace the invitation link?"
        description={
          resendUser ? (
            <>The link already sent to <span className="font-semibold">{resendUser.email}</span> stops working. A new one is created and, when mail is configured, sent.</>
          ) : (
            "The previous link stops working."
          )
        }
        confirmLabel="Create a new link"
        confirmLoading={resendMut.isPending}
        onConfirm={() => { if (resendUser) resendMut.mutate(resendUser); }}
        onCancel={() => setResendUser(null)}
      />

      <Dialog open={sessionsUser !== null} onOpenChange={(open) => { if (!open) setSessionsUser(null); }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Active sessions</DialogTitle>
            <DialogDescription>
              {sessionsUser
                ? `Browsers that can still act as ${sessionsUser.email}. Only identifiers and times are shown — never a token.`
                : ""}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            {sessions.isLoading ? (
              <p className="text-sm text-muted-foreground">Loading sessions...</p>
            ) : sessions.isError ? (
              <p className="text-sm text-destructive">The sessions could not be loaded.</p>
            ) : (sessions.data?.length ?? 0) === 0 ? (
              <p className="text-sm text-muted-foreground">
                No active sessions. The account can sign in again at any time; ending a session does not deactivate it.
              </p>
            ) : (
              <ul className="divide-y rounded-md border" aria-label="Active sessions">
                {sessions.data!.map((session) => (
                  <li key={session.id} className="p-3 text-sm">
                    <div className="font-mono text-xs break-all">{session.id}</div>
                    <div className="text-muted-foreground text-xs mt-1">
                      Created {formatDateTime(session.created_at)}
                      {session.last_used_at ? ` · last used ${formatDateTime(session.last_used_at)}` : ""}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSessionsUser(null)}>Close</Button>
            <Button
              variant="destructive"
              onClick={() => sessionsUser && revokeSessionsMut.mutate(sessionsUser.id)}
              disabled={revokeSessionsMut.isPending || (sessions.data?.length ?? 0) === 0}
            >
              {revokeSessionsMut.isPending ? "Ending..." : "End all sessions"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={bulkConfirm !== null}
        onOpenChange={(open) => {
          if (!open && bulkMut.isPending) return;
          if (!open) setBulkConfirm(null);
        }}
        variant={bulkConfirm === "deactivate" ? "destructive" : "default"}
        title={bulkConfirm === "deactivate" ? "Deactivate the selected accounts?" : "Activate the selected accounts?"}
        description={
          bulkConfirm === "deactivate" ? (
            <>
              {selectedIds.length} selected accounts will lose access and their sessions will be ended.
              The whole selection is applied at once, or not at all; the last active administrator is refused
              by the API rather than left behind as an exception.
            </>
          ) : (
            <>{selectedIds.length} selected accounts will be able to sign in again.</>
          )
        }
        confirmLabel={bulkConfirm === "deactivate" ? "Deactivate" : "Activate"}
        confirmLoading={bulkMut.isPending}
        onConfirm={() => {
          if (bulkConfirm) bulkMut.mutate(bulkConfirm);
        }}
        onCancel={() => setBulkConfirm(null)}
      >
        {bulkMut.isError && (
          <p role="alert" className="text-sm text-destructive">
            {describeApiError(bulkMut.error, "The selection was refused; nothing was changed.")}
          </p>
        )}
      </ConfirmDialog>

      <Dialog open={dialogOpen} onOpenChange={(o) => { if (!o) resetForm(); setDialogOpen(o); }}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{editing ? "Edit user" : "Create new user"}</DialogTitle>
            <DialogDescription>
              {editing
                ? "Update user details and optionally reset their password. A reset password is temporary: the account replaces it at its next sign-in."
                : "Add a new user to the platform with a specific role. The password you type here is temporary — the account replaces it at first sign-in."}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label htmlFor="user-form-email">Email</Label>
              <Input
                id="user-form-email"
                type="email"
                placeholder="user@example.com"
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-form-fullname">Full name <span className="text-muted-foreground">(optional)</span></Label>
              <Input
                id="user-form-fullname"
                placeholder="John Doe"
                value={form.full_name}
                onChange={(e) => setForm({ ...form, full_name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-form-role">Role</Label>
              <Select value={form.role} onValueChange={(v: string) => setForm({ ...form, role: v as UserRole })}>
                <SelectTrigger id="user-form-role"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ROLES.map(r => (
                    <SelectItem key={r} value={r} className="capitalize">{r}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="user-form-rate-limit">Rate limit (minutes)</Label>
              <Input
                id="user-form-rate-limit"
                type="number"
                min={0}
                max={RATE_LIMIT_MAX_MINUTES}
                step={1}
                value={form.rateLimitMinutes}
                aria-invalid={!!(rateLimitInput as { error?: string }).error}
                aria-describedby="user-form-rate-limit-help"
                onChange={(e) => setForm({ ...form, rateLimitMinutes: e.target.value })}
              />
              <p id="user-form-rate-limit-help" className="text-xs text-muted-foreground">
                Minimum interval between two manual actions of the same scope:
                <span className="font-medium text-foreground"> 0 or empty = no limit</span>,
                <span className="font-medium text-foreground"> {RATE_LIMIT_MAX_MINUTES} = once per day</span>.
                Counted separately per connector and for report generation.
                {form.role === "viewer"
                  ? " This role cannot start scans, so the limit applies to report generation only."
                  : ""}
              </p>
              <p className="text-xs" aria-live="polite">
                {"error" in rateLimitInput ? (
                  <span className="text-destructive">{rateLimitInput.error}</span>
                ) : (
                  <span className="text-muted-foreground">
                    Effective: <span className="font-medium text-foreground">{describeRateLimit(rateLimitValue)}</span>
                    {rateLimitCapped ? ` (capped at ${RATE_LIMIT_MAX_MINUTES} minutes)` : ""}
                  </span>
                )}
              </p>
            </div>
            {editing ? (
              <div className="space-y-3 rounded-md border border-input p-3">
                <div className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    id="reset-pw"
                    className="h-4 w-4 rounded border-input text-primary focus:ring-primary"
                    checked={!!form.resetPassword}
                    onChange={(e) => setForm({ ...form, resetPassword: e.target.checked })}
                  />
                  <Label htmlFor="reset-pw" className="!mb-0 !cursor-pointer flex items-center gap-1.5">
                    <RotateCcw className="w-3.5 h-3.5" />
                    Reset password
                  </Label>
                </div>
                {form.resetPassword && (
                  <div className="space-y-2 pl-6">
                    <Label htmlFor="user-form-newpassword">Temporary password</Label>
                    <Input
                      id="user-form-newpassword"
                      type="password"
                      placeholder="Enter temporary password"
                      value={form.newPassword || ""}
                      onChange={(e) => setForm({ ...form, newPassword: e.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">
                      The account is refused everywhere except the onboarding page until it replaces
                      this. Pass the value on out of band; it stops being the account's password as
                      soon as its owner signs in.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-2">
                <Label htmlFor="user-form-password">Temporary password</Label>
                <Input
                  id="user-form-password"
                  type="password"
                  placeholder="Enter temporary password"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                />
                <p className="text-xs text-muted-foreground">
                  Hand this to the account holder out of band. At first sign-in they are asked to
                  choose their own, which is when it stops being a shared secret.
                </p>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDialogOpen(false)}
              disabled={createMut.isPending || updateMut.isPending}
            >
              Cancel
            </Button>
            <Button
              onClick={submit}
              disabled={createMut.isPending || updateMut.isPending}
            >
              {createMut.isPending || updateMut.isPending
                ? "Saving..."
                : editing ? "Save changes" : "Create user"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
