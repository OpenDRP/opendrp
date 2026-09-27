import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Pencil, Trash2, RefreshCw, Check, X, ShieldAlert, ShieldCheck, ShieldOff, Eye, UserRound, RotateCcw } from "lucide-react";
import { describeApiError, endpoints } from "@/lib/api";
import { useDebounce } from "@/lib/useDebounce";
import { useAuthStore } from "@/store/auth";
import { formatNumber } from "@/lib/utils";
import { TIME_ZONE_HINT, formatDateTime } from "@/lib/datetime";
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

export default function UsersPage() {
  const qc = useQueryClient();
  const currentUser = useAuthStore(s => s.user);

  const [page, setPage] = useState(1);
  const [size, setSize] = useState(20);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);
  const [roleFilter, setRoleFilter] = useState<UserRole | undefined>();
  const [activeFilter, setActiveFilter] = useState<boolean | undefined>();

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
    queryKey: ["users", page, size, debouncedSearch, roleFilter, activeFilter],
    queryFn: () => endpoints.listUsers({
      page,
      size,
      role: roleFilter,
      is_active: activeFilter,
      search: debouncedSearch || undefined,
    }),
    staleTime: 15_000,
    placeholderData: { items: [], total: 0, page: 1, size: 20, pages: 0 },
  });

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

  const deleteMut = useMutation({
    mutationFn: (id: string) => endpoints.deleteUser(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
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
              <Badge
                variant="outline"
                className="border-red-500/30 text-red-500 bg-red-500/10 text-[10px]"
                title={`Temporarily locked due to failed login attempts until ${formatDateTime(u.locked_until!)}`}
              >
                Locked (Brute-force)
              </Badge>
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
            {pending.length > 0 && (
              <Badge
                variant="outline"
                className="border-amber-500/30 text-amber-500 bg-amber-500/10"
                title="The account has to complete this at its next sign-in; until then the API refuses everything except the onboarding page."
              >
                pending: {pending.join(" + ")}
              </Badge>
            )}
          </div>
        );
      },
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
          <Button variant="outline" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isFetching ? "animate-spin" : ""}`} />
            Refresh
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
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-4">
          <PaginatedDataTable
            columns={columns}
            rows={data?.items ?? []}
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
        onOpenChange={setDeactivateOpen}
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
          setDeactivateOpen(false);
          setDeactivatingUser(null);
        }}
        onCancel={() => setDeactivatingUser(null)}
      />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        variant="destructive"
        title="Permanently delete user?"
        description={deletingUser ? (
          <>Permanently remove <span className="font-semibold">{deletingUser.email}</span> and all of their sessions. Reports they generated are kept, and their email address is freed. This cannot be undone — use <span className="font-semibold">Deactivate</span> instead to keep the account recoverable.</>
        ) : "This action cannot be undone."}
        confirmLabel="Delete permanently"
        confirmLoading={deleteMut.isPending}
        onConfirm={() => {
          if (deletingUser) deleteMut.mutate(deletingUser.id);
          setDeleteOpen(false);
          setDeletingUser(null);
        }}
        onCancel={() => setDeletingUser(null)}
      />

      <ConfirmDialog
        open={mfaResetOpen}
        onOpenChange={setMfaResetOpen}
        variant="destructive"
        title="Clear this account's second factor?"
        description={mfaResetUser ? (
          <>The authenticator enrolled for <span className="font-semibold">{mfaResetUser.email}</span> stops working immediately. The account keeps its password, but a new second factor is required at its next sign-in before the rest of the platform opens. Use this for a lost device — the account cannot remove its own factor.</>
        ) : "The second factor will be cleared."}
        confirmLabel="Clear second factor"
        confirmLoading={mfaResetMut.isPending}
        onConfirm={() => {
          if (mfaResetUser) mfaResetMut.mutate(mfaResetUser.id);
          setMfaResetOpen(false);
          setMfaResetUser(null);
        }}
        onCancel={() => setMfaResetUser(null)}
      />

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
