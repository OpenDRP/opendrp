from __future__ import annotations

from typing import TYPE_CHECKING
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import Boolean, DateTime, Enum, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDMixin
if TYPE_CHECKING:
    from app.models.report import Report


class UserRole(str, PyEnum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


def role_name(role: UserRole | str) -> str:
    """The role as the string it is stored, reported and queried as.

    ``str(UserRole.admin)`` is ``"UserRole.admin"`` — Python's ``Enum.__str__``,
    not the value — so an audit detail written with ``str(role)`` reads as a class
    repr rather than as a role, and a SIEM rule keyed on ``details.role == "admin"``
    matches nothing. The equality side of this is silent (``UserRole.admin ==
    "admin"`` is true, which is why comparisons in the code work either way), so
    the only place it shows is in what gets written down.
    """
    return str(getattr(role, "value", role))


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum(UserRole, name="user_role", create_constraint=True, validate_strings=True),
        default=UserRole.viewer,
        nullable=False,
    )
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Minimum interval between two *manual* actions of the same scope, in
    # minutes: 0 = unlimited, 1440 = at most once per day. Scopes are counted
    # separately per connector and once for the reports module, so a frequent
    # breach rescan never blocks report generation.
    rate_limit_minutes: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    # --- Second factor (TOTP) -------------------------------------------------
    # The shared secret is Fernet ciphertext, not plaintext: it is the one value
    # in this database that can mint valid one-time codes, so a database copy
    # without ENCRYPTION_KEY must not be enough to impersonate the account.
    totp_secret: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # NULL means "no second factor". It is set only after a code generated from
    # the stored secret has been verified, so an abandoned enrolment cannot lock
    # an operator out of their own account.
    totp_enabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # The counter of the last accepted code. TOTP accepts a ±1 step window for
    # clock skew; requiring each accepted step to be strictly greater makes a
    # code single-use inside that window.
    totp_last_used_step: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Dedicated MFA throttling state. Password failures and six-digit/recovery
    # code failures are separate credentials and must not share a counter: a
    # password spray must not make a correctly configured authenticator unusable,
    # and a missing OTP must still be bounded without consuming the password
    # lockout budget.
    mfa_failed_attempts: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    mfa_locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # bcrypt hashes of one-time recovery codes. The plaintext codes are returned
    # exactly once after enrolment and are never persisted.
    mfa_recovery_codes: Mapped[list[str] | None] = mapped_column(
        JSON, nullable=True
    )

    # --- Credential onboarding -------------------------------------------------
    # A password that someone else chose is a shared secret: the administrator
    # who typed it, the shell history that recorded it and the documentation that
    # suggested it all still hold it. This flag makes that state visible and
    # temporary — every authenticated route except the ones that fix it refuses
    # the session until the owner has picked a password only they know.
    #
    # Set by anything that assigns a password on someone's behalf: creating an
    # account over the API, resetting a password as an administrator, and the
    # `manage_admin create` / `reset` CLI. Cleared by POST /auth/password.
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
    # The second factor was removed *for* this account rather than by it — an
    # administrator clearing a lost device, or the CLI recovery path. Without
    # this flag a cleared factor would simply mean "no MFA from now on", which is
    # the opposite of what a recovery should leave behind.
    #
    # Cleared by POST /auth/mfa/enable, i.e. once a new factor is proven.
    must_enrol_mfa: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )

    reports: Mapped[list["Report"]] = relationship(
        "Report", back_populates="created_by_user", cascade="all, delete-orphan"
    )
