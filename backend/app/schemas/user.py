import re
import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, computed_field, field_validator

from app.core.mfa_policy import mfa_required_by_policy
from app.schemas.email import EmailAddress


PASSWORD_MIN_LENGTH = 12
# 0 disables throttling; 1440 means at most one manual action per day.
RATE_LIMIT_MAX_MINUTES = 1440
_PASSWORD_REQUIRED_PATTERNS = (
    (r"[A-Z]", "at least one uppercase letter (A-Z)"),
    (r"[0-9]", "at least one digit (0-9)"),
)


def validate_password_strength(password: SecretStr | str) -> SecretStr | str:
    raw = password.get_secret_value() if isinstance(password, SecretStr) else password
    if not raw or len(raw) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
    if len(raw.encode("utf-8")) > 72:
        raise ValueError("Password must not exceed 72 UTF-8 bytes")
    for pattern, human in _PASSWORD_REQUIRED_PATTERNS:
        if not re.search(pattern, raw):
            raise ValueError(f"Password must contain {human}")
    return password


UserRole = Literal["admin", "analyst", "viewer"]
AssetType = Literal["domain", "ip_address", "email_account", "keyword_domain", "keyword_title"]


class UserBase(BaseModel):
    email: EmailAddress
    role: UserRole
    is_active: bool
    full_name: Optional[str] = None
    # Minutes between two manual actions of the same scope (0 = unlimited).
    rate_limit_minutes: int = Field(default=0, ge=0, le=RATE_LIMIT_MAX_MINUTES)

    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    @field_validator("role", mode="before")
    @classmethod
    def _coerce_role(cls, v):
        if v is None:
            return v
        if hasattr(v, "value"):
            return v.value
        return str(v)


class UserResponse(UserBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime
    # Credential onboarding state (see models/user.py). Carried on every user
    # payload rather than fetched separately, because two callers route on it: the
    # account holder's own client, which sends them to the page that fixes it, and
    # an administrator looking at the user list, for whom "this account has not
    # used its temporary password yet" is what explains a support call.
    must_change_password: bool = False
    must_enrol_mfa: bool = False
    locked_until: Optional[datetime] = None
    failed_login_attempts: int = 0
    # When the second factor was enrolled, or NULL when there is none. An admin
    # list needs to distinguish "no factor" from "not enrolled yet, and the account
    # owes one", and the recovery action (clearing somebody else's factor) only
    # makes sense for an account that has one. This is a timestamp, not a secret:
    # the same value is already returned by GET /auth/mfa for the account itself.
    totp_enabled_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def mfa_required_by_policy(self) -> bool:
        """Whether this installation requires a second factor this account lacks.

        Computed on every response from the deployment's setting and the account's
        own enrolment, never stored. The policy belongs to the installation, so
        turning it off has to release every account it held, and an administrator
        who enrols is finished the moment the code verifies — with a stored flag,
        getting either of those wrong means an account that cannot get in and
        nobody able to say why.

        It is on the user payload because two readers decide on it: the account
        holder's own client, which is sent to the page that enrols a factor instead
        of waiting for a refusal, and an administrator looking at the user list,
        for whom "this admin still owes a factor" is what explains a support call.
        """
        return mfa_required_by_policy(self.role, self.totp_enabled_at)


class UserCreate(BaseModel):
    email: EmailAddress
    password: SecretStr
    role: UserRole = "viewer"
    full_name: Optional[str] = None
    rate_limit_minutes: int = Field(default=0, ge=0, le=RATE_LIMIT_MAX_MINUTES)

    @field_validator("password")
    @classmethod
    def _password_strength(cls, v: SecretStr) -> SecretStr:
        # validate_password_strength raises on weak input and returns the
        # input unchanged; re-return ``v`` keeps the SecretStr type.
        validate_password_strength(v)
        return v


class UserUpdate(BaseModel):
    email: Optional[EmailAddress] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    full_name: Optional[str] = None
    new_password: Optional[SecretStr] = None
    rate_limit_minutes: Optional[int] = Field(
        default=None, ge=0, le=RATE_LIMIT_MAX_MINUTES
    )

    @field_validator("new_password")
    @classmethod
    def _password_strength(cls, v: Optional[SecretStr]) -> Optional[SecretStr]:
        if v is None:
            return None
        validate_password_strength(v)
        return v

    @field_validator("role", mode="before")
    @classmethod
    def _coerce_role(cls, v):
        if v is None:
            return v
        if hasattr(v, "value"):
            return v.value
        return str(v)


class ToggleActiveResponse(BaseModel):
    id: uuid.UUID
    is_active: bool
    action: Literal["locked", "unlocked"]


class LoginRequest(BaseModel):
    """Credentials for sign-in.

    Password *strength* rules intentionally do NOT apply here: the policy
    governs what may be *set*, while sign-in must verify whatever the account
    already holds. Every rejected attempt — strong or weak — also has to reach
    the handler so it is counted by the rate limiter and recorded in the audit
    trail.
    """

    email: EmailAddress
    password: SecretStr
    # The TOTP code, when the account has a second factor enabled. Optional at
    # this layer because the platform cannot know before verifying the password
    # whether a code is required — and saying so earlier would make this endpoint
    # answer "this account exists and uses MFA" to anyone who asks.
    totp_code: Optional[SecretStr] = None
    # A one-time recovery code may replace the authenticator code when the device
    # is unavailable. It is accepted only after the password verifies and is
    # removed atomically from the stored hash list.
    recovery_code: Optional[SecretStr] = None


class PasswordChangeRequest(BaseModel):
    """Replacing the signed-in account's own password.

    ``current_password`` is required even though the caller already holds a valid
    access token. For an account whose password was assigned by an administrator
    that is a useful check in itself — it proves the caller is the person the
    password was handed to rather than someone who found a live session — and for
    every other account it is what stops a stolen token from becoming a takeover.

    A password that no longer matches is refused rather than accepted, and inside
    a session the *new* password is the one the caller keeps control of: that is
    the whole point of the operation.
    """

    current_password: SecretStr
    new_password: SecretStr

    @field_validator("new_password")
    @classmethod
    def _password_strength(cls, v: SecretStr) -> SecretStr:
        validate_password_strength(v)
        return v


class MfaSetupRequest(BaseModel):
    """Start enrolling a second factor; the password is re-checked here.

    Re-authentication rather than trusting the session: a stolen access token
    must not be enough to attach a new authenticator to the account, which is
    what would turn a 15-minute token theft into permanent access.
    """

    password: SecretStr


class MfaSetupResponse(BaseModel):
    """The candidate secret, and the URI an authenticator app scans.

    Returned once. Nothing is enabled until the code generated from it is
    verified, so a client that never completes enrolment leaves the account
    exactly as it was.
    """

    secret: str
    otpauth_uri: str
    digits: int = 6
    period_seconds: int = 30


class MfaCodeRequest(BaseModel):
    """Confirm or remove a second factor.

    ``password`` is required for both: enabling must be an act of the account
    holder, and disabling must not be possible from a borrowed session alone.
    """

    password: SecretStr
    code: Optional[SecretStr] = None


class MfaStatusResponse(BaseModel):
    enabled: bool
    enabled_at: Optional[datetime] = None


class MfaEnableResponse(MfaStatusResponse):
    """MFA state plus recovery codes, only on the one response that creates them."""

    recovery_codes: list[str] = Field(default_factory=list)


class MfaRecoveryCodesResponse(BaseModel):
    """Plaintext recovery codes, returned only immediately after enrolment."""

    codes: list[str]


class MfaRecoveryCodeRequest(BaseModel):
    code: SecretStr


class SessionResponse(BaseModel):
    """One session this account can still be used through.

    There is no `revoked` flag: `GET /auth/sessions` returns usable sessions
    only, so the field could never be anything but false. A session that ended
    is an audit event, not a session.
    """

    id: uuid.UUID
    created_at: datetime
    last_used_at: Optional[datetime] = None
    current: bool = False


class SecurityActivityResponse(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    action: str
    ip_address: str
    details: dict


class TokenResponse(BaseModel):
    """Access-token response for browser clients.

    Refresh tokens are delivered only via the HttpOnly cookie. Keeping them
    out of JSON prevents browser JavaScript from extracting the long-lived
    credential even if an API response is inspected by application code.
    """

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    """Optional body for refresh/logout requests.

    Browser clients authenticate with the HttpOnly ``opendrp_refresh`` cookie and
    therefore legitimately send an empty JSON object. API clients may instead put
    the token in this body. Making the field optional lets FastAPI parse both forms;
    the endpoint still rejects a request when neither a body token nor a cookie is
    present.
    """

    refresh_token: Optional[str] = None
