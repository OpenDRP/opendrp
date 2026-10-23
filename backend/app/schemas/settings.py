import re
import uuid
from typing import Annotated, Any, Literal

from app.services.module_aliases import canonical_module_id
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    TypeAdapter,
    field_serializer,
    field_validator,
    model_validator,
)

_TELEGRAM_BOT_TOKEN_RE = re.compile(r"^[0-9]{5,20}:[A-Za-z0-9_\-]{20,128}$")
_TELEGRAM_CHAT_ID_RE = re.compile(r"^(@[A-Za-z0-9_]{4,}|[+-]?\d{4,32})$")
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)


def _validate_hostname_or_ip(value: str, field_name: str) -> str:
    stripped = value.strip()
    if _HOSTNAME_RE.match(stripped):
        return stripped
    if _IPV4_RE.match(stripped):
        return stripped
    try:
        import ipaddress
        ipaddress.IPv6Address(stripped)
        return stripped
    except Exception:
        pass
    raise ValueError(f"{field_name}: invalid hostname or IP address")


class SystemSettingsBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    telegram_bot_token: str | None = Field(None, max_length=512)
    smtp_host: str | None = Field(None, max_length=255)
    smtp_port: int | None = Field(None, ge=1, le=65535)
    smtp_security_mode: str = "starttls"
    smtp_user: str | None = Field(None, max_length=255)
    smtp_password: str | None = Field(None, max_length=512)
    # These are encrypted operational addresses. They are returned masked by
    # SystemSettingsResponse; keeping the wire type as string also lets the UI
    # submit the mask unchanged while editing an unrelated setting.
    smtp_from_email: str | None = None
    alert_recipient_email: str | None = None

    # --- Alert channels ---
    email_alerts_enabled: bool = False
    telegram_alerts_enabled: bool = False
    # User UUIDs receiving email alerts; validated in SystemSettingsUpdate.
    alert_email_user_ids: list[str] | None = None
    # Telegram chat IDs, each validated in SystemSettingsUpdate.
    telegram_chat_ids: list[str] | None = None

    # --- Alert budget (see app/services/alert_policy.py) ---
    # The operator's half of the alert policy. ``None`` is not "off" or "zero":
    # it is "this installation has not decided this one", and the environment's
    # ``ALERT_*`` value answers it. The four numbers carry the same bounds the
    # environment schema does, so a row cannot be written through the API that the
    # resolver would have to refuse; the one relationship between two of them (the
    # digest threshold stays below the direct one) is checked where both values are
    # known — in the service, against the row as it will be saved, because a save
    # may state only one of the pair.
    alert_confidence_direct: int | None = Field(None, ge=1, le=100)
    alert_confidence_digest: int | None = Field(None, ge=0, le=99)
    alert_phishing_digest_enabled: bool | None = None
    alert_phishing_digest_hour_utc: int | None = Field(None, ge=0, le=23)
    alert_no_channel_retry_hours: int | None = Field(None, ge=0, le=8760)
    alert_candidate_change_notifications: bool | None = None
    # The breach module's half of the budget (see app/services/alert_policy.py).
    # ``None`` is "not decided here", exactly as above; ``all`` restores the
    # behaviour that reported spam and fabricated incidents like any other.
    alert_breach_noise_policy: Literal["store_only_spam", "verified_only", "all"] | None = None
    alert_breach_digest_threshold: int | None = Field(None, ge=0, le=500)

    # --- Scan schedules (UTC) ---
    schedule_phishing: dict | None = None
    schedule_breaches: dict | None = None
    schedule_dns_security: dict | None = None
    schedule_exposure: dict | None = None
    schedules: dict[str, dict | None] | None = None


class SystemSettingsUpdate(SystemSettingsBase):
    expected_version: int | None = Field(None, ge=1)
    @field_validator("smtp_security_mode")
    @classmethod
    def _validate_smtp_security_mode(cls, v: str) -> str:
        mode = str(v or "").strip().lower()
        if mode not in {"starttls", "ssl", "plain"}:
            raise ValueError("smtp_security_mode: expected starttls, ssl, or plain")
        return mode

    @field_validator("telegram_bot_token", mode="before")
    @classmethod
    def _validate_tg_bot_token(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not s:
            return None
        if "*" in s or "•" in s:
            return s
        if not _TELEGRAM_BOT_TOKEN_RE.match(s):
            raise ValueError("telegram_bot_token: invalid format (expected NNNN:XXXX)")
        return s

    @field_validator("smtp_host", mode="before")
    @classmethod
    def _validate_smtp_host(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not s:
            return None
        return _validate_hostname_or_ip(s, "smtp_host")

    @field_validator("smtp_port", mode="before")
    @classmethod
    def _validate_smtp_port(cls, v):
        if v is None:
            return None
        if isinstance(v, str) and v.strip() == "":
            return None
        if isinstance(v, bool) or isinstance(v, float):
            raise ValueError("smtp_port: must be an integer")
        try:
            iv = int(v)
        except (ValueError, TypeError):
            raise ValueError("smtp_port: must be an integer between 1 and 65535, or empty")
        if iv < 1 or iv > 65535:
            raise ValueError("smtp_port: must be between 1 and 65535")
        return iv

    @field_validator("smtp_user", mode="before")
    @classmethod
    def _validate_smtp_user(cls, v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        if not s:
            return None
        if len(s) > 255:
            raise ValueError("smtp_user: too long")
        if "\x00" in s or "\r" in s or "\n" in s:
            raise ValueError("smtp_user: contains control characters")
        return s

    @field_validator("smtp_password", mode="before")
    @classmethod
    def _validate_smtp_password(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if isinstance(v, str) and v == "":
            return None
        s = v
        if len(s) > 512:
            raise ValueError("smtp_password: too long")
        if "\x00" in s:
            raise ValueError("smtp_password: contains NUL byte")
        return s

    @field_validator("smtp_from_email", "alert_recipient_email", mode="before")
    @classmethod
    def _validate_email_or_mask(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("email address must be a string")
        value = v.strip()
        if not value:
            return None
        # The response deliberately contains a non-reversible mask. It must be
        # accepted on a subsequent save so changing an unrelated setting does
        # not erase the encrypted address.
        if "*" in value or "•" in value:
            return value
        try:
            return str(TypeAdapter(EmailStr).validate_python(value))
        except Exception as exc:
            raise ValueError("valid email address required") from exc

    @field_validator("alert_email_user_ids", mode="before")
    @classmethod
    def _validate_alert_email_user_ids(cls, v):
        if v is None:
            return None
        if not isinstance(v, list) or len(v) > 100:
            raise ValueError("alert_email_user_ids: expected at most 100 user ids")
        out: list[str] = []
        for item in v:
            s = str(item).strip()
            try:
                uuid.UUID(s)
            except (ValueError, AttributeError, TypeError) as e:
                raise ValueError(f"alert_email_user_ids: invalid user id {s!r}") from e
            if s not in out:
                out.append(s)
        return out

    @field_validator("telegram_chat_ids", mode="before")
    @classmethod
    def _validate_telegram_chat_ids(cls, v):
        if v is None:
            return None
        if isinstance(v, str):
            # Accept a newline/comma separated blob from the UI textarea.
            v = [chunk for chunk in v.replace(",", "\n").split("\n")]
        if not isinstance(v, list) or len(v) > 100:
            raise ValueError("telegram_chat_ids: expected at most 100 chat ids")
        out: list[str] = []
        for item in v:
            s = str(item).strip()
            if not s:
                continue
            if not _TELEGRAM_CHAT_ID_RE.match(s):
                raise ValueError(
                    f"telegram_chat_ids: invalid chat id {s[:32]!r} (expected @username or numeric id)"
                )
            if s not in out:
                out.append(s)
        return out

    @field_validator("schedules", mode="before")
    @classmethod
    def _validate_module_schedules(cls, value):
        if value is None:
            return None
        if not isinstance(value, dict) or len(value) > 100:
            raise ValueError("schedules: expected an object with at most 100 module entries")
        validated = {}
        for module_id, spec in value.items():
            clean_id = canonical_module_id(str(module_id))
            if clean_id in {"phishing", "breaches", "dns", "exposure"}:
                raise ValueError("Built-in schedules must use their dedicated fields")
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", clean_id):
                raise ValueError("schedules: invalid module id")
            if spec is None:
                validated[clean_id] = None
                continue
            if not isinstance(spec, dict) or set(spec) != {"days", "hour", "minute"}:
                raise ValueError(f"schedules.{clean_id}: expected days, hour, and minute")
            days, hour, minute = spec["days"], spec["hour"], spec["minute"]
            if not isinstance(days, list) or not days or any(type(day) is not int or not 0 <= day <= 6 for day in days):
                raise ValueError(f"schedules.{clean_id}.days: non-empty weekday list 0..6")
            if type(hour) is not int or not 0 <= hour <= 23:
                raise ValueError(f"schedules.{clean_id}.hour: integer 0..23")
            if type(minute) is not int or not 0 <= minute <= 59:
                raise ValueError(f"schedules.{clean_id}.minute: integer 0..59")
            validated[clean_id] = {"days": sorted(set(days)), "hour": hour, "minute": minute}
        return validated

    @field_validator("schedule_phishing", "schedule_breaches", "schedule_dns_security", "schedule_exposure", mode="before")
    @classmethod
    def _validate_schedule(cls, v):
        if v is None:
            return None
        if not isinstance(v, dict) or set(v) != {"days", "hour", "minute"}:
            raise ValueError("schedule: expected days, hour and minute only")
        days = v.get("days")
        hour = v.get("hour")
        minute = v.get("minute")
        if not isinstance(days, list) or not days:
            raise ValueError("schedule.days: non-empty list of weekdays (0=Sun..6=Sat)")
        cleaned_days: list[int] = []
        for d in days:
            if type(d) is not int or not 0 <= d <= 6:
                raise ValueError("schedule.days: each day must be an integer 0..6")
            if d not in cleaned_days:
                cleaned_days.append(d)
        if type(hour) is not int or not 0 <= hour <= 23:
            raise ValueError("schedule.hour: integer 0..23")
        if type(minute) is not int or not 0 <= minute <= 59:
            raise ValueError("schedule.minute: integer 0..59")
        return {"days": sorted(cleaned_days), "hour": hour, "minute": minute}


class SystemSettingsResponse(SystemSettingsBase):
    id: uuid.UUID
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @model_validator(mode="before")
    @classmethod
    def decrypt_persisted_values(cls, value):
        """Expose validated values, never Fernet ciphertext, to API clients."""
        if isinstance(value, dict):
            return value

        from app.core.crypto import decrypt_value

        fields = (
            "id",
            "version",
            "created_at",
            "updated_at",
            "telegram_bot_token",
            "smtp_host",
            "smtp_port",
            "smtp_security_mode",
            "smtp_user",
            "smtp_password",
            "smtp_from_email",
            "alert_recipient_email",
            "email_alerts_enabled",
            "telegram_alerts_enabled",
            "alert_email_user_ids",
            "telegram_chat_ids",
            "alert_confidence_direct",
            "alert_confidence_digest",
            "alert_phishing_digest_enabled",
            "alert_phishing_digest_hour_utc",
            "alert_no_channel_retry_hours",
            "alert_candidate_change_notifications",
            "alert_breach_noise_policy",
            "alert_breach_digest_threshold",
            "schedule_phishing",
            "schedule_breaches",
            "schedule_dns_security",
            "schedule_exposure",
            "schedules",
        )
        result = {field: getattr(value, field, None) for field in fields}
        for field in (
            "telegram_bot_token",
            "smtp_password",
            "smtp_from_email",
            "alert_recipient_email",
        ):
            result[field] = decrypt_value(result[field])
        return result

    @field_serializer(
        "telegram_bot_token",
        "smtp_password",
        "smtp_from_email",
        "alert_recipient_email",
    )
    def mask_secret(self, v: str | None) -> str | None:
        if not v:
            return None
        from app.core.crypto import decrypt_value, mask_value

        try:
            decrypted = decrypt_value(v) or v
        except RuntimeError:
            # ``decrypt_persisted_values`` already turns ORM ciphertext into
            # plaintext. This fallback also keeps response serialization safe
            # for callers that provide an already-plain value in production.
            decrypted = v
        return mask_value(decrypted, keep_first=2, keep_last=2)


class AlertPolicyResponse(BaseModel):
    """The alert budget as it is *in force*, not as it is stored (WI-13).

    The Settings page edits the six columns; this is what the platform is routing
    by right now, and the two are not the same thing: a value the operator never
    stated is the deployment's, and a row that does not hold together is refused in
    favour of it. ``source`` answers "did my save take effect?" and ``invalid``
    names the fields that were refused, so the page can say which of the two
    answered instead of showing six empty inputs and leaving the operator to guess.
    """

    model_config = ConfigDict(from_attributes=True)

    confidence_direct: int
    confidence_digest: int
    digest_enabled: bool
    digest_hour_utc: int
    no_channel_retry_hours: int
    candidate_change_notifications: bool
    #: The breach module's two values: which incidents the channel stores silently,
    #: and how many new incidents one scan reports before the rest wait for the
    #: digest (0 = no waiting).
    breach_noise_policy: Literal["store_only_spam", "verified_only", "all"]
    breach_digest_threshold: int
    source: Literal["environment", "settings"]
    invalid: list[str]


class TestEmailRequest(BaseModel):
    to: EmailStr | None = None


class TestEmailResponse(BaseModel):
    """What `POST /settings/test-email` answers when the test message went out.

    Two fields, both always present: the recipient the service actually used (the
    request's `to`, or the configured alert address when it is omitted) and the
    status. The SPA has its own interface for this, compared with this model by
    `scripts/check_api_types.py`.
    """

    status: str
    to: str


class TestTelegramResponse(BaseModel):
    """What `POST /settings/test-telegram` answers, chat by chat.

    The four counts are the route's promise: `sent` is how many chats accepted the
    message, `total` how many were attempted, `validated` how many the bot could
    reach, and `validation_failed` the difference.

    `results` stays a list of provider objects rather than a nested model on
    purpose. Each entry is Telegram's own chat shape — `chat_id` and `ok`, plus
    either the chat metadata of an accepted send or the error code of a rejected
    one — and a strict entry model would have to add nulls for the fields the other
    variant omits, changing the bytes the SPA receives today. The entry shape is
    declared in the client (`TelegramChatValidationResult`) and served as a payload
    of its own by `POST /settings/validate-telegram`.
    """

    sent: int
    total: int
    validated: int
    validation_failed: int
    results: list[dict[str, Any]]


class DatabasePoolSettings(BaseModel):
    """The connection pool the process is actually running with.

    Read from `core_settings` rather than from the Compose file, because the
    question this endpoint answers is what the container received — the two can
    disagree after a recreate that did not happen.
    """

    size: int
    max_overflow: int
    pool_timeout_seconds: int


class RuntimeTimeouts(BaseModel):
    """The three timeouts an operator is most likely to have just changed.

    The last two are `float` in `core/config.py` and stay `float` here, so the
    diagnostics page prints `3.0` and `45.0` exactly as the applied settings hold
    them rather than an integer that looks like a different value.
    """

    statement_ms: int
    command_seconds: float
    outbound_dns_seconds: float


class RuntimeConfigurationResponse(BaseModel):
    """What `GET /settings/runtime` answers: applied configuration, never secrets.

    The route deliberately exposes no connection URL and no credential; this model is
    the enumeration of what it may expose, so a field added to the handler without a
    field here is dropped rather than leaked.
    """

    app_env: str
    version: str
    database_pool: DatabasePoolSettings
    timeouts: RuntimeTimeouts
    resource_limits_source: str


class TelegramChatOkResult(BaseModel):
    """One chat the bot could reach, with the metadata `getChat` reported.

    The three chat fields are nullable but not optional: they are keys the provider
    answer always produces, and a null title is a value Telegram sent rather than a
    field this platform invented. That is what keeps the response's bytes the same as
    the dict this model replaced.
    """

    chat_id: str
    ok: Literal[True]
    chat_type: str | None
    username: str | None
    title: str | None


class TelegramChatErrorResult(BaseModel):
    """One chat the bot could not reach, with the reason it could not."""

    chat_id: str
    ok: Literal[False]
    error_code: str
    error: str


class TelegramValidationResponse(BaseModel):
    """What `POST /settings/validate-telegram` answers, chat by chat.

    `ok` discriminates the two row shapes rather than one row model whose unused
    fields would arrive as nulls: a validation pass and a failed validation do not
    have the same keys, and the SPA's `TelegramChatValidationResult` already declares
    both.
    """

    valid: int
    total: int
    results: list[Annotated[TelegramChatOkResult | TelegramChatErrorResult, Field(discriminator="ok")]]


class TestTelegramRequest(BaseModel):
    chat_id: str | None = Field(None, max_length=255)

    @field_validator("chat_id", mode="before")
    @classmethod
    def _validate_chat_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not isinstance(v, str):
            raise ValueError("chat_id must be a string")
        s = v.strip()
        if not s:
            return None
        if not _TELEGRAM_CHAT_ID_RE.match(s):
            raise ValueError(
                "chat_id: invalid format (expected @username or numeric id)"
            )
        return s
