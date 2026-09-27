import re
import uuid
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

    # --- Scan schedules (UTC) ---
    schedule_phishing: dict | None = None
    schedule_breaches: dict | None = None


class SystemSettingsUpdate(SystemSettingsBase):
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
        if not isinstance(v, list):
            raise ValueError("alert_email_user_ids: expected a list of user ids")
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
        if not isinstance(v, list):
            raise ValueError("telegram_chat_ids: expected a list of chat ids")
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

    @field_validator("schedule_phishing", "schedule_breaches", mode="before")
    @classmethod
    def _validate_schedule(cls, v):
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("schedule: expected an object")
        days = v.get("days")
        hour = v.get("hour")
        minute = v.get("minute")
        if not isinstance(days, list) or not days:
            raise ValueError("schedule.days: non-empty list of weekdays (0=Sun..6=Sat)")
        cleaned_days: list[int] = []
        for d in days:
            if not isinstance(d, int) or not 0 <= d <= 6:
                raise ValueError("schedule.days: each day must be an integer 0..6")
            if d not in cleaned_days:
                cleaned_days.append(d)
        if not isinstance(hour, int) or not 0 <= hour <= 23:
            raise ValueError("schedule.hour: integer 0..23")
        if not isinstance(minute, int) or not 0 <= minute <= 59:
            raise ValueError("schedule.minute: integer 0..59")
        return {"days": sorted(cleaned_days), "hour": hour, "minute": minute}


class SystemSettingsResponse(SystemSettingsBase):
    id: uuid.UUID
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
            "schedule_phishing",
            "schedule_breaches",
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


class TestEmailRequest(BaseModel):
    to: EmailStr | None = None


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
