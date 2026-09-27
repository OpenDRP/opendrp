from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin
from app.core.audit import AuditLogger
from app.core.config import settings as core_settings
from app.core.safe_errors import sanitize_external_error
from app.schemas.settings import (
    SystemSettingsResponse,
    SystemSettingsUpdate,
    TestEmailRequest,
    TestTelegramRequest,
)
from app.services.settings_service import (
    _ENCRYPTED_FIELDS,
    SettingsService,
    is_unchanged_masked_value,
)

router = APIRouter(prefix="/settings", tags=["System Settings"])


@router.get("", response_model=SystemSettingsResponse)
async def get_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    settings = await SettingsService(db).get_singleton()
    await AuditLogger.emit_background(
        db,
        action="settings.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={},
    )
    return settings


@router.get("/runtime")
async def get_runtime_configuration(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Expose safe, applied container configuration for operator diagnostics.

    Secrets and raw connection URLs are intentionally absent. This endpoint
    answers the common self-host question "did the recreated container receive
    my setting?" without turning the Settings page into a secret disclosure.
    """
    await AuditLogger.emit_background(
        db,
        action="settings.runtime.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={},
    )
    return {
        "app_env": core_settings.APP_ENV,
        "version": core_settings.OPENDRP_VERSION or "development",
        "database_pool": {
            "size": core_settings.DB_POOL_SIZE,
            "max_overflow": core_settings.DB_MAX_OVERFLOW,
            "pool_timeout_seconds": core_settings.DB_POOL_TIMEOUT_SECONDS,
        },
        "timeouts": {
            "statement_ms": core_settings.DB_STATEMENT_TIMEOUT_MS,
            "command_seconds": core_settings.DB_COMMAND_TIMEOUT_SECONDS,
            "outbound_dns_seconds": core_settings.OUTBOUND_DNS_TIMEOUT_SECONDS,
        },
        "resource_limits_source": "docker-compose.yml",
    }


@router.put("", response_model=SystemSettingsResponse)
async def update_settings(
    request: Request,
    data: SystemSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    service = SettingsService(db)
    s = await service.get_singleton()
    raw_dump = data.model_dump(exclude_unset=True)

    updated_fields = [
        k
        for k, v in raw_dump.items()
        if not (
            k in _ENCRYPTED_FIELDS
            and is_unchanged_masked_value(
                v, getattr(s, _ENCRYPTED_FIELDS[k], None)
            )
        )
    ]
    result = await service.update_settings(s, data)
    await AuditLogger.emit(
        db,
        action="settings.update",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"updated_fields": updated_fields},
    )
    return result


@router.post("/test-email", status_code=200)
async def send_test_email(
    request: Request,
    req: TestEmailRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    service = SettingsService(db)
    s = await service.get_singleton()
    try:
        result = await service.send_test_email(s, req.to)
    except Exception as e:
        await AuditLogger.emit(
            db,
            action="settings.test_email_failed",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                "to": req.to,
                "error": sanitize_external_error(e, limit=300),
            },
        )
        raise
    await AuditLogger.emit(
        db,
        action="settings.test_email_sent",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"to": req.to},
    )
    return result


@router.post("/validate-telegram", status_code=200)
async def validate_telegram(
    request: Request,
    req: TestTelegramRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    from app.services.alert_service import AlertService

    s = await SettingsService(db).get_singleton()
    try:
        result = await AlertService(db).validate_telegram_chats(s, req.chat_id)
    except Exception as e:
        await AuditLogger.emit(
            db,
            action="settings.telegram.validate_failed",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={"chat_id": req.chat_id, "error": type(e).__name__},
        )
        raise
    await db.commit()
    return result


@router.post("/test-telegram", status_code=200)
async def send_test_telegram(
    request: Request,
    req: TestTelegramRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    from app.services.alert_service import AlertService

    s = await SettingsService(db).get_singleton()
    try:
        result = await AlertService(db).send_test_telegram(s, req.chat_id)
    except Exception as e:
        await AuditLogger.emit(
            db,
            action="settings.test_telegram_failed",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={"chat_id": req.chat_id, "error": str(e)[:300]},
        )
        raise
    await AuditLogger.emit(
        db,
        action="settings.test_telegram_sent",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"sent": result.get("sent"), "total": result.get("total")},
    )
    await db.commit()
    return result
