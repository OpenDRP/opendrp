"""Operator-owned provider accounts; credential references are names, not values."""

import re
from sqlalchemy import select
from app.models.source_account import SourceAccount
from app.core.crypto import decrypt_value, encrypt_value, mask_value
from app.core.exceptions import BadRequestException, NotFoundException
from app.services.provider_quota import validate_policy

# Printable ASCII without spaces, the same rule connectors apply before sending
# a key in a header. A value that fails it could never authenticate anyway.
API_KEY_PATTERN = re.compile(r"[\x21-\x7e]{1,512}")


async def provision_account(db, *, source_id, name, credential_ref=None):
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", source_id) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,63}", name
    ):
        raise BadRequestException("Invalid account identity")
    if credential_ref and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", credential_ref):
        raise BadRequestException(
            "Credential reference must be an environment variable name"
        )
    account = (
        await db.execute(
            select(SourceAccount).where(
                SourceAccount.source_id == source_id, SourceAccount.name == name
            )
        )
    ).scalar_one_or_none()
    created = account is None
    credential_ref_updated = False
    if created:
        account = SourceAccount(
            source_id=source_id,
            name=name,
            credential_ref=credential_ref,
            policy={"approved": False},
        )
        db.add(account)
    elif credential_ref is not None and account.credential_ref != credential_ref:
        # Allow an operator to attach/update the secret-manager variable name
        # for migrated/default account rows without replacing the account UUID.
        account.credential_ref = credential_ref
        credential_ref_updated = True
    await db.flush()
    return account, created, credential_ref_updated


async def approve_policy(db, account_id, policy):
    account = await db.get(SourceAccount, account_id)
    if account is None:
        raise NotFoundException("Source account not found")
    if set(policy) - {
        "approved",
        "requests_per_minute",
        "daily_budget",
    }:
        raise BadRequestException("Unsupported account policy field")
    if type(policy.get("approved")) is not bool:
        raise BadRequestException("Explicit approved boolean required")
    if not all(key in policy for key in ("requests_per_minute", "daily_budget")):
        raise BadRequestException("Explicit minute and daily request budgets required")
    try:
        validate_policy(policy)
    except ValueError as exc:
        raise BadRequestException(str(exc)) from exc
    account.policy = dict(policy)
    await db.flush()
    return account


async def _account_by_id(db, account_id):
    account = await db.get(SourceAccount, account_id)
    if account is None:
        raise NotFoundException("Source account not found")
    return account


async def set_api_key(db, account_id, api_key):
    """Store an account's provider key encrypted; only a masked hint is kept in clear."""
    if not isinstance(api_key, str) or not API_KEY_PATTERN.fullmatch(api_key):
        raise BadRequestException("Invalid API key format")
    account = await _account_by_id(db, account_id)
    account.api_key_encrypted = encrypt_value(api_key)
    account.api_key_hint = mask_value(api_key, keep_first=0, keep_last=4)
    await db.flush()
    return account


async def clear_api_key(db, account_id):
    account = await _account_by_id(db, account_id)
    account.api_key_encrypted = None
    account.api_key_hint = None
    await db.flush()
    return account


async def api_key_for_connector(db, connector):
    """The key of the account this connector is bound to, if it belongs to its provider.

    A connector never receives another account's key: the binding and the
    provider must both match the account row that holds the ciphertext.
    """
    if not connector.source_account_id:
        return None
    account = await db.get(SourceAccount, connector.source_account_id)
    if account is None or not account.api_key_encrypted:
        return None
    if account.source_id != connector.provider:
        return None
    return decrypt_value(account.api_key_encrypted)
