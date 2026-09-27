"""Encryption of secrets at rest, with support for rotating the key.

Provider and alert secrets (`system_settings.smtp_password` and friends) are
stored Fernet-encrypted in a column that keeps its ciphertext across an upgrade.
That is what makes a single `ENCRYPTION_KEY` a liability: rotating it used to
mean either losing every stored value or re-encrypting the database in a
migration, and a leaked key therefore stayed a live credential for as long as the
operator was unwilling to do that.

`cryptography`'s ``MultiFernet`` is the standard answer, and it costs nothing to
adopt: encryption uses the **first** key in the list, decryption tries every key.
An operator rotating a key therefore:

1. generates a new key and puts it first, keeping the old one in
   ``ENCRYPTION_PREVIOUS_KEYS`` — every stored value still decrypts;
2. runs ``python -m scripts.rotate_keys rewrap``, which re-encrypts each value
   with the new key;
3. drops the previous key once ``python -m scripts.rotate_keys status`` reports
   that nothing depends on it any more.

Each step is reversible and verifiable, which is the property a rotation
procedure needs to have: the alternative — a procedure that must work first try,
once, under pressure — is how credentials leak.

A key that is not a valid Fernet key is a startup failure in every environment.
No fallback derives one from the value: a derived key cannot read what the real
key wrote, so tolerating the value turns "the stored secrets became unreadable"
into a mystery, and it hides how little a passphrase that is not a key at all
protects what it encrypts.
"""

from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import settings


def configured_keys() -> list[str]:
    """Every configured key, newest first.

    The list is ordered by importance, not by age: index 0 is the key that
    encrypts, and everything after it exists so older ciphertext can still be
    read. `ENCRYPTION_KEY` is first by definition.
    """
    keys = [settings.ENCRYPTION_KEY]
    keys.extend(settings.encryption_previous_keys())
    return [key for key in keys if key]


def _fernet_for(key: str, *, primary: bool) -> Fernet:
    """The cipher for one configured key, or a startup error naming the setting.

    ``primary`` decides which setting the message names and nothing else: the
    first key encrypts, the rest exist so older ciphertext stays readable, and a
    malformed value in either place is reported rather than worked around. A typo
    in a previous key would otherwise derive a different key and turn "the old
    values became unreadable" into a mystery.
    """
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        if primary:
            raise RuntimeError("ENCRYPTION_KEY is not a valid Fernet key") from exc
        raise RuntimeError(
            "ENCRYPTION_PREVIOUS_KEYS contains a value that is not a valid Fernet key"
        ) from exc


_cache_signature: str | None = None
_cache_multi: MultiFernet | None = None


def _get_fernet() -> MultiFernet:
    """The cipher for the keys currently configured, rebuilt when they change.

    Cached by the *content* of the key list rather than built once at import:
    rotation happens while the process is running (a container restart is not
    always available), and a module-level singleton would keep using the old key
    until something reloaded the module.
    """
    global _cache_signature, _cache_multi
    keys = configured_keys()
    if not keys:
        raise RuntimeError("no ENCRYPTION_KEY is configured")
    signature = "\x00".join(keys)
    if _cache_signature != signature or _cache_multi is None:
        ferns = [_fernet_for(key, primary=index == 0) for index, key in enumerate(keys)]
        _cache_multi = MultiFernet(ferns)
        _cache_signature = signature
    return _cache_multi


def reset_cache() -> None:
    """Forget the cached cipher. Used by the rotation script and by tests."""
    global _cache_signature, _cache_multi
    _cache_signature = None
    _cache_multi = None


# Fail at import with an unusable key, rather than at the first request that
# happens to touch an encrypted column.
_get_fernet()


def encrypt_value(plain: Optional[str]) -> Optional[str]:
    if plain is None:
        return None
    if not plain:
        return plain
    return _get_fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt_value(encrypted: Optional[str]) -> Optional[str]:
    if encrypted is None:
        return None
    if not encrypted:
        return encrypted
    try:
        return _get_fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        raise RuntimeError("Unable to decrypt configured secret") from exc


def key_index_for(encrypted: Optional[str]) -> Optional[int]:
    """Which configured key can read this value, or ``None`` if none can.

    This is what makes "the old key can now be dropped" a checked statement
    instead of a guess: `scripts/rotate_keys status` counts values per index.
    """
    if not encrypted:
        return None
    for index, key in enumerate(configured_keys()):
        try:
            _fernet_for(key, primary=index == 0).decrypt(encrypted.encode("utf-8"))
            return index
        except (InvalidToken, ValueError, TypeError):
            continue
        except RuntimeError:
            continue
    return None


def rewrap_value(encrypted: Optional[str]) -> Optional[str]:
    """Re-encrypt a stored value with the newest key.

    Raises rather than returning the input unchanged when the value cannot be
    read: a rotation that silently leaves a value behind on the old key would
    make step 3 above wrong, and the operator would drop a key that is still
    needed.
    """
    if encrypted is None or encrypted == "":
        return encrypted
    try:
        return _get_fernet().rotate(encrypted.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        raise RuntimeError(
            "a stored value cannot be decrypted with any configured key; "
            "restore the key that wrote it before rotating"
        ) from exc


def mask_value(
    value: str, keep_first: int = 2, keep_last: int = 2, mask_char: str = "*"
) -> str:
    if not value:
        return value
    length = len(value)
    if length <= keep_first + keep_last:
        return mask_char * length
    return (
        value[:keep_first]
        + mask_char * (length - keep_first - keep_last)
        + value[-keep_last:]
    )
