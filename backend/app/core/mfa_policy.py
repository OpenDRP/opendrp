"""The one place the installation's second-factor policy is interpreted.

``REQUIRE_MFA_ROLES`` (and the older ``REQUIRE_MFA_FOR_ADMINS``, which adds
``admin`` to whatever the list names) is a property of the deployment, not of an
account:
turning it on writes nothing to ``users``, and turning it off releases every
account it held. That is deliberate — a per-account flag would have to be
back-filled for administrators who already exist, and would survive the setting
being switched off, which is the kind of state nobody can explain six months
later. The cost is that "does this account owe a second factor?" has to be
answered from two facts at once, and more than one caller needs the answer:

* the credential gate in ``app/api/deps.py``, which refuses the account everywhere
  but the endpoints that fix it;
* the user payload (``app/schemas/user.py``), which tells a client which step to
  ask for, so an administrator learns at sign-in rather than from a refusal on the
  first admin page;
* the CLI, which reports the same state to a host operator.

Keeping the predicate in one function is what stops those three from drifting:
the day the rule changes — a different role, an exemption, a grace period — it
changes in one place, and the tests that pin it are about the rule rather than
about each caller's copy of it. The rule is now "the roles this installation
names", which is why the role list is parsed here too: a caller that split the
environment value itself would be a second copy of the rule.
"""

from __future__ import annotations

from typing import Any

from app.core.config import settings


def required_roles() -> frozenset[str]:
    """The roles this installation requires a second factor from.

    Two settings, one answer: ``REQUIRE_MFA_ROLES`` names roles directly, and the
    older ``REQUIRE_MFA_FOR_ADMINS`` adds ``admin``. They are read together rather
    than one replacing the other, because the flag is what an existing installation
    has already turned on and a deployment that sets both means the union.
    """
    names = {
        item.strip().lower()
        for item in (settings.REQUIRE_MFA_ROLES or "").split(",")
        if item.strip()
    }
    if settings.REQUIRE_MFA_FOR_ADMINS:
        names.add("admin")
    return frozenset(names)


def mfa_required_by_policy(role: Any, totp_enabled_at: Any) -> bool:
    """Whether this account owes a second factor the installation requires.

    Whichever roles ``REQUIRE_MFA_ROLES`` lists, plus administrators when
    ``REQUIRE_MFA_FOR_ADMINS`` is set. The default is nobody: the policy exists
    because an administrator account is the one worth stealing — it can create
    users, read the audit trail and change the installation's settings — and an
    installation that required a factor from every viewer would be one deployment
    decision away from locking out accounts nobody asked to protect. Requiring it
    from analysts is a real choice some installations make, which is why the
    setting is a list rather than a boolean.

    ``totp_enabled_at`` is the enrolment fact (``NULL`` means no factor). It is not
    a secret: the same value is already returned to the account itself by
    ``GET /auth/mfa``, and to administrators in the user list, because "has a
    factor" is what decides whether the recovery action applies.
    """
    if totp_enabled_at is not None:
        return False
    return str(getattr(role, "value", role)) in required_roles()
