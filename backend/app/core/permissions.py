"""What each role may do, declared once.

The three roles and their reach used to be expressed by three predicates, each
spelling out the roles it accepted — and the one named ``require_viewer_plus``
accepted *every* role. It read like a boundary while checking nothing, and two consequences
followed from there (USR-04 in
``docs/internal/audit-2026-10-15_users-rbac_03``):

* a fourth member added to ``UserRole`` would automatically receive every
  ``viewer+`` route, because the check was written as "the role is one of these
  three" rather than "the role holds this capability";
* "what may an analyst do?" could only be answered by reading the route table.

This module is that answer in one place. A **capability** is a named thing the
platform lets an account do, and :data:`CAPABILITY_ROLES` says which roles hold
it. Route dependencies are derived from the table, so a route declares a
capability rather than a list of roles, and granting a new role anything requires
editing this file — which a test refuses to let you forget
(``tests/test_route_access_gate.py`` requires every ``UserRole`` member to appear
in the table and every route to name a capability or a documented exception).

Why only three capabilities
---------------------------
They are the three levels the platform actually enforces today. Splitting
``manage_users`` from ``manage_settings`` would be a product decision — both are
administrator-only, and inventing a distinction no route makes would produce a
table that lies about the code. When a route needs a narrower or different
audience, add the capability and point the route at it; nothing else has to move.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, FrozenSet

from app.models.user import UserRole, role_name


class Capability(str, Enum):
    """A named thing an account may do on this platform."""

    #: Manage your own account: password, second factor, sessions, own security
    #: activity. Every role holds it, including any role added later, because this
    #: is the account holder's business rather than an administrator's — and the
    #: sign-in gate (``get_current_user``) already refuses the account everywhere
    #: else while a credential is out of order.
    SELF_SERVICE = "self_service"
    #: Read the platform: dashboard, inventory, findings, reports, alert lists.
    #: Every role holds it — an account that could not read anything could not do
    #: its job, and the boundary that matters is the one below.
    VIEW_PLATFORM = "view_platform"
    #: Act on findings rather than read them: run scans, triage, promote an
    #: observation into a monitored asset, delete a finding.
    ANALYSE = "analyse"
    #: Administer the installation: accounts, roles, settings, the audit trail,
    #: connector tokens.
    ADMINISTER = "administer"


#: The one place roles are listed. Ordering inside a frozenset is irrelevant;
#: the mapping is the contract.
CAPABILITY_ROLES: dict[Capability, FrozenSet[str]] = {
    Capability.SELF_SERVICE: frozenset(
        {UserRole.admin.value, UserRole.analyst.value, UserRole.viewer.value}
    ),
    Capability.VIEW_PLATFORM: frozenset(
        {UserRole.admin.value, UserRole.analyst.value, UserRole.viewer.value}
    ),
    Capability.ANALYSE: frozenset({UserRole.admin.value, UserRole.analyst.value}),
    Capability.ADMINISTER: frozenset({UserRole.admin.value}),
}

#: Human-readable refusal, one per capability, used by the guards and by the
#: audit row's ``required`` marker.
CAPABILITY_DETAILS: dict[Capability, str] = {
    Capability.SELF_SERVICE: "Insufficient permissions",
    Capability.VIEW_PLATFORM: "Insufficient permissions",
    Capability.ANALYSE: "Analyst or Admin role required",
    Capability.ADMINISTER: "Admin role required",
}


def roles_for(capability: Capability) -> FrozenSet[str]:
    """Which roles hold ``capability``."""
    return CAPABILITY_ROLES[capability]


def role_holds(role: Any, capability: Capability) -> bool:
    """Whether ``role`` (enum member or string) holds ``capability``."""
    return role_name(role) in CAPABILITY_ROLES[capability]


def roles_without_capability(capability: Capability) -> FrozenSet[str]:
    """Every declared role that does *not* hold ``capability``.

    The route gate prints the difference when a route's access cell disagrees
    with the code, which is more useful than "viewer is refused".
    """
    declared = {member.value for member in UserRole}
    return frozenset(declared - CAPABILITY_ROLES[capability])


def declared_roles_missing_from_table() -> FrozenSet[str]:
    """``UserRole`` members no capability mentions — the gate's completeness test.

    Empty today. A fourth role added to the enum without being placed in the
    table would make this non-empty, and the route gate fails on it: silence is
    how a new role inherits every route that used to read "viewer+".
    """
    mentioned: set[str] = set()
    for roles in CAPABILITY_ROLES.values():
        mentioned |= set(roles)
    return frozenset({member.value for member in UserRole} - mentioned)


def capability_error(capability: Capability) -> str:
    """The message a refusal carries for ``capability``."""
    return CAPABILITY_DETAILS[capability]


__all__ = [
    "Capability",
    "CAPABILITY_DETAILS",
    "CAPABILITY_ROLES",
    "capability_error",
    "declared_roles_missing_from_table",
    "role_holds",
    "roles_for",
    "roles_without_capability",
]
