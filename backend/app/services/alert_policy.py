"""The alert budget's operator-set values, resolved into one policy.

Eight values decide how loud the channel is: where a candidate stops being a message
and starts being a line in the daily digest, below which it is only a line in the
list, whether the digest runs at all and at which UTC hour, how long a finding that
no channel can receive is held instead of consumed, whether a *revision* of an
already reported candidate is worth a second message, and - for credential breaches -
which incidents are stored silently and how many new incidents one scan may report
before the rest wait for the digest.

Two sources can state them, and until this module existed only the first could:

* the **environment** is the deployment's answer - the values ``.env``, Compose and
  CI carry, read once when a process starts. It is where the platform's defaults
  live, and it is the answer for every installation that never opens the Settings
  page;
* the ``system_settings`` row is the **operator's** answer, and it is the one that
  can change without recreating a container. The Settings page writes it; the
  delivery path, the digest and the ingest read it.

The rule between the two is "the row answers where it states a value, and the
environment answers the rest". A column that is NULL is *unset*, not zero: an
operator who raises one threshold has not also asked for the other five to be
reset, and a fresh installation has stated nothing at all. Both sources are held
to the same bounds, including the one that is a relationship rather than a range -
the digest threshold must stay below the direct one, because an equal pair leaves
no middle band and silences exactly the candidates the digest exists to report.

The values are read at the moment they are used rather than cached at start, so a
save takes effect on the next scan instead of the next restart. A row that became
inconsistent - because the environment moved under it, or because one field was
written by an older client - is reported as such and *not* honoured: routing
candidates through a threshold pair that contradicts itself is worse than ignoring
the operator's half-configured row, and the environment's consistent answer is
still a working installation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import BREACH_NOISE_POLICIES as NOISE_POLICIES
from app.core.config import settings as core_settings
from app.models.settings import SystemSettings

#: ``system_settings`` column -> policy field. The column names are the ones the
#: API and the Settings page use, so an operator reading either sees the same word
#: for the same value.
ROW_FIELDS: tuple[tuple[str, str], ...] = (
    ("alert_confidence_direct", "confidence_direct"),
    ("alert_confidence_digest", "confidence_digest"),
    ("alert_phishing_digest_enabled", "digest_enabled"),
    ("alert_phishing_digest_hour_utc", "digest_hour_utc"),
    ("alert_no_channel_retry_hours", "no_channel_retry_hours"),
    ("alert_candidate_change_notifications", "candidate_change_notifications"),
    ("alert_breach_noise_policy", "breach_noise_policy"),
    ("alert_breach_digest_threshold", "breach_digest_threshold"),
)

#: The bounds each numeric value is held to, mirroring the environment schema and
#: the Settings page's inputs. A stored row is trusted no further than a submitted
#: form: the database is not the only writer that has ever existed.
_BOUNDS: dict[str, tuple[int, int]] = {
    "confidence_direct": (1, 100),
    "confidence_digest": (0, 99),
    "digest_hour_utc": (0, 23),
    "no_channel_retry_hours": (0, 8760),
    # 0 means "one message per scan": the threshold is the point past which a scan
    # stops being a report and starts being a backlog, and an installation that
    # never wants to wait for a digest states it by turning the number off.
    "breach_digest_threshold": (0, 500),
}

#: Why one breach incident is noise, as a stored reason. Spam and fabricated lists
#: are the two the source's own flags name; ``unverified`` is only ever a reason
#: under ``verified_only``.
NOISE_REASONS: tuple[str, ...] = ("spam_list", "fabricated", "unverified")


@dataclass(frozen=True)
class AlertPolicy:
    """The values the alert budget is answering with right now.

    ``source`` names where the answer came from (``"environment"`` or
    ``"settings"``) and ``invalid`` names the fields of a row that was refused, so
    an operator asking "did my save take effect?" can be answered from the system
    rather than from a guess.
    """

    confidence_direct: int
    confidence_digest: int
    digest_enabled: bool
    digest_hour_utc: int
    no_channel_retry_hours: int
    candidate_change_notifications: bool
    breach_noise_policy: str = "store_only_spam"
    breach_digest_threshold: int = 20
    source: str = "environment"
    invalid: tuple[str, ...] = ()

    @property
    def consistent(self) -> bool:
        """Whether these values describe a channel that can actually route.

        A digest threshold at or above the direct one is the contradiction the
        environment schema refuses at startup; a row can reach the same state one
        field at a time, and nothing else in the delivery path would notice.
        """
        for field, (low, high) in _BOUNDS.items():
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool):
                return False
            if not low <= value <= high:
                return False
        if self.breach_noise_policy not in NOISE_POLICIES:
            return False
        return self.confidence_digest < self.confidence_direct

    def breach_noise_reason(self, attributes: dict | None) -> str | None:
        """Why one incident is stored silently, or ``None`` when it is reported.

        The source's own flags decide, never a keyword in a description: an incident
        the provider itself labels spam or fabricated is not evidence a credential
        was exposed, and a mailbox address appearing in one is not worth a page. The
        flags are read from the row's own ``attributes``, which is where a connector
        puts vendor-specific facts, so this asks the question with the data the
        platform actually stores rather than a second provider-shaped schema.

        An incident whose flags arrived under none of these names is *not* treated
        as spam: silence has to be justified by a positive statement, and a source
        that never sends verification flags would otherwise have every incident it
        reports suppressed.
        """
        facts = attributes if isinstance(attributes, dict) else {}
        if self.breach_noise_policy == "all":
            return None
        if facts.get("is_fabricated") is True:
            return "fabricated"
        if facts.get("is_spam_list") is True:
            return "spam_list"
        if self.breach_noise_policy == "verified_only" and facts.get("is_verified") is not True:
            return "unverified"
        return None

    def digest_is_due(self, moment: datetime) -> bool:
        """Whether this tick is the one the configured UTC hour names.

        The beat schedule ticks every hour and asks this, rather than carrying the
        hour itself: the hour is an operator's value now, and a schedule built at
        worker start could only ever be the one the container was recreated with.
        """
        return moment.hour == self.digest_hour_utc


def policy_from_environment() -> AlertPolicy:
    """The deployment's own answer: the defaults, from the environment."""
    return AlertPolicy(
        confidence_direct=core_settings.ALERT_CONFIDENCE_DIRECT,
        confidence_digest=core_settings.ALERT_CONFIDENCE_DIGEST,
        digest_enabled=core_settings.ALERT_PHISHING_DIGEST_ENABLED,
        digest_hour_utc=core_settings.ALERT_PHISHING_DIGEST_HOUR_UTC,
        no_channel_retry_hours=core_settings.ALERT_NO_CHANNEL_RETRY_HOURS,
        candidate_change_notifications=core_settings.ALERT_CANDIDATE_CHANGE_NOTIFICATIONS,
        breach_noise_policy=core_settings.ALERT_BREACH_NOISE_POLICY,
        breach_digest_threshold=core_settings.ALERT_BREACH_DIGEST_THRESHOLD,
    )


def policy_from_row(row: SystemSettings | None) -> AlertPolicy:
    """The policy in force for this installation, given its settings row.

    ``None`` and an all-NULL row both mean "nobody has decided anything yet", which
    is what the environment answers. A row that states values which do not hold
    together is refused as a whole and recorded in ``invalid``: the fields are one
    decision about one channel, and applying half of a contradictory one would put
    the installation in a state neither source asked for.
    """
    environment = policy_from_environment()
    if row is None:
        return environment
    stated = {
        field: getattr(row, column)
        for column, field in ROW_FIELDS
        if getattr(row, column, None) is not None
    }
    if not stated:
        return environment
    candidate = replace(environment, **stated, source="settings")
    if candidate.consistent:
        return candidate
    refused = tuple(sorted(stated))
    return replace(environment, invalid=refused)


async def resolve_alert_policy(db: AsyncSession) -> AlertPolicy:
    """Read the policy in force from the settings row, falling back to the environment.

    A plain read rather than ``SettingsService.get_singleton``: that helper creates
    the row when it is missing, and a delivery pass or an ingest has no business
    writing a settings row it merely wanted to read.
    """
    row = (
        await db.execute(
            select(SystemSettings).where(SystemSettings.singleton_key == 1)
        )
    ).scalar_one_or_none()
    return policy_from_row(row)
