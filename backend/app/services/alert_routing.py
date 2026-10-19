"""Which channel band one candidate belongs to, read at the moment it is routed.

The decision is a pure function of a candidate, the analyst's verdict and the
resolved alert policy; the policy itself (where its values come from and how a
contradictory settings row is refused) lives in :mod:`app.services.alert_policy`.
Keeping the two apart is what lets the Settings page answer "what would this
threshold do?" without importing the delivery path.
"""

from typing import Literal

from app.services.alert_policy import AlertPolicy, policy_from_environment
from app.services.phishing_score_service import alert_band

#: The bands the phishing budget routes a candidate into (WI-07, W1.4), plus the
#: silence an analyst's rejection asks for (WI-12).
PhishingRoute = Literal["immediate", "digest", "list", "suppressed", "unknown"]


def phishing_alert_route(
    candidate, *, policy: AlertPolicy | None = None
) -> PhishingRoute:
    """How the alert budget routes one candidate, read at the moment it is routed.

    `immediate` is the score the audit says is worth interrupting someone for;
    `digest` is the band that is reported once a day instead; `list` is the rest,
    which the list shows and the channel does not mention. The thresholds are the
    resolved alert policy (`app.services.alert_policy`) — the operator's saved values
    where they exist, the deployment's environment where they do not — and they are
    read on every call, so an operator raising one sees the next scan respect it
    rather than the next release. ``policy`` is passed in by a caller that resolved it
    once for a whole pass; without one the environment answers.

    Turning the digest off is not a special case in this function's caller: the
    middle band becomes `list` here, and the budget turns binary — which is exactly
    what an installation that wants only its high-confidence candidates in the
    inbox has asked for.

    `unknown` is the answer for a candidate the caller cannot read (deleted between
    the event and the drain). It is not the same as `list`: the caller has no score
    to suppress a delivery with, so it lets the event through rather than deciding
    a fact it cannot see.

    The analyst's verdict is read before the score, because the two answer different
    questions and only one of them is a guess. ``confirmed`` is somebody having looked
    at the candidate and saying it matters — routed `immediate` however low the score
    is, which is what makes a confirmation a decision rather than a note, and what
    re-alerts when the thing changes afterwards. ``rejected`` is a decision *not* to
    be told about it: `suppressed`, not `list`, because `list` is a budget judgement
    that the daily digest still reports on, and re-reporting a candidate somebody has
    already judged would train an operator to ignore the channel. A verdict of nothing
    (`None`) is the ordinary case and falls through to the score.
    """
    if candidate is None:
        return "unknown"
    if candidate.verdict == "rejected":
        return "suppressed"
    if candidate.verdict == "confirmed":
        return "immediate"
    active = policy if policy is not None else policy_from_environment()
    band = alert_band(int(candidate.confidence or 0), policy=active)
    if band == "direct":
        return "immediate"
    if band == "digest":
        return "digest" if active.digest_enabled else "list"
    return "list"
