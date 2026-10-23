"""The nightly pass that keeps a stored confidence honest (AUD-033).

`phishing_score_service.score_pending` rescored every candidate from the signals
it was explained by, and nothing called it outside the tests. The weights are
code, so a release that changes one leaves rows holding a score computed under the
old table — beside a breakdown the API recomputes with today's — and the list's
`?min_confidence=` filter and `confidence` sort keep using the stale number.

This task is the caller. It is deliberately a sweep over the whole list rather
than a targeted repair: a weight change applies to every row, and the pass already
reports how many it actually moved, so a run that changes nothing is a justified
no-op. It writes only `signals`-derived scores, so a repeat is safe; a redelivered
message rescoring twice produces the same numbers.
"""

from __future__ import annotations

import structlog

from app.core.celery_app import async_task, celery_app

log = structlog.get_logger()


@celery_app.task(name="rescore_phishing_candidates", ignore_result=False)
@async_task
async def rescore_phishing_candidates_task() -> dict:
    """Rescore every stored candidate and report how many scores moved."""
    from app.core.database import AsyncSessionLocal
    from app.services.phishing_score_service import score_pending

    async with AsyncSessionLocal() as db:
        moved = await score_pending(db)

    log.info("phishing.candidates_rescored", candidates_moved=moved)
    return {"candidates_moved": moved}
