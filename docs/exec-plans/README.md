# Refactoring plans (ExecPlans)

Each plan here is one measured step of a refactoring that is too large to land at
once. A plan states the goal, the files it will touch, the steps in order and the
acceptance criteria, and it keeps its own progress log — so the next session
resumes from the document instead of re-reading the code, and a reviewer can tell
what a commit was supposed to change from what it actually changed.

They are working records, not operator guidance. The maintained pages are under
[docs/](../) and the entry point is [README.md](../../README.md#documentation).

| Plan | State | What it covers |
|---|---|---|
| [001-alert-service-message-layer.md](001-alert-service-message-layer.md) | done | Lifts the message vocabulary, the `Notification` shape and the routing decision out of `alert_service.py` into pure modules. |
| [002-alert-transport-and-facts.md](002-alert-transport-and-facts.md) | done | Moves the delivery error taxonomy, the retry policy and the SMTP slot pool into `alert_transport.py`, and the stored-fact readers into `alert_facts.py`. |
| [003-connector-provider-runtime.md](003-connector-provider-runtime.md) | in progress | Puts pacing, quota reservation, the retry loop, `Retry-After` parsing and a bounded response read into one provider client shared by every connector, and closes the unbounded-body gap in two of them. |

## Writing the next one

A plan that does not name its acceptance criteria is a wish. Every plan here uses
the same sections: Goal, Plan of Work, Concrete Steps, Validation and Acceptance —
plus a Progress and Milestones section that is updated as the work lands, never at
the end.
