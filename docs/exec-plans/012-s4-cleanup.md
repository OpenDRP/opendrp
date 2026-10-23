# Plan 012 — the two threads the audit left open

**State:** done — both threads closed 2026-10-22

## Goal

Plan 009 closed with two threads it did not take, both S4 and neither changing a
guarantee an operator relies on. This plan takes them and leaves the register
otherwise untouched.

1. **The compact Telegram renderer is dead code.** `alert_message.telegram_text`
   has no production caller: the live channel sends `alert_content.telegram_parts`,
   which prints every field of every finding across as many messages as the budget
   needs. `telegram_text` — with `telegram_finding_line`, `TELEGRAM_DETAIL_FIELDS`,
   `TELEGRAM_DETAIL_LIMIT`, `escaped` and `OMISSION_NOTE_RESERVE`, which nothing else
   uses — is a second renderer nobody wires, and AUD-016's fix landed inside it. A
   reader who finds it cannot tell whether the platform sends it. Deleting it is the
   repair: the facts it was dropped for are printed by the live path, which
   `tests/test_breach_alert_content.py` already pins.

2. **The certificate row names one subject.** AUD-037 made the sighting carry every
   hostname a certificate was reported for (`signals.subjects`, exposed as
   `subjects` on the triage payload) and made R3 evaluate each of them. The review
   list still prints `sighting.subject` alone, so a reviewer looking at a shared
   address cannot see the neighbour's name the rules did act on — and cannot judge
   whether the deployment is expected for it.

The rule from the audit still applies: nothing here is a finding. The register gains
no row, and the two rows these threads touch (`AUD-016`, `AUD-037`) stay `fixed` —
the first now cites the test that pins the live channel instead of the test of a
renderer that no longer exists.

## Plan of Work

| File | Change |
|---|---|
| `backend/app/services/alert_message.py` | delete `telegram_text`, `telegram_finding_line`, `TELEGRAM_DETAIL_FIELDS`, `TELEGRAM_DETAIL_LIMIT`, `escaped`, `OMISSION_NOTE_RESERVE` and the imports only they used |
| `backend/app/services/alert_service.py` | the send loop's variable is named `part`, not after the deleted function |
| `backend/tests/test_alert_message_layer.py` | delete the eight tests that assert the deleted renderer, and the two names that import it; the digest wording keeps its assertion through `plain_text` and `telegram_parts` |
| `frontend/src/components/CertificateTriage.tsx` | print every hostname a sighting was reported for, with the single `subject` as the fallback for a payload that predates the set |
| `frontend/src/components/CertificateTriage.test.tsx` | a sighting reported for two names shows both; a sighting with only `subject` still shows it |
| `docs/audit-findings.md` | `AUD-016`'s fix cell names the test that pins the live Telegram path, and says the compact renderer it described was deleted rather than kept |
| `docs/exec-plans/009-staged-audit.md` | S27's surface gains `check_api_types.py`, the gate AUD-060 added after the split — the map gate found it assigned to no step |
| `docs/exec-plans/README.md` | one row for this plan |
| `CHANGELOG.md` | the removal under Removed, the certificate row under Changed |

## Concrete Steps

1. **Delete the compact renderer.** Remove the six names above from
   `alert_message.py` together with the `html` and `settings` imports nothing else
   in the module uses. The module keeps its 97% floor: the deleted functions were
   covered by the tests that go with them. *Acceptance:* no module, test or document
   under `backend/` or `connectors/` imports `telegram_text` from
   `app.services.alert_message`; the alert-layer, content and delivery collections
   stay green; `python scripts/check_api_types.py` and the critical-coverage gate are
   unaffected.
2. **Print every subject.** A helper reads `subjects` when the payload carries it
   and falls back to `subject`, de-duplicated, and the sighting row joins the names
   instead of printing one. *Acceptance:* the two-name fixture renders both names,
   the single-name fixture still renders, and every existing test in the file passes
   with `getAllByText`, since a name now appears once per sighting that reported it.

## Validation and Acceptance

- [x] `backend/tests/test_alert_message_layer.py`, `test_alert_message_format.py`,
      `test_breach_alert_content.py`, `test_phishing_alert_content.py` and
      `test_alert_service.py` pass, and `ruff check` is clean on the touched module.
      (91 passed; the coverage run below reports the module at 107 statements, 100%.)
- [x] `frontend/src/components/CertificateTriage.test.tsx` passes and `tsc -b` is
      clean — the payload field the component reads is the one the backend sends.
- [x] The gates over the register, the documentation and the skip inventory stay
      green (89 passed); `AUD-016` still resolves a test file that exists, and that
      file pins the live channel rather than the deleted one.
- [x] Nothing outside the files named in Plan of Work changes behaviour: no route,
      no model, no migration, no setting.

## Progress and Milestones

- **2026-10-22 — opened.** Reading the two threads against the tree settled both
  questions the handoff left open. `telegram_text` has no caller outside its own
  tests (`alert_service.py:706` and `alert_delivery_service.py:705` both send
  `telegram_parts`), and the payload the triage reads already carries `subjects`
  (`tls_identity_service.py:1000`, typed at `frontend/src/types/api.ts:69`) — so the
  first thread is a deletion and the second is a render, and neither needs a new
  field or a migration.
- **2026-10-22 — the compact renderer is gone (96 lines of module, 110 of tests).**
  `telegram_text`, `telegram_finding_line`, `TELEGRAM_DETAIL_FIELDS`,
  `TELEGRAM_DETAIL_LIMIT`, `escaped` and `OMISSION_NOTE_RESERVE` are deleted with the
  eight tests that asserted them, and the `html`/`settings` imports nothing else used.
  The digest-wording test keeps its subject-by-subject comparison through
  `plain_text` and `telegram_parts`, which is where the wording is actually sent.
  `AUD-016` now cites the live channel's pinning test
  (`test_breach_alert_content.py::TestBreachMessageContent::test_incomplete_metadata_is_named_on_the_message`)
  and says the renderer it described was deleted rather than kept.
  The live send loop's local was still called `telegram_text`, naming the function
  that no longer exists; it is `part` now.
  Two things the change surfaced in passing, both fixed here: the map gate found
  `backend/scripts/check_api_types.py` assigned to no step — AUD-060 added it after
  the plan's split — so it joins S27's surface, and the module is 107 statements at
  100% coverage on the pure message and digest suites, well above its 97% floor.
- **2026-10-22 — the review row prints every name.** `subjectNames` reads
  `subjects` when the payload carries it, de-duplicates, and falls back to the
  single `subject` for evidence recorded before the set existed; `SightingSubjects`
  renders the names joined in one `font-mono` span where the single name used to be.
  The new test was shown red against the old line — `Unable to find an element with
  the text: mail.example.com · portal.example.com` — and green with the change.
  *Verified:* the alert collections above 91 passed (8 min); the coverage run over
  `test_alert_message_layer`, `test_alert_message_format`, `test_breach_digest` and
  `test_phishing_digest` 47 passed with the module at 100%; the five register, map,
  documentation, numbers and skip gates 89 passed (7 min); `CertificateTriage` 10
  passed; `tsc -b` clean; `ruff check` clean on both touched backend files. The full
  backend suite was not run in one process — it takes over an hour on this host, and
  no production module outside `alert_message.py` changed.
