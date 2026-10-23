# Batch 01 — Authentication and the request boundary

**State:** done — `auth.py` 94.9%, `deps.py` 99.5%, floors 91/96; closing run green
(2026-10-20: 3 089 passed, 14 skipped, critical-coverage gate OK).

**Scope:** every branch behind a session: password login, refresh rotation, CSRF,
MFA, lockout, and the dependency layer that decides who the caller is.

**Baseline:** the `backend` job of the CI run on `main` (2026-10-19): 2 918 passed,
8 skipped, `app/` at 90.65% (14 300 statements, 1 337 missed).

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/api/v1/routers/auth.py` | 533 | 78 | 85.4% |
| `app/api/deps.py` | 204 | 31 | 84.8% |

**After the batch (2026-10-19):** 81 of the 109 baseline misses are now executed;
28 remain. Both modules clear the batch's 92% criterion, and the per-module floors
in `backend/scripts/check_critical_coverage.py` are raised to the measured value
minus three points (rounded down to the whole percent the readiness table prints):
`auth.py` gains 91, `deps.py` moves from 75 to 96.

| Module | Statements | Missed | Covered |
|---|---|---|---|
| `app/api/v1/routers/auth.py` | 533 | 27 | 94.9% |
| `app/api/deps.py` | 204 | 1 | 99.5% |

**Baseline misses**

- `auth.py`: 77-79, 133-134, 143-144, 222, 238-239, 248-252, 309-310, 344,
  383-384, 404-405, 459-461, 540-542, 565, 570-571, 647, 661, 732-748, 812, 837,
  907-910, 932, 944-945, 975-976, 1001-1003, 1047, 1072-1074, 1093, 1113, 1115,
  1123, 1125-1130, 1138, 1179-1181, 1210, 1220, 1256-1258
- `deps.py`: 126-127, 214, 226, 340, 348-352, 357-359, 379-380, 388, 391-397,
  401, 404-405, 426-428, 558-559

**First move**

```bash
cd backend
COVERAGE_CORE=sysmon python -m pytest -q --cov=app.api.v1.routers.auth --cov=app.api.deps --cov-report=term-missing --cov-report=json:/tmp/batch01.json
python scripts/coverage_gaps.py /tmp/batch01.json --total
```

**Work items**

Name each range above as a behaviour before writing its test; a range that cannot
be named does not belong to this batch.

- [x] Session invalidation, deactivated-account half: a refresh token for an
      inactive account is refused and audited (`tests/test_auth_defense_in_depth.py`),
      and an access token for one is refused by `get_current_user`.
- [x] Session invalidation, password-change half: `tests/test_auth_edges.py`
      (`TestPasswordChangeInvalidation`) signs in, changes the password, and
      replays the pre-change refresh token — which is refused with 401. The test
      was proven to fail when the `revoke_refresh_families` call was removed, so
      it pins the revocation rather than the endpoint's shape.
- [x] MFA: enrollment, a wrong code, and the recovery path an administrator takes.
      Enrolment edges and recovery-code rotation are in `tests/test_mfa.py`;
      setup/enable/disable refusals are in `tests/test_auth_edges.py`.
- [x] Lockout and rate-limit answers: the refusal is the same shape for an unknown
      address as for a wrong password, and the audit row says which happened
      (`tests/test_login_enumeration.py`, `tests/test_auth_edges.py`,
      `TestMfaFailureBudget`).
- [x] `deps.py`: the dependency branches that decide 401 versus 403
      (`tests/test_security_boundaries.py`, `tests/test_deps_boundaries.py`, 22
      cases). The item this batch was written with also named "the API-key path a
      connector uses instead of a session"; no such path exists in `deps.py` —
      connectors authenticate through `connector_credentials` — so it is recorded
      as a scope correction below rather than tested here.
- [x] Every audit action this batch executes is already allowlisted;
      `tests/test_audit_service_unit.py` fails on an emitted action that is not.

**Done when**

- [x] both modules are at or above 92%, and the floor in
      `backend/scripts/check_critical_coverage.py` is raised to the measured value
      minus three points — `auth.py` gains 91, `deps.py` 75 → 96, mirrored in the
      readiness page's gated-boundaries table;
- [x] the auth suites and the full backend suite are green — the auth suites are
      (`test_auth`, `test_mfa`, `test_auth_edges`, `test_deps_boundaries`: 98
      passed); the full suite closed on 3 089 passed, 14 skipped;
- [x] this file's progress log names the behaviours that turned out unreachable on
      purpose, if any (below).

**Progress log**

| Date | Change | Measured |
|---|---|---|
| 2026-10-19 | batch written from the CI baseline | `auth.py` 85.4%, `deps.py` 84.8% |
| 2026-10-19 | `deps.py`: 19 tests in `tests/test_deps_boundaries.py` — forwarded-address parsing (quoted, bracketed, `host:port`, malformed), a `TRUSTED_PROXY_IPS` typo, an unreadable configuration, a peer whose socket is gone, a failed audit write during a refusal, an undecodable token, `_denied_target` with no matching parameter, and the policy-factor refusal | every branch the batch named is executed; `_normalize_ip` refuses the malformed forms it used to pass through a fragment of |
| 2026-10-19 | `auth.py`: 8 tests in `tests/test_mfa.py` (`TestEnrolmentEdges`, `TestRecoveryCodeRotationEdges`) — enabling twice, confirming without a code, a wrong password at the second step (with its audit row), a lost pending secret, rotation without a factor, rotation with a wrong password (audited), rotation replaying the enrolment code, and a successful rotation that records its count | covers `auth.py` 732-748 and 1112-1134; the first step's own pairs (`setup` while a factor is active, `setup` with a wrong password) were already pinned |
| 2026-10-19 | `auth.py`: 23 tests in `tests/test_auth_edges.py` — lockout predicates on naive timestamps, a Redis outage in both best-effort helpers, the session-identity fallback and its two refusals, an undecryptable pending secret, login without a body, a locked factor at login, `revoke-others` with no identifiable session, a cookie logout without the CSRF header, a refresh without a family, the setup/QR/enable/disable refusals, revoking one session (with its audit row), a logout whose token cannot be parsed, and a refresh whose rotation cannot be committed (`503`, never a token that storage did not accept) | 51 of the module's 78 baseline misses are now executed |
| 2026-10-19 | closing measurement and ratchet: the baseline's covered lines united with the two suites' runs (the method below), then `auth.py` gated at 91 and `deps.py` raised 75 → 96 in the gate and the readiness page | `auth.py` 506/533 = **94.9%** (27 missed), `deps.py` 203/204 = **99.5%** (1 missed); 81 of 109 closed |
| 2026-10-19 | one behavioural test in `tests/test_auth_edges.py` (`TestPasswordChangeInvalidation`): sign in, change the password, replay the refresh token issued before it, expect 401 — the family-revoked branch was already executed by the reuse test, so the number does not move, but the behaviour the batch was written for is now pinned; removing the `revoke_refresh_families` call makes it fail | unchanged: `auth.py` 94.9%, `deps.py` 99.5%, 81/109 |

**How the after-batch number was measured**

The baseline report records which lines the full suite executed at the commit the
batch started from. The batch changed no file in `app/api/`, so its new number is
exactly the baseline's executed lines united with the lines its own runs execute.
Running the whole suite again to add two files would cost hours on this machine
and could not produce a different answer for unchanged sources.

A subset run on its own is not the module's number: `deps.py` is resolved by every
authenticated route, so its 22 tests alone show 64%, and `auth.py` is exercised by
ten suites, not the three the earlier log used. Raw per-suite percentages therefore
understate both and are not used as floors.

**Deliberate gaps**

- `deps.py:226` (`if not user_id` after `uuid.UUID(...)`) cannot execute:
  `uuid.UUID` never returns a falsy value, so the branch is unreachable by
  construction. Removing it is a code change, not a test.
- `auth.py:238-239` (form-encoded login): `form_data` is bound to
  `Depends(lambda: None)`, so the branch cannot execute. Recorded rather than
  tested; whether the dependency should be removed is a code decision.
- `auth.py:837` (`with_for_update()`): PostgreSQL-only, covered by the integration
  suite (`test_production_integrations.py`) rather than the unit run.
- `auth.py:1138`: a second lock check after the password was verified. Only a
  concurrent request can lock the account between the two checks, and constructing
  that race would mock the unit under test; it stays as a defensive duplicate.
- The commit/rollback durability pairs (`auth.py` 309-310, 383-384, 404-405,
  459-461, 540-542, 1072-1074, 1179-1181, 1256-1258): reaching them requires
  replacing the session's `commit` with a failing mock, which is the thing under
  test. The plan's rule says record these, not mock them. The refresh pair is the
  exception and is tested behaviourally (`503`), because the route's contract
  distinguishes "token not issued" from "token issued".
- `auth.py:975-976`: a failed audit write during logout is swallowed on purpose —
  ending the browser session must not fail because the trail could not be written.
  Testing it would mock the audit writer.

**Closing run**

- `COVERAGE_CORE=sysmon python -m pytest -q --cov=app` on 2026-10-20: 3 089 passed,
  14 skipped; the critical-coverage gate OK on that report, mypy 0 errors, version
  gate 0.2.1. This file and the index moved to `done`.
