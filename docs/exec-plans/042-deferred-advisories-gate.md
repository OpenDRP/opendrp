# Plan 042 — the deferred-advisory list is recomputed, not remembered

**State:** done — 2026-10-25: the gate, its tests, the audit JSON the `security` job
now writes, and the pages that describe them

## Goal

`README.md` carried a section called "Known deferred findings", and on 2026-10-25 it
said:

> The Vite/esbuild/vitest toolchain advisories are devDependencies; every fix is a
> major bump. CI prints them on each run so the list stays visible.

Both halves were wrong, and neither had been wrong for long. The three advisories it
named (`source-map-js` 1.2.1, two `@vitest/mocker` 4.1.11) were lifted by a patch and
a minor in #42 — `source-map-js` 1.2.2 and `vitest` 4.1.12 — so the paragraph named
packages that were already clear and promised a migration nobody had to perform. A full
`npm audit` over the lockfile reports nothing, which the paragraph could not have known
because nothing recomputed it.

The reason it could age invisibly is structural, and it is the defect this plan
carries: the exemption the paragraph described was the one part of the software supply
chain no gate read. `npm audit` over the whole tree ran with `continue-on-error`, so the
output was a log line nobody compared with the prose, and the paragraph could stay
plausible while describing a different tree than the one CI built. That is the audit's
"A number in the prose that nothing recomputes" family (AUD-001, 075, 079, 083), applied
to the exemption list itself.

Decision: **the list is compared with the audits on every run.** Two directions,
because they are two different failures:

1. an audit reports an advisory the paragraph does not name — the paragraph is
   incomplete, and this is the direction that matters for a new CVE;
2. the paragraph names an advisory no audit reports — the paragraph is stale, and this
   is the direction that was true on 2026-10-25.

## Plan of Work

| File | Change |
|---|---|
| `scripts/check_deferred_advisories.py` | the gate: read the README section, read the audit JSON, compare the two sets, print a paste-ready row for a missing advisory |
| `backend/tests/test_deferred_advisories_gate.py` | 20 tests over fixtures: both directions, the empty-set sentence, both table-format errors, npm scope and PEP 503 name normalisation, unreadable and mis-shaped inputs, the shipped README, and "CI runs it" |
| `.github/workflows/ci.yml` | the `security` job's three audits write JSON (`pip-audit -f json -o`, `npm audit --json`), and a new step runs the gate over every file; the report-only step's comment no longer claims the dev advisories need a major bump |
| `README.md` | the deferred section says the gate is what recomputes it, and names the table format a real deferral would use |
| `docs/production-readiness.md` | a gate row, and the skip inventory gains the new test module (counts 38/55 → 39/56) |
| `CHANGELOG.md` | the gate, under Unreleased |

## Concrete Steps

1. **Write the gate and its tests together.** The script's `deferred()` reads the
   section from its opener line — the empty set is declared on that line, so reading
   only the lines below it misses the sentence — and the table, when one exists, by its
   header. `read_audit()` classifies a file by shape: an object with a `vulnerabilities`
   map is `npm audit --json`, an object with a `dependencies` list is `pip-audit -f json`
   as 2.x writes it, and a bare list of `{name, version, vulns}` is the 0.x shape of the
   same report.
2. **Compare both ways in one pass.** `compare()` prints, for a missing advisory, the
   row that would fix the paragraph, and for a stale one, the instruction to drop it.
   A disagreement is exit 1; a malformed README section or an unreadable report is exit
   2, because "the section says neither `none` nor a table" must not read as agreement.
3. **Make the audits produce the files, without losing the log.** `pip-audit` writes
   its JSON with `-o`, which moves the report out of the log, so both audit steps print
   the file and keep the exit status: a failing audit still fails the job and still
   shows which advisory did it. The connector loop stops at the first failing lock, as
   the `set -euo pipefail` version did.
4. **Run the gate on the real tree.** With the real README (empty set) and the real
   `npm audit --json` output (empty `vulnerabilities`), the gate prints
   `0 deferred advisories, 0 reported — they agree`; with a pip report naming `certifi`
   it exits 1 and prints the row to add.
5. **Update the prose that describes the audits**, including the stale rationale in the
   report-only step's comment — the same sentence the README carried, one file over.

## Validation and Acceptance

- [x] `python scripts/check_deferred_advisories.py README.md /tmp/audit-*.json` on the
      real tree: exit 0, `0 deferred advisories, 0 reported by 2 audit report(s)`.
- [x] The same command with a report naming an unlisted package: exit 1, the advisory
      named with the row to paste; with a row no audit reports: exit 1, "drop the row";
      with a section that is neither: exit 2.
- [x] `test_deferred_advisories_gate.py` — 20 passed.
- [x] Every `run:` block the `security` job's audits and gate use passes `bash -n`, and
      the connector loop was driven with a stubbed `pip-audit`: six reports written,
      JSON printed, exit 0 when clean and 1 at the first failing lock.
- [x] The skip inventory, docs and repo gates pass with the new module and row.
- [x] The first CI run failed for a reason worth keeping: `pip-audit` 2.10.1 writes
      `{"dependencies": [...], "fixes": []}` and the gate read the 0.x bare list, so the
      step exited 2. The gate now reads both, with a test per shape; driven against the
      envelope CI actually wrote, a clean report agrees and a `certifi` advisory exits 1
      with the row to paste.
- [x] CI green on the pull request (#45): all twelve checks `success` on run
      `40159524599`, `security` (which runs the gate) in 1m14s and `backend` the long one;
      squash-merged as `d1ccf20`.

## Progress and Milestones

- **2026-10-25 — merged.** PR #45 squash-merged as `d1ccf20`; the gate now runs in the
  `security` job on every push and pull request, and `README.md` says what recomputes it.
- **2026-10-25 — opened.** The README paragraph was rewritten to say "none", and the
  question it left behind is this plan: what stops the next one from ageing the same way.
- **2026-10-25 — closed in code.** The gate, the JSON the audits write, the tests and the
  pages. What it does not cover is written down in the script and here: the Python
  development requirements (`backend/requirements-dev.txt`) have no audit step, so an
  advisory there is in no file the gate reads.
- **2026-10-25 — the first run taught the second shape.** `security` failed on the gate
  with `not an npm audit --json report`: `pip-audit` 2.10.1 had written a
  `{"dependencies": ...}` envelope, and the gate had been written against the bare list
  that 0.x produced — a shape nothing in this repository pinned, because the step runs
  `pip install --upgrade pip-audit`. Reading both shapes, and testing each, is the fix.
