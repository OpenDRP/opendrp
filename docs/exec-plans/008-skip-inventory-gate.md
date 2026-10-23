# Plan 008 — A skip inventory the page and the tree cannot disagree about

**State:** done — 2026-10-21

**Goal:** make the skip count on
[production-readiness.md](../production-readiness.md#what-a-host-run-skips-and-why)
readable as an inventory rather than a number. Every place in `backend/tests`
that can turn a test into a skip is listed on that page with the reason it fires,
and a test compares the page against the tree in both directions: a new skip site
that nobody described fails the suite, and a row whose site has been deleted or
renamed fails it too.

**Scope:** the page's "What a host run skips, and why" section and one new test
file. No skip is removed, no fixture changes behaviour, and no test starts
requiring a service it did not require before.

**Baseline** (measured on 2026-10-21, this checkout): the page explained sixteen
skips in four causes, named with `file:line` references that break on the next
insertion above them, and nothing compared those four causes to the tree. The
tree actually held **48** skip sites in **seven** kinds when this plan was written,
most of them guards that never fire in a full checkout (a gate test that skips when
the file it reads is not mounted).

## Plan of Work

| File | Change |
|---|---|
| `docs/production-readiness.md` | the cause table gains a "Skip sites" column whose number the gate recomputes, its `file:line` references become `file::name`, and a second table lists every site with its cause |
| `backend/tests/test_skip_inventory_gate.py` | new: discovers skip sites from the AST, parses both tables, and asserts set equality, per-cause counts and that every `tests/...` reference on the page resolves |
| `docs/exec-plans/README.md` | one row for this plan |
| `CHANGELOG.md` | one `Added` entry, because the page now promises something a check enforces |

## Concrete Steps

1. **Discover.** Walk every module in `backend/tests` — `test_*`, `conftest.py`
   and the helpers — with `ast`, collecting `pytest.skip(...)`,
   `pytest.importorskip(...)`, `@pytest.mark.skipif` and `@pytest.mark.skip`. A
   site is named by its file and its nearest enclosing function, or by the file
   alone when the skip is at module level — stable under edits above it, unlike a
   line number.
2. **Document.** Rewrite the section as two tables: seven causes with their site
   counts, and one row per site naming the cause and what makes it fire.
3. **Compare.** Assert the documented site set equals the discovered one, that
   each cause row's count equals the rows that name it, and that every
   `tests/...` reference on the page still resolves to a file and a name.
4. **Guard the application.** Assert `backend/app` contains no skip call, so the
   only skips in the platform are the ones the page describes.

## Validation and Acceptance

- [x] `cd backend && python -m pytest -q tests/test_skip_inventory_gate.py` is
      green against the new page: 5 passed.
- [x] The gate fails in both directions. Measured 2026-10-21 by pointing the
      gate at a mutated copy of the page, so the real one was never edited:
      deleting the row for
      `tests/test_retention_tasks.py::test_rejects_a_symlink_that_leaves_the_store`
      fails the site-set check and the count check; adding a row for a test that
      does not skip fails the stale-row check, the count check and the reference
      check; changing the broker row's count from 1 to 2 fails the count check;
      renaming a cause fails the count check with the inventory row that names it.
- [x] The section's numbers are recomputed rather than copied: the summary's
      "Skip sites" column is `len()` of the inventory rows for that cause, and the
      `Total` row is the size of the whole inventory — editing it from 48 to 49
      fails with `{'Total': (49, 48)}`.
- [x] `python scripts/check_docs_consistency.py` stays green (the new tables have
      consistent cell counts and every reference resolves).
- [x] No behaviour changes: no skip was added or removed and no fixture changed.
      The sixteen are the ones the 2026-10-21 full run reported (`188 passed,
      16 skipped` across the thirteen files that hold them), and the diff touches
      the page, this plan, the changelog and one new test file only.

## Progress and Milestones

- **2026-10-21 — inventory taken.** 48 sites across 7 causes: 1 broker fixture,
  5 PostgreSQL module gates, 3 SQLite row-lock cases, 3 symlink cases,
  31 partial-checkout guards, 3 `git`-absent cases, 1 filesystem-root case, and
  the gate's own page-absent guard. The 31 partial-checkout guards are why the
  page never mentioned them: none fires in a full checkout, so none appeared in
  the sixteen.
- **2026-10-21 — one more site, later the same day.** Plan 009's map gate skips
  when the plan it reads is not mounted, exactly like its siblings, so the
  inventory grew to 49 (`Partial checkout` 33, `Total` 49). The gate caught it on
  the first run, which is the behaviour this plan exists for.
- **2026-10-21 — page rewritten** as cause summary plus per-site inventory, and
  the gate written against it. Four mutations of a copy of the page — a row
  deleted, a row added, a count edited, a cause renamed — each fail the check
  they should, and the real page passes all five tests.
