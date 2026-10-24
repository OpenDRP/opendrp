# Plan 041 — the tag is the release

**State:** done — 2026-10-24: `v0.1.0` … `v0.2.1` branches deleted, a gate keeps them
from returning

## Goal

Fixing the release workflow's refs removed the name collision from the pipeline but left
the condition that produced it: a `vX.Y.Z` branch could exist beside the tag of the same
name, with no invariant but prose saying they should match. On 2026-10-24 they did not —
the branch still carried the `certifi` the tag had replaced, the release built the
branch, and only the image scan noticed.

The decision taken for this plan: **stop using version branches.** The tag is the
release. A branch with the same name is a second ref with a different lifetime, and it
carried nothing the tag did not — every one of them was a copy of a released state kept
for a `git clone --branch` that no procedure in this repository or its pages performs.

Decisions:

1. **Delete, do not reconcile.** A gate that fails when the branch and the tag disagree
   keeps the convention alive: it needs a person to reset the branch on every release,
   and it cannot tell a stale branch from a deliberately divergent one. Deleting the
   refs removes the failure mode instead of monitoring it.
2. **The workflow's qualification stays.** `refs/tags/<tag>` in every checkout is what
   makes a name unambiguous for whoever types one, and it holds in the window between a
   branch being recreated and CI noticing. Removing it because "there are no branches
   now" would make the pipeline depend on a policy held somewhere else.
3. **Absence is checked, not assumed.** `scripts/check_release_branches.py` reads the
   remote's branches and fails, naming the `git push origin --delete` that fixes it. A
   `git push origin v0.3.0` typed where a tag push was meant is now a red build rather
   than a second ref the next release has to work around.
4. **History was verified before deletion, not after.** For each branch the tip was
   compared with its tag and with `main`: `v0.1.0` and `v0.2.0` were one commit past
   their tags and fully contained in `main`; `v0.2.1` was identical to its tag; `v0.1.1`
   and `v0.1.2` carried six commits whose *content* is in `main` under the rebuilt
   history (the pytest 9 move, the react-router/vite/vitest upgrade, the
   `requirements*.txt` consolidation, the 2026-09-28 audit report — each of those files
   and states is present on `main` today), so nothing was lost but object identity.

## Plan of Work

| File | Change |
|---|---|
| GitHub (refs) | `v0.1.0`, `v0.1.1`, `v0.1.2`, `v0.2.0`, `v0.2.1` deleted, remote and local; the tags remain |
| `scripts/check_release_branches.py` | the gate: parse `git ls-remote --heads`, fail on `^v\d+\.\d+\.\d+$`, print the delete command |
| `backend/tests/test_release_branches_gate.py` | ten tests over saved listings, plus "CI runs the gate" |
| `.github/workflows/ci.yml` | the gate runs in `release-image-coverage`, beside the ref gate; that gate's comment states the branches are gone |
| `.github/workflows/release.yml` | the qualified-checkout comment no longer describes a branch that exists |
| `scripts/check_release_refs.py` | the docstring says the branches were deleted and why the gate stays |
| `docs/deployment.md` | "The tag is the only ref": the history, the two gates, and the commands that cut a release |
| `docs/production-readiness.md` | a gate row, and the skip inventory gains the new module |
| `CHANGELOG.md` | the change, under Unreleased |

## Concrete Steps

1. **Verify the refs before touching them.** Compare each branch tip with its tag commit
   and count commits reachable only from the branch; confirm the divergent content is on
   `main` under the rebuilt history.
2. **Delete the branches.** `git push origin --delete refs/heads/vX.Y.Z` — the fully
   qualified refspec, because the bare name is ambiguous once the tag of that name
   exists, which is the whole subject of this plan. Local branches follow.
3. **Build and test.** Write `scripts/check_release_branches.py` and
   `backend/tests/test_release_branches_gate.py` together; drive it against the real
   remote (three branches, none a version) and against a listing with `v0.2.1` appended
   (one failure, exit 1).
4. **Wire it in and update the prose** that describes version branches as an existing
   convention.

## Validation and Acceptance

- [x] After deletion `git ls-remote --heads origin` lists `main`, `ci/dev-deps-and-tag-trigger`
      and `ci/scan-before-publish` — no version branch; `git tag` still lists `v0.1.0`
      … `v0.2.1`.
- [x] `python scripts/check_release_branches.py` — `no version branch exists — 3 branch(es)
      checked`; with a `refs/heads/v0.2.1` line appended to a saved listing it exits 1 and
      prints `git push origin --delete refs/heads/v0.2.1`.
- [x] `test_release_branches_gate.py` — 10 passed: ordinary branches pass, a version
      branch is reported, `v0.2`, `v0.2.1-rc1`, `release/v0.2.1` and tag refs are not
      version branches, an unreadable listing is exit 2, and CI runs the gate.
- [ ] CI green on the pull request.
- [x] The skip inventory, docs and CI gates pass with the new module and row.

## Progress and Milestones

- **2026-10-24 — opened.** The remaining half of the v0.2.1 incident: the workflow was
  fixed, the refs were not.
- **2026-10-24 — branches deleted.** Remote and local; tags untouched.
- **2026-10-24 — closed in code.** Gate, tests and pages; the live proof is the next
  release cut from a tag alone.
