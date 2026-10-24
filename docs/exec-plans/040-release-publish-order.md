# Plan 040 — publish only what the scan approved

**State:** done — 2026-10-24: release tags are copied from the scanned digest, and a gate
keeps the order

## Goal

The first v0.2.1 release run built the wrong tree and pushed `<version>` and `latest`
before Trivy read anything. The scan then failed — so the gate worked as a check and not
as a gate: the images it rejected stayed pullable by `latest` until the release was
re-run by hand, and an operator who deployed in between got exactly the artifact the
pipeline had already refused. Nothing in CI could see the ordering, because the ordering
was the bug.

The release must create the tags a release is known by only after the scan has approved
the bytes they point at.

Decisions:

1. **The mechanism is a candidate tag plus a digest copy, not a local build.** The
   obvious shape — `load: true`, scan the local image, `docker push` — was measured and
   rejected: the docker exporter cannot carry SBOM and provenance attestations, so
   BuildKit drops them silently, and `docs/production-readiness.md` promises both. A
   registry only accepts a push under a tag, so the workflow pushes one tag nothing
   documents (`<version>-candidate`), scans that build's **digest**, and promotes the
   digest with `docker buildx imagetools create`. Verified against a local registry: the
   promoted tags carry the candidate's index digest exactly, attestation manifest
   included, and no layer is uploaded again.
2. **The scan reads a digest, not a tag.** A tag can move between the read and the push;
   a digest cannot, and it is the value the promotion copies — so "what was scanned" and
   "what is published" are the same bytes by construction rather than by convention.
3. **The leftover candidate is accepted and named.** A failed run leaves
   `<version>-candidate` in GHCR (no registry API deletes a tag alone). No Compose file
   resolves it, no page documents it, and its name states what it is; that is a smaller
   price than losing the attestations or publishing under a tag an operator deploys.
4. **The order is a checked property.** `scripts/check_release_publish_order.py` reads
   the `build-and-push` job and fails on a build that pushes a release tag, a `docker
   push` or a tag promotion before the scan, a second build, and a scan that reads a tag.

## Plan of Work

| File | Change |
|---|---|
| `.github/workflows/release.yml` | one build that pushes `<version>-candidate`, the scan pinned to `steps.build.outputs.digest`, then `docker buildx imagetools create` for `<version>` and `latest`; header comment states the five steps and why the order exists |
| `scripts/check_release_publish_order.py` | the gate: candidate-only build tags, digest scan, promotion last, no stray `docker push` |
| `backend/tests/test_release_publish_order_gate.py` | the shipped workflow passes; the v0.2.1 order and eight other shapes are reported |
| `.github/workflows/ci.yml` | the gate runs in the `release-image-coverage` job, beside the ref gate |
| `docs/deployment.md` | the release procedure: scan, then tag, and what a failed run leaves behind |
| `docs/production-readiness.md` | a gate row for the ordering, and the release row in the security table states it |
| `README.md` | the `release-image-coverage` job's description names the ordering check |
| `CHANGELOG.md` | the fix, under Unreleased |

## Concrete Steps

1. **Measure the mechanism before writing the gate.** Build a scratch image with
   `--sbom=true --provenance=mode=max` into a local `registry:2`, promote its digest with
   `imagetools create`, and compare the index: same digest under all three tags, the
   `attestation-manifest` entry present in the promoted index.
   *Acceptance:* the promotion copies the manifest — otherwise the design would silently
   drop the attestations and the workflow would need a rebuild instead.
2. **Reorder the workflow.** Candidate build with `id: build`, scan
   `image@${{ steps.build.outputs.digest }}`, promote `${IMAGE}@${DIGEST}` to
   `${IMAGE}:${VERSION}` and `${IMAGE}:latest`. The `meta` step that computed the two
   release tags goes away.
3. **Write the gate red first.** Run it against `HEAD`'s workflow: three failures — no
   promotion, a build pushing `${{ steps.meta.outputs.tags }}`, and a scan reading a tag.
4. **Wire it into CI** beside `check_release_refs.py`, in the job that already reads the
   release workflow.
5. **Update the pages** that describe a release, so the procedure an operator follows and
   the workflow that runs agree.

## Validation and Acceptance

- [x] The gate fails on the v0.2.1 workflow (`git show HEAD:.github/workflows/release.yml`)
      with the three failures above, and passes on the new one: `the release tags are
      created from the scanned digest`.
- [x] `test_release_publish_order_gate.py` — 13 passed: the shipped file, and twelve
      shapes it rejects; `test_release_refs_gate.py` and `test_release_image_matrix.py`
      stay green (36 passed together).
- [x] The promotion was measured, not assumed: against `registry:2` on
      `localhost:5001`, `demo:0.0.0`, `demo:latest` and `demo:0.0.0-candidate` all report
      index digest `sha256:237ef31a…`, and the promoted index holds the
      `unknown/unknown` attestation manifest next to the `linux/amd64` image.
- [ ] CI green on the pull request (`release-image-coverage` runs the new gate).
- [ ] The next release run is the live proof: images appear under
      `<version>-candidate` first, and `<version>`/`latest` only after the scan step.
- [x] The documentation gates and `test_github_docs_claims.py` pass with the new rows.

## Progress and Milestones

- **2026-10-24 — opened.** Raised as the remaining risk after the ref incident: fixing
  which tree is built does not fix that the failing step ran after the publication.
- **2026-10-24 — mechanism measured.** Digest promotion keeps the attestations; the
  `load: true` shape cannot, so the plan does not take it.
- **2026-10-24 — closed in code.** Workflow reordered, gate and tests added, pages
  updated. The live proof is the next tagged release.
