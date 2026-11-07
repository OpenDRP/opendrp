# Plan 043 — the release runs the images it publishes

**State:** in progress — the job is written; the first tagged run is what proves it

## Goal

Every claim the release workflow makes up to now is a claim about *provenance*:
the images were built from the tagged tree, they carry SBOM and provenance
attestations, the scan approved the digest the release tags copy. None of them is
a claim that the images **start**.

v0.2.3 was checked by hand on 2026-11-07, and the check was worth doing because it
could have failed: a workstation pulled all eight published images, confirmed the
backend digest was exactly the promoted one
(`sha256:d64d1f5da493d320a72663b29d0e20d511551cd3472c50a3e8f3ada2a21322bd`), raised
the stack with `docker compose up -d --wait` and got `/api/v1/health` answering
`{"status":"ok","version":"0.2.3"}` and `/api/v1/ready` answering
`{"status":"ready"}` with `database`, `redis` and `audit` all `ok`. That
verification exists in a chat log and nowhere in the repository, and it was
performed by remembering to perform it — which is the same shape as the deferred
advisories paragraph that plan 042 replaced, one layer over: a claim about a
release that no run recomputes.

Decision: **the release workflow starts the images it publishes, before the notes
are published.**

## Plan of Work

| File | Change |
|---|---|
| `.github/workflows/release.yml` | a `smoke-published-images` job after `build-and-push`: pull every release image, refuse one without a registry digest, raise the stack with `--wait`, assert the health version, readiness and the SPA; `release` now needs it. The header comment counts six steps instead of five. |
| `docs/exec-plans/README.md` | this plan, in the index |
| `docs/production-readiness.md` | the gate row that names the job and what it asserts |
| `CHANGELOG.md` | the job, under Unreleased |

## Concrete Steps

1. **Pull, never build.** The job runs `docker compose pull` with
   `OPENDRP_IMAGE_PREFIX` pointed at the owner's registry path and
   `OPENDRP_VERSION` pinned to the release. Both go to `$GITHUB_ENV`, so the
   Compose commands below resolve the same references. A smoke that built would
   test the source tree; the artifact is the thing an operator downloads.
2. **Refuse an image that was built instead of pulled.** For each of the eight
   images the matrix publishes, `docker image inspect` must report a
   `RepoDigests` entry naming that reference. Only a registry supplies a digest,
   so a locally built image — or a pull that resolved a different name — fails
   here rather than passing as "the published image starts".
3. **Raise the stack from those images.** `docker compose up -d --wait
   --wait-timeout 600` over `postgres redis backend celery-worker
   celery-worker-alerts celery-beat frontend`. Every one of them has a
   healthcheck (the repository gate `scripts/check_compose_healthchecks.py`
   enforces that), and `--wait` turns "never healthy" into a non-zero exit. The
   connector containers are deliberately not started: a connector needs a
   core-issued token (`docs/deployment.md` step 6) and the provider ones an API
   key, so a fresh installation shows them restarting by design. Their images are
   still pulled and digest-checked in step 2.
4. **Assert what a user would see.** `/api/v1/health` must report the version the
   tag names — the running artifact, not the file the build job read;
   `/api/v1/ready` must be `ready` with no degraded audit chain and no non-`ok`
   check; the SPA root must answer `text/html` with `<div id="root">`. A 200 from
   `/health` alone would pass on a stack that cannot see its database.
5. **Gate the notes on it.** `release` now needs `smoke-published-images`, so a
   release is not published for images nobody has seen run. The failing half is
   printed by the job itself: `docker compose ps` and 200 log lines, because a
   runner's output is gone when the job ends.
6. **Write the configuration the way an operator does.** `python3 setup.py
   --non-interactive --public-url http://127.0.0.1`, the wizard the e2e job
   already uses, so a wizard that stops writing a startable `.env` fails the
   release too.

## Validation and Acceptance

What the manual pass established, and therefore what the job is expected to
assert on its first tagged run:

- [x] All eight published images pull; the backend's digest equals the promoted
      release digest, so the artifact is the one the scan approved.
- [x] `docker compose up -d --wait` reaches 12/12 healthy on a fresh database,
      exit 0, from pulled images with no local build.
- [x] `/api/v1/health` reports `version: 0.2.3` with HTTP 200.
- [x] `/api/v1/ready` reports `status: ready`, `checks`: database/redis/audit
      `ok`, `audit_degraded: false`, HTTP 200.
- [x] The SPA root answers HTTP 200.
- [x] The workflow file parses as YAML and keeps the gates that read it green
      (`check_release_publish_order.py`, `check_release_refs.py`,
      `check_release_images.py`, `check_docs_consistency.py`,
      `check_portable_commands.py`); all 16 `run:` blocks pass `bash -n` and the
      five embedded Python programs compile.
- [x] The three assertions were extracted from the workflow and driven against
      this machine's 0.2.3 stack: the digest guard accepts the pulled release and
      rejects a version tag that is not present, the health assertion accepts
      `0.2.3` and rejects `9.9.9`, and readiness plus the SPA pass.
- [ ] The first tagged run: `smoke-published-images` succeeds, and `release`
      starts only after it.

Two blockers the manual pass hit are local, not release defects, and the job
avoids both by construction: a GHCR token without `read:packages` cannot pull a
private image (the job logs in with the repository's own `GITHUB_TOKEN` under
`packages: read`), and a host whose existing Docker networks already occupy
`172.18.0.0/16` cannot create Compose's default subnets (a GitHub runner starts
with only the bridge network).

## Progress and Milestones

- **2026-11-07 — the manual pass.** v0.2.3 verified by hand on a workstation: 8
  images pulled, stack up, health/ready/frontend answering. Two environment
  blockers recorded above; a third finding — a fresh `.env` has empty
  `CONNECTOR_TOKEN_*`, so the five connector containers restart until step 6 is
  run — is what step 3 of this plan encodes rather than works around.
- **2026-11-07 — the job is written.** `smoke-published-images` added to
  `release.yml`, `release` gated on it, the gate row, this plan and the
  changelog. The YAML and the repository gates pass locally; the first tagged run
  is the remaining acceptance item.
- **2026-11-07 — the digest guard had the bug it was written to catch, in the
  first direction.** Run against the real 0.2.3 pull, it reported all eight
  pulled images as "built locally": `RepoDigests` entries name the repository
  without the tag (`…/backend@sha256:…`), and the comparison used the tagged
  reference. It compares the repository prefix now, and the same run accepts the
  published images and still rejects a version nobody published. This is the
  argument for running the assertion body against something real before the first
  tag trusts it.
