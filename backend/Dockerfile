# ------------------------------------------------------------------------------
# OpenDRP Backend Dockerfile
# Target: Python 3.12 slim + FastAPI + Celery + dnstwist + whois CLI
# Multi-stage build to keep final image lean
# ------------------------------------------------------------------------------

# ---- Stage 1: Builder — install system packages + Python wheels --------------
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# System deps needed to compile wheels (kept out of the final image).
#
# No `git` and no Poetry installer. Every dependency is pinned in
# requirements.txt and none is fetched from a VCS URL, so the builder needs
# neither a VCS client nor a second package manager. Installing Poetry from a
# URL was doing worse than nothing: `curl -sSL ... | python3 -` executes a remote
# script that is not pinned by digest, so a build could not be reproduced from
# this repository alone, and there is no poetry.lock for it to consume anyway.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    libffi-dev \
    libssl-dev \
  && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for layer caching
COPY pyproject.toml requirements.txt requirements-dev.txt ./

# Test/lint tooling is opt-in. The production image installs requirements.txt
# only, so a shipped container carries no test framework or type checker; the
# local Compose stack sets INSTALL_DEV_REQUIREMENTS=true because its Makefile
# targets run the test suite inside this container.
ARG INSTALL_DEV_REQUIREMENTS=false

# Install into venv that we can copy to runtime stage.
# Single path: always use requirements.txt (explicit, deterministic, no BuildKit
# heredoc edge cases).
RUN python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --upgrade pip && \
    pip install --no-cache-dir setuptools==84.0.0 && \
    pip install --no-cache-dir -r requirements.txt && \
    if [ "$INSTALL_DEV_REQUIREMENTS" = "true" ]; then \
        echo "[builder] installing dev requirements (test/lint tooling)"; \
        pip install --no-cache-dir -r requirements-dev.txt; \
    else \
        echo "[builder] dev requirements skipped (production image)"; \
    fi

# ---- Stage 2: Runtime — small final image with only necessary deps -----------
FROM python:3.12-slim AS runtime

# Runtime identity. Overridable because a Linux host bind-mounts its own uid into
# the container: with `./backend:/app` mounted, a container user whose uid does
# not match the checkout owner cannot write there, and the coverage/typecheck
# targets that run inside this container would fail. Docker Desktop presents
# bind mounts as owned by the container user, so the default is right there; on
# Linux set OPENDRP_UID/OPENDRP_GID (docker-compose passes them as build args).
ARG USER_UID=1000
ARG USER_GID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    REPORTS_STORE_DIR=/workspace/reports_store \
    HOME=/home/opendrp

WORKDIR /app

# System runtime deps: dnstwist, whois CLI, curl (for healthcheck), ca-certs
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnstwist \
    python3-dnspython \
    whois \
    curl \
    ca-certificates \
    fonts-dejavu \
    libpq5 \
  && apt-get upgrade -y --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*

# pip embeds an SBOM of its vendored tools which can misreport old versions of
# packages in the environment. Drop that metadata from both the base interpreter
# and the copied venv so image scanners inspect the installed distributions.
# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
RUN find /usr/local/lib/python3.12/site-packages /opt/venv/lib/python3.12/site-packages \
      -path '*/pip/_vendor/bom.cdx.json' -delete

# Copy application source
COPY . /app/

# Ensure alembic.ini points to correct dir
RUN mkdir -p /app/alembic/versions

# Create the runtime user *after* the last COPY so the copied tree can be
# chowned in the same layer, and so nothing above runs as a user that may not
# exist yet. `--create-home` matters: fpdf and pip both write caches under HOME.
RUN groupadd --gid "${USER_GID}" opendrp \
  && useradd --uid "${USER_UID}" --gid "${USER_GID}" \
       --create-home --shell /usr/sbin/nologin opendrp \
  && mkdir -p /workspace/reports_store \
  && chown -R "${USER_UID}:${USER_GID}" /app /workspace \
  && chmod 0700 /home/opendrp

# Nothing in this image needs root: uvicorn and the Celery worker only read the
# source, write generated PDFs into the reports store, and connect out. Running
# as an unprivileged uid means a remote code execution in the API no longer
# starts with ownership of the application tree — which matters here because the
# development stack bind-mounts that tree read-write.
USER opendrp

# Default command overridden by docker-compose service command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
