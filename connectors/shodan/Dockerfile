FROM python:3.12-slim

# The base layer is upgraded, not just the packages this image asks for. The
# official `python:3.12-slim` carries a Debian trixie snapshot, and its
# point-release security fixes reach the archive only after Docker rebuilds that
# image: at 0.2.4 the snapshot shipped a `zlib1g` that Trivy reports as HIGH
# (CVE-2026-76844, CVE-2026-85091) with a fix already published as `+deb13u1`.
# The release workflow fails on a fixable HIGH, so nothing ships until this
# layer moves. `upgrade`, not `dist-upgrade`: only packages the base image
# already installed are moved, and no new package is added.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Shared SDK first (cached layer).
COPY connectors/base /opt/sdk
RUN pip install --no-cache-dir /opt/sdk

COPY connectors/shodan/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt

COPY connectors/shodan/main.py /app/main.py

RUN useradd --system --uid 10001 connector
USER connector

ENV PYTHONUNBUFFERED=1 \
    CONNECTOR_LIVENESS_FILE=/tmp/opendrp-connector-alive

# Liveness, read from the file the SDK's watchdog task touches. The file is
# written on its own timer rather than by the poll loop, so a long scan does not
# read as a dead container; a stale file means the event loop stopped running.
# 90 s is roughly eighteen missed writes at the default 5 s poll interval.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,sys,time; p=os.environ.get('CONNECTOR_LIVENESS_FILE','/tmp/opendrp-connector-alive'); sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < 90 else 1)"

CMD ["python", "main.py"]
