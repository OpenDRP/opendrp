FROM python:3.12-slim

# dnstwist binary + its dictionary. The Debian package only Recommends
# python3-dnspython (skipped by --no-install-recommends), yet the CLI's
# shebang points at the system python and hard-fails at runtime with
# "missing DNSPython library" without it — install it explicitly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends dnstwist python3-dnspython \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Shared SDK first (cached layer).
COPY connectors/base /opt/sdk
RUN pip install --no-cache-dir /opt/sdk

COPY connectors/dnstwist/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY connectors/dnstwist/main.py /app/main.py

# Non-root runtime user.
RUN useradd --system --uid 10001 connector
USER connector

ENV PYTHONUNBUFFERED=1 \
    CONNECTOR_LIVENESS_FILE=/tmp/opendrp-connector-alive

# Liveness, read from the file the SDK's watchdog task touches. The file is
# written on its own timer rather than by the poll loop, so dnstwist's long
# scans do not read as a dead container; a stale file means the event loop
# stopped running. 90 s is roughly eighteen missed writes at the default 5 s
# poll interval.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,sys,time; p=os.environ.get('CONNECTOR_LIVENESS_FILE','/tmp/opendrp-connector-alive'); sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < 90 else 1)"

CMD ["python", "main.py"]
