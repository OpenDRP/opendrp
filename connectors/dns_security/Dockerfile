FROM python:3.12-slim

WORKDIR /app
COPY connectors/base /opt/sdk
RUN pip install --no-cache-dir /opt/sdk
COPY connectors/dns_security/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt
# The active TLS probe is a `curl` invocation rather than a library: the exact
# command an operator can reproduce by hand, with the exit-code taxonomy the
# classification rules on. `ca-certificates` comes with it because verification
# against the system store is the point of the authoritative pass, and `%{certs}`
# needs curl 7.88 (the worker records its version and refuses to probe on an older
# build rather than reporting hosts as certificate-less).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY connectors/dns_security/main.py connectors/dns_security/tls_probe.py /app/
RUN useradd --system --uid 10001 connector
USER connector
ENV PYTHONUNBUFFERED=1 CONNECTOR_LIVENESS_FILE=/tmp/opendrp-connector-alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,sys,time; p=os.environ.get('CONNECTOR_LIVENESS_FILE'); sys.exit(0 if p and os.path.exists(p) and time.time()-os.path.getmtime(p)<90 else 1)"
CMD ["python", "main.py"]
