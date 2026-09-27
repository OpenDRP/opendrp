FROM python:3.12-slim

WORKDIR /app

# Shared SDK first (cached layer).
COPY connectors/base /opt/sdk
RUN pip install --no-cache-dir /opt/sdk

COPY connectors/shodan/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

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
