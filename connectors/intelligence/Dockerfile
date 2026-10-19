FROM python:3.14-slim
WORKDIR /app
COPY connectors/base /opt/sdk
RUN pip install --no-cache-dir /opt/sdk
COPY connectors/intelligence/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt
COPY connectors/intelligence/main.py connectors/intelligence/providers.py /app/
RUN useradd --system --uid 10001 connector
USER connector
ENV PYTHONUNBUFFERED=1 CONNECTOR_LIVENESS_FILE=/tmp/opendrp-connector-alive
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,sys,time; p=os.environ.get('CONNECTOR_LIVENESS_FILE'); sys.exit(0 if p and os.path.exists(p) and time.time()-os.path.getmtime(p)<90 else 1)"
CMD ["python", "main.py"]
