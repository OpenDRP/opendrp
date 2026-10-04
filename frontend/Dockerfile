# ------------------------------------------------------------------------------
# OpenDRP Frontend Dockerfile
# NOTE: build context MUST be the repo ROOT (docker-compose sets context: .)
# Multi-stage: Node 20 (build) → Nginx Alpine (serve)
# ------------------------------------------------------------------------------

# ---- Stage 1: Builder — install deps & run Vite production build -------------
FROM node:20-alpine AS builder

WORKDIR /app

# Install base deps for native modules (parcel, esbuild, etc.)
RUN apk add --no-cache libc6-compat python3 make g++

# Copy package manifests first — enables Docker layer caching of node_modules
COPY ./frontend/package*.json ./

# ---------- npm ci — FAIL FAST, preserve full log ----------------------------
# NOTE: piping to `tail` would hide the REAL npm error because pipe exit code
#       becomes `tail`'s exit (always 0). We write to a temp logfile, then
#       inspect npm's $?; and cat the tail only if user wants summary.
RUN set -euo pipefail; \
  npm config set fetch-retries 5; \
  npm config set fetch-retry-mintimeout 20000; \
  npm config set fetch-retry-maxtimeout 120000; \
  npm config set cache /tmp/npm-cache --global; \
  echo "[builder] npm version:"; npm -v; \
  echo "[builder] node version:"; node -v; \
  \
  LOG=/tmp/npm-install.log; \
  if [ -f package-lock.json ]; then \
    echo "[builder] package-lock.json found → npm ci"; \
    set +e; \
    npm ci --no-audit --no-fund --loglevel=error >"$LOG" 2>&1; \
    NPM_RC=$?; \
    set -e; \
  else \
    echo "[builder] ERROR: package-lock.json is required for reproducible production builds"; \
    exit 1; \
  fi; \
  \
  echo "------------------------------------------------------------"; \
  echo "[builder] === npm install/ci log (tail -100): ==="; \
  tail -n 100 "$LOG" || true; \
  echo "------------------------------------------------------------"; \
  echo "[builder] npm exit code: $NPM_RC"; \
  if [ "$NPM_RC" -ne 0 ]; then \
    echo "[builder] ERROR: npm ci FAILED (rc=$NPM_RC). Full log below (1000 lines):"; \
    head -n 1000 "$LOG" || true; \
    exit "$NPM_RC"; \
  fi; \
  \
  if ! [ -d node_modules ]; then \
    echo "[builder] ERROR: node_modules directory does NOT exist after npm (rc=0) - filesystem?"; \
    ls -la /app; \
    exit 2; \
  fi; \
  echo "[builder] OK node_modules size: $(du -sh node_modules | cut -f1)"

# Pass build-time API base URL. Defaults to /api/v1 which nginx proxies to backend in Stage 2.
ARG VITE_API_BASE_URL=/api/v1
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ARG VITE_CANONICAL_ORIGIN=
ENV VITE_CANONICAL_ORIGIN=${VITE_CANONICAL_ORIGIN}
# The version the bundle reports in the UI (see src/lib/appMeta.ts). Baked in at
# build time so the footer of a running instance names the release that produced
# it, which is what makes a screenshot usable in a bug report. Defaulted to the
# in-tree version rather than left unset, so a development build does not claim
# to be a release it is not.
ARG VITE_APP_VERSION=0.1.1
ENV VITE_APP_VERSION=${VITE_APP_VERSION}
ENV NODE_ENV=production

# Copy remaining frontend source code and configs
COPY ./frontend/tsconfig*.json ./
COPY ./frontend/vite.config.* ./
COPY ./frontend/index.html ./
COPY ./frontend/public ./public
COPY ./frontend/src ./src

# ---------- TypeScript check + Vite build — FAIL FAST, preserve log --------
RUN set -euo pipefail; \
  TS_LOG=/tmp/tsc.log; VITE_LOG=/tmp/vite.log; \
  \
  echo "[builder] === TypeScript typecheck: tsc -b ==="; \
  set +e; npx tsc -b >"$TS_LOG" 2>&1; TS_RC=$?; set -e; \
  echo "------------------------------------------------------------"; \
  echo "[builder] tsc log (tail -120):"; tail -n 120 "$TS_LOG" || true; \
  echo "[builder] tsc exit code: $TS_RC"; \
  if [ "$TS_RC" -ne 0 ]; then \
    echo "[builder] ERROR tsc FAILED (rc=$TS_RC). First 500 lines of $TS_LOG:"; \
    head -n 500 "$TS_LOG" || true; \
    exit "$TS_RC"; \
  fi; \
  \
  echo "[builder] === Vite production build ==="; \
  set +e; npx vite build >"$VITE_LOG" 2>&1; VITE_RC=$?; set -e; \
  echo "------------------------------------------------------------"; \
  echo "[builder] vite log (tail -120):"; tail -n 120 "$VITE_LOG" || true; \
  echo "[builder] vite exit code: $VITE_RC"; \
  if [ "$VITE_RC" -ne 0 ]; then \
    echo "[builder] ERROR vite build FAILED (rc=$VITE_RC). First 500 lines of $VITE_LOG:"; \
    head -n 500 "$VITE_LOG" || true; \
    exit "$VITE_RC"; \
  fi; \
  \
  if ! [ -d dist ]; then \
    echo "[builder] CRITICAL: dist directory NOT FOUND after successful vite build (rc=0). ls -la /app:"; \
    ls -la /app; \
    exit 3; \
  fi; \
  echo "[builder] SUCCESS - dist contents:"; \
  du -sh dist; \
  ls -la dist;

# ---- Stage 2: Runtime — Nginx serve SPA + reverse-proxy /api → backend ------
FROM nginx:1.31.0-alpine3.23 AS runtime

# Keep packages in the base image current with security updates published for
# this Alpine branch after the upstream nginx image was built.
RUN apk upgrade --no-cache

# Copy global nginx.conf (worker tuning, gzip, logging)
COPY ./docker/nginx/nginx.conf /etc/nginx/nginx.conf

# Copy server block: serves SPA + proxies /api → http://backend:8000
COPY ./docker/nginx/default.conf /etc/nginx/conf.d/default.conf

# Renders /etc/nginx/hsts.inc from HSTS_ENABLED, HSTS_MAX_AGE and
# HSTS_INCLUDE_SUBDOMAINS at container start, because nginx cannot read an
# environment variable and `add_header` cannot be made conditional. The nginx
# entrypoint runs every executable *.sh in /docker-entrypoint.d/ before the server
# starts, and the script checks its own output with `nginx -t`.
COPY ./docker/nginx/hsts.sh /docker-entrypoint.d/40-opendrp-hsts.sh
# A declared default as well, so the configuration parses in the built image and
# in any start that bypasses the entrypoint; the entrypoint overwrites it.
RUN chmod 0755 /docker-entrypoint.d/40-opendrp-hsts.sh \
    && printf '# HSTS disabled until the entrypoint renders it.\n' > /etc/nginx/hsts.inc

# Copy SPA build artifacts from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Default port exposed by nginx
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || exit 1

CMD ["nginx", "-g", "daemon off;"]
