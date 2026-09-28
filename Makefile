.PHONY: help setup check-env up up-tools pull-prod down destroy logs build ps seed-demo shell-backend shell-frontend test-backend test-backend-fast test-backend-integration test-backend-critical-coverage tools-check check-backend-migrations check-compose check-commands check-deps check-frontend-spa migrate connector-token connector-token-rotate connector-tokens backup backup-verify restore verify-audit-chain typecheck-backend lint-backend mypy-backend restart health verify-replicas clean

.DEFAULT_GOAL := help

# ==============================================================================
# Two file sets: one installation, one test harness
# ==============================================================================
# `make up` is the installation. It is docker-compose.yml alone — the shape
# docs/production-readiness.md describes and the shape an operator runs. There is
# no `SHAPE` variable any more and no second deployment to pick between: a wizard
# that wrote a "development" `.env` meant that what a developer tested was not
# what a user got, and the difference only became visible on a real host.
#
# The development overlay is still here, as *tooling*. `make up-tools` layers it
# on to get a source-mounted API container with pytest, ruff and mypy, which is
# what the test and lint targets below exec into. It is named for what it is, and
# no installation path reaches it.
#
# Why explicit `-f` flags rather than relying on Compose's automatic overlay
# load: the file name Compose auto-loads, docker-compose.override.yml, is reserved
# for a developer's own uncommitted tweaks (it is in .gitignore). Keeping the
# committed overlay under its own name means a target can never silently address
# the wrong shape — and that matters most for `backup`, which writes to a
# different path in each shape and would otherwise archive an empty directory
# without complaint.
COMPOSE = docker compose -f docker-compose.yml
TOOLS = docker compose -f docker-compose.yml -f docker-compose.dev.yml

# The two-replica stack used by `make verify-replicas`: the production API shape
# with the container name and published port released so Compose can run two
# instances of it.
COMPOSE_REPLICAS ?= docker compose -f docker-compose.yml -f docker-compose.replicas.yml

help:
	@echo "OpenDRP Platform — Makefile targets"
	@echo "==================================="
	@echo ""
	@echo "Core commands:"
	@echo "  setup           Create .env from .env.example, generating every secret"
	@echo "                  (asks deployment/security questions; `python setup.py --check` audits an"
	@echo "                  existing .env, `--repair` fills gaps, `--force` rotates)"
	@echo "  up              Build + start the installation (base compose file, no source mounts,"
	@echo "                  read-only rootfs)"
	@echo "  up-tools        Start the tooling stack: source mounts + pytest/ruff/mypy for the test"
	@echo "                  and lint targets below. Not an installation; `up` and it are alternatives"
	@echo "  down            Stop all services (keeps volumes)"
	@echo "  destroy         ⚠️  Stop + DELETE ALL volumes (postgres_data, redis_data, reports_store)"
	@echo "  build           Build images only ($(COMPOSE) build)"
	@echo "  restart         down + up (restart all services)"
	@echo "  clean           Remove __pycache__, .pytest_cache, and temporary files"
	@echo ""
	@echo "Data safety:"
	@echo "  backup          Dump PostgreSQL + report store into ./backups (one pass)"
	@echo "  backup-verify   Restore the newest dump into a throwaway DB and check it"
	@echo "  restore         ⚠️  Restore a dump over the live DB (FILE=...; needs CONFIRM_RESTORE=yes)"
	@echo "  verify-audit-chain  Verify the audit hash chain (FULL=1 for a full pass,"
	@echo "                  FILE=<ndjson> to check an exported stream instead of the DB)"
	@echo ""
	@echo "Monitoring & diagnostics:"
	@echo "  logs            Tail all container logs in real time (--tail=200)"
	@echo "  ps              List running containers and their status"
	@echo "  health          Compose status + API healthcheck http://localhost:8000/api/v1/health"
	@echo "  verify-replicas Start two API replicas and prove they share state (see docs/upgrading.md)"
	@echo ""
	@echo "Compose file sets (one installation shape, and no variable to pick one):"
	@echo "  installation    docker-compose.yml — what `make up`, `make logs` and `make backup` address"
	@echo "  tooling         + docker-compose.dev.yml — what `make up-tools` and the test targets use"
	@echo ""
	@echo "Backend development (the test and lint targets need `make up-tools`):"
	@echo "  shell-backend   Open /bin/bash inside the backend container"
	@echo "  shell-frontend  Open sh inside the frontend container"
	@echo "  migrate         Apply pending Alembic migrations (alembic upgrade head)"
	@echo "  test-backend    Run pytest for the backend test suite (tests/)"
	@echo "  test-backend-integration  Run real PostgreSQL/Redis boundary tests inside Compose"
	@echo "  check-backend-migrations  Verify the Alembic revision graph and that the schema it builds"
	@echo "                  matches the ORM models (scripts/check_migrations.py + check_schema_drift.py)"
	@echo "  check-compose   Fail if a service loses its healthcheck, log bound or network split"
	@echo "  check-env       Fail if .env.example and the Compose files disagree about a setting"
	@echo "  check-commands  Fail if a documented command needs a shell-specific line continuation"
	@echo "  check-deps      Fail if dependency declarations drift apart from requirements*.txt"
	@echo "  check-frontend-spa  Fail if Nginx can redirect an SPA route to a static directory"
	@echo "  test-backend-critical-coverage  Enforce coverage for security/connector modules"
	@echo "  typecheck-backend  Compile-time bytecode check (compileall over app scripts tests)"
	@echo "  mypy-backend    mypy ratchet gate vs baseline (scripts/check_mypy_baseline.py)"
	@echo "  seed-demo       Populate DB with demo data (users + assets + threats + breaches)"
	@echo ""

# The wizard is a host script, not a container one: it runs before the stack
# exists (that is the point) and needs nothing but a Python interpreter. `make
# setup` is the shortcut; `python setup.py` is the same thing.
setup:
	@python setup.py

# The template is the only configuration reference this project ships, so it is
# checked rather than trusted: every variable Compose reads is documented, every
# documented setting reaches a container, and none of them is shadowed by a
# literal in the Compose file. Each of those has shipped as a real defect.
check-env:
	@python scripts/check_env_template.py

# The documentation is a list of instructions, and an instruction wrapped over
# several lines with trailing backslashes is only usable in bash/zsh: PowerShell
# and cmd.exe read the remaining lines as separate commands. One of those
# shipped in the quick start and failed on the first Windows install.
check-commands:
	@python scripts/check_portable_commands.py

check-deps:
	@python scripts/check_dependency_sources.py

# A failed `up` is the least diagnosable moment in this project: Compose prints
# `dependency failed to start: container opendrp-backend is unhealthy`, which
# names the *blocked* service and not the reason, and the actual traceback is one
# `docker compose logs` away. So the reason is printed here instead of being
# described in a document nobody reads mid-incident. Bounded to the services that
# are not running, so a healthy stack's logs are not dumped into the terminal.
up:
	@$(COMPOSE) up -d --build || { \
		echo ""; \
		echo "⚠️  The stack did not start. Docker reports only the healthcheck verdict, so here is"; \
		echo "    the state and the log tail of every service that is not running:"; \
		$(COMPOSE) ps; \
		for service in $$($(COMPOSE) config --services); do \
			container=$$($(COMPOSE) ps -q $$service); \
			[ -n "$$container" ] || continue; \
			state=$$(docker inspect -f '{{.State.Status}}' $$container 2>/dev/null); \
			[ "$$state" = "running" ] && continue; \
			echo ""; \
			echo "--- $$service ($$state) ---"; \
			$(COMPOSE) logs --tail=40 $$service; \
		done; \
		echo ""; \
		echo "    The entrypoint runs with set -e, so the last [OpenDRP] line names the failing step."; \
		echo "    docs/operations.md, Troubleshooting, has the triage for an unhealthy container."; \
		exit 1; \
	}

# Tooling, not an installation. This layers docker-compose.dev.yml on so the API
# container mounts the checkout and carries pytest, ruff and mypy — which is what
# the test and lint targets below exec into. Switching between this and `make up`
# recreates the API container (the overlay changes its image tag and its mounts);
# the datastores keep their data, and the two shapes cannot run at the same time,
# because the service container names are fixed.
up-tools:
	$(TOOLS) up -d --build

pull-prod:
	$(COMPOSE) pull

# The test and lint targets exec into the tooling stack, because pytest, ruff and
# mypy live in that image and not in the shipped one. Without this, running one
# against an installation fails with "pytest: not found" from inside a container
# that is working exactly as designed — a message that names the symptom and
# hides the cause, which is that the wrong file set is up.
tools-check:
	@container=$$($(TOOLS) ps -q backend 2>/dev/null); \
	if [ -z "$$container" ]; then \
		echo "This target runs pytest/ruff/mypy inside the tooling container, which is not running."; \
		echo "Start it first:  make up-tools"; \
		echo "(an installation started with 'make up' is a different shape and is unaffected.)"; \
		exit 1; \
	fi

down:
	$(COMPOSE) down

destroy:
	@echo "⚠️  DESTRUCTIVE: deleting ALL data (postgres_data, redis_data, reports_store volumes)"
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f --tail=200

build:
	$(COMPOSE) build

ps:
	$(COMPOSE) ps

seed-demo:
	$(COMPOSE) exec -T backend python -m scripts.seed_data all --yes

shell-backend:
	$(COMPOSE) exec backend /bin/bash

shell-frontend:
	$(COMPOSE) exec frontend sh

# COVERAGE_CORE=sysmon: the default C tracer mis-reports async task frames in
# this environment (endpoints verified returning 200/201 while their lines were
# counted as missed), understating coverage by ~9 points. sysmon tracks tasks
# correctly. See scripts/check_mypy_baseline.py header for the investigation.
test-backend: tools-check
	$(TOOLS) exec -T backend sh -c 'COVERAGE_CORE=sysmon python -m pytest -v tests/'

test-backend-fast: tools-check
	$(TOOLS) exec -T backend sh -c 'COVERAGE_CORE=sysmon python -m pytest -q -m "not integration" tests/'

# Real-services boundary tests (PostgreSQL row locking, enum/UUID/JSON columns,
# Redis atomic NX/TTL). Runs against the live Compose database, so the
# destructive Alembic round-trip stays in CI with its own throwaway database.
# REQUIRE_INTEGRATION=1 makes missing connection env a hard error rather than
# a skip, so this target cannot silently pass without exercising PostgreSQL.
test-backend-integration: tools-check
	$(TOOLS) exec -T backend sh -c 'COVERAGE_CORE=sysmon REQUIRE_INTEGRATION=1 INTEGRATION_DATABASE_URL=$$DATABASE_URL INTEGRATION_REDIS_URL=$$REDIS_URL python -m pytest -q tests/test_production_integrations.py'

# Both halves of "is the schema what the code expects": the revision *graph*
# (single head, ancestry, table names that exist by then) and the *models*
# versus what the chain actually builds. They are one target because running
# half of the check is how a green result becomes a false one.
check-backend-migrations:
	$(COMPOSE) exec -T backend sh -c 'python scripts/check_migrations.py && python -m scripts.check_schema_drift'

test-backend-critical-coverage: tools-check
	$(TOOLS) exec -T backend sh -c 'COVERAGE_CORE=sysmon python -m pytest -q --cov=app.core.security --cov=app.core.crypto --cov=app.api.deps --cov=app.services.connector_manifest --cov=app.services.connector_service --cov=app.services.connector_credentials --cov=app.services.module_registry --cov=app.services.ingestion_service --cov=app.core.request_rate_limit --cov=app.services.alert_service --cov=app.services.alert_delivery_service --cov=app.tasks.alert_tasks --cov=app.api.v1.routers.alerts --cov=app.core.health --cov=app.tasks.report_tasks --cov=app.services.phishing.whois_service --cov-report=json:coverage-critical.json --cov-report=term-missing tests/ && python scripts/check_critical_coverage.py coverage-critical.json'

migrate:
	$(COMPOSE) exec -T backend alembic upgrade head

# Per-connector credentials: NAME=<connector> TYPE=<module>
# Issue a connector's credential and record it in .env, so provisioning a fresh
# checkout is one command rather than copy-pasting a secret by hand. The token is
# printed as well, because the plaintext is shown exactly once and never stored.
#
# Usage: make connector-token NAME=dnstwist TYPE=phishing
#        make connector-token-rotate NAME=dnstwist
CONNECTOR_TOKEN_VAR = CONNECTOR_TOKEN_$(shell echo $(NAME) | tr '[:lower:]-' '[:upper:]_')

connector-token:
	@test -n "$(NAME)" || (echo "Usage: make connector-token NAME=<connector> TYPE=<module>" && exit 2)
	@test -n "$(TYPE)" || (echo "Usage: make connector-token NAME=<connector> TYPE=<module>" && exit 2)
	@var=$(CONNECTOR_TOKEN_VAR); \
	output=$$($(COMPOSE) exec -T backend python -m scripts.manage_connector_tokens issue $(NAME) --type $(TYPE) --env $$var); \
	echo "$$output"; \
	line=$$(printf '%s\n' "$$output" | grep "^[[:space:]]*$$var=" | tr -d '[:space:]'); \
	test -n "$$line" || { echo "No token was issued — read the output above." >&2; exit 1; }; \
	if [ -f .env ] && grep -q "^$$var=" .env; then \
		sed -i "s|^$$var=.*|$$line|" .env; \
		echo ">> .env: replaced $$var"; \
	else \
		printf '\n# Connector credential for %s, issued by `make connector-token`.\n# Not recoverable: the core stores only its digest.\n%s\n' "$(NAME)" "$$line" >> .env; \
		echo ">> .env: appended $$var"; \
	fi; \
	echo "Recreate the connector to pick it up: $(COMPOSE) up -d connector-$(NAME)"
	echo "A restart is not enough: a container keeps the environment it was created with."

connector-token-rotate:
	@test -n "$(NAME)" || (echo "Usage: make connector-token-rotate NAME=<connector>" && exit 2)
	@var=$(CONNECTOR_TOKEN_VAR); \
	output=$$($(COMPOSE) exec -T backend python -m scripts.manage_connector_tokens rotate $(NAME) --env $$var); \
	echo "$$output"; \
	line=$$(printf '%s\n' "$$output" | grep "^[[:space:]]*$$var=" | tr -d '[:space:]'); \
	test -n "$$line" || { echo "No token was issued — read the output above." >&2; exit 1; }; \
	if grep -q "^$$var=" .env; then sed -i "s|^$$var=.*|$$line|" .env; \
	else printf '\n%s\n' "$$line" >> .env; fi; \
	echo ">> .env: updated $$var"; \
	echo "Recreate the connector to pick it up: $(COMPOSE) up -d connector-$(NAME)"
	echo "A restart is not enough: a container keeps the environment it was created with."

connector-tokens:
	$(COMPOSE) exec -T backend python -m scripts.manage_connector_tokens list

typecheck-backend: tools-check
	$(TOOLS) exec -T backend python -m compileall -q app scripts tests

mypy-backend: tools-check
	$(TOOLS) exec -T backend python scripts/check_mypy_baseline.py

lint-backend: tools-check
	$(TOOLS) exec -T backend ruff check app scripts tests

check-compose:
	python scripts/check_compose_healthchecks.py docker-compose.yml

check-frontend-spa:
	python scripts/check_frontend_spa.py

# --- Backup and restore -------------------------------------------------------
# Both run the same script as the scheduled `backup` profile service, inside a
# postgres:17-alpine container, so the pg_dump client always matches the server
# and the host needs no PostgreSQL client tools.
#
# BACKUP_ONCE=1 is what makes this a command rather than a daemon: the script's
# default is the compose profile's loop (one pass every BACKUP_INTERVAL_SEC,
# 24 h), so without it `make backup` takes the dump and then sits in `sleep`
# forever. Same reason it is set explicitly in CI.
backup:
	$(COMPOSE) run --rm -e BACKUP_ONCE=1 backup

backup-verify:
	$(COMPOSE) run --rm backup sh /backup-scripts/verify_restore.sh

# Destructive by design: refuses without CONFIRM_RESTORE=yes, refuses while any
# other client is connected, and takes a safety copy first. Stop the writers:
#   docker compose -f docker-compose.yml stop backend celery-worker celery-beat connector-dnstwist connector-shodan connector-hibp
#   make restore FILE=backups/opendrp-20260913T041500Z.dump
restore:
	@test -n "$(FILE)" || (echo "Usage: make restore FILE=<dump>  (CONFIRM_RESTORE=yes is demanded by the script)" && exit 2)
	$(COMPOSE) run --rm backup \
		sh /backup-scripts/restore.sh /backups/$(notdir $(FILE))

# --- Audit integrity ----------------------------------------------------------
# The database copy of the audit trail is hash-chained; this checks that it still
# verifies, and reports the first position that does not. The nightly task runs
# the incremental pass on its own schedule — this is for the moment an operator
# needs an answer now, or needs the whole history re-derived (FULL=1).
#
# With FILE=<ndjson> it verifies an exported audit stream instead, which needs no
# database at all: that is how a copy held outside the platform is checked.
verify-audit-chain:
	@if [ -n "$(FILE)" ]; then \
		$(COMPOSE) exec -T backend python -m scripts.verify_audit_chain --ndjson "/data/$(notdir $(FILE))"; \
	else \
		$(COMPOSE) exec -T backend python -m scripts.verify_audit_chain $(if $(FULL),--full,) $(if $(JSON),--json,); \
	fi

restart: down up

# --- Statelessness under two API replicas -------------------------------------
# What this proves, and why it is a make target rather than a claim in a
# document: the platform is meant to scale horizontally by adding API replicas
# behind a load balancer, and "stateless" is only true if a session created on
# one replica is usable on the other. The script logs in against replica A,
# presents that access token and refresh cookie to replica B, refreshes there,
# and confirms both replicas read the same audit row — i.e. that the only shared
# state is PostgreSQL and Redis, and nothing lives in process memory.
#
# The stack it starts is the production shape: the replicas override drops
# `container_name` and the published port (both of which exist for the single-API
# deployment), so two containers can run at once. It is not torn down for you,
# because seeing the two replicas side by side is the point:
#
#   make verify-replicas        # start the stack and run the proof
#   docker compose -f docker-compose.yml -f docker-compose.replicas.yml down
#
# Requires ADMIN_EMAIL and ADMIN_PASSWORD for an existing administrator, since
# the last check reads the audit trail.
verify-replicas:
	@test -n "$(ADMIN_EMAIL)" || (echo "Usage: ADMIN_EMAIL=<addr> ADMIN_PASSWORD=<pass> make verify-replicas" && exit 2)
	@test -n "$(ADMIN_PASSWORD)" || (echo "Usage: ADMIN_EMAIL=<addr> ADMIN_PASSWORD=<pass> make verify-replicas" && exit 2)
	$(COMPOSE_REPLICAS) up -d --build
	@echo "[replicas] waiting for two healthy API containers..."
	$(COMPOSE_REPLICAS) up -d --wait backend
	$(COMPOSE_REPLICAS) --profile verify run --rm --no-deps \
		-e ADMIN_EMAIL="$(ADMIN_EMAIL)" -e ADMIN_PASSWORD="$(ADMIN_PASSWORD)" \
		replica-check

health:
	$(COMPOSE) ps
	@echo ""
	@echo "--- API healthcheck ---"
	curl -f http://localhost:8000/api/v1/health || (echo "API is unreachable" && exit 1)
	@echo ""

clean:
	@echo "Cleaning temporary files and cache..."
	@find . -type d \( -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache -o -name htmlcov \) -prune -exec rm -rf {} +
	@find . -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '.coverage' -o -name 'coverage-critical.json' -o -name '*.tsbuildinfo' \) -delete
	@rm -f celerybeat-schedule celerybeat-schedule* backend/celerybeat-schedule backend/celerybeat-schedule*
	python -c "import pathlib, shutil; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]; [shutil.rmtree(p, ignore_errors=True) for p in pathlib.Path('.').rglob('.pytest_cache')]; [p.unlink() for p in pathlib.Path('.').rglob('*.pyc')]" 2>/dev/null || true
	@echo "Clean completed."
