# =============================================================================
#  NetShield-ISP — developer entry points.
#  Run `make help` for the full list.
# =============================================================================

SHELL := /bin/bash

# Compose implementation discovery, in order of preference:
#   1. `docker compose`  — Docker CLI with the Compose v2 plugin
#   2. `docker-compose`  — standalone Compose v2 binary, which also drives Podman
#   3. `podman compose`  — Podman's own wrapper
# Override with `make COMPOSE="..." <target>` if the guess is wrong.
COMPOSE ?= $(shell \
	if docker compose version >/dev/null 2>&1; then echo "docker compose"; \
	elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; \
	elif [ -x "$$HOME/.local/bin/docker-compose" ]; then echo "$$HOME/.local/bin/docker-compose"; \
	elif command -v podman-compose >/dev/null 2>&1; then echo "podman-compose"; \
	else echo "docker compose"; fi)

# When only Podman is present, Compose needs to be pointed at its rootless
# socket. Start it once with `systemctl --user enable --now podman.socket`.
PODMAN_SOCKET := /run/user/$(shell id -u)/podman/podman.sock
ifeq ($(shell command -v docker >/dev/null 2>&1 && echo yes),)
ifneq ($(wildcard $(PODMAN_SOCKET)),)
export DOCKER_HOST := unix://$(PODMAN_SOCKET)
endif
endif

BACKEND_EXEC := $(COMPOSE) exec backend
WORKER_EXEC := $(COMPOSE) exec celery_worker
FRONTEND_EXEC := $(COMPOSE) exec frontend

.DEFAULT_GOAL := help
.PHONY: help runtime init build up down restart logs ps clean \
        migrate migration seed create-admin db-shell redis-shell \
        test lint format typecheck security audit check \
        frontend-lint frontend-typecheck worker-ping nmap-caps

# -----------------------------------------------------------------------------
# Meta
# -----------------------------------------------------------------------------

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  compose implementation: $(COMPOSE)"
	@echo "  DOCKER_HOST           : $${DOCKER_HOST:-<default>}"

runtime: ## Show the detected container runtime and verify it responds
	@echo "compose     : $(COMPOSE)"
	@echo "DOCKER_HOST : $${DOCKER_HOST:-<default>}"
	@$(COMPOSE) version

init: ## Create .env from the template and generate strong secrets
	@python3 scripts/generate_env.py
	@echo "Review .env before starting the stack."

# -----------------------------------------------------------------------------
# Stack lifecycle
# -----------------------------------------------------------------------------

build: ## Build every image
	$(COMPOSE) build

up: ## Start the full stack in the background
	$(COMPOSE) up -d
	@echo "API      http://localhost:8000/docs"
	@echo "Frontend http://localhost:3000"

down: ## Stop the stack, keeping volumes
	$(COMPOSE) down

restart: ## Restart every service
	$(COMPOSE) restart

logs: ## Follow logs for all services
	$(COMPOSE) logs -f --tail=100

ps: ## Show service status
	$(COMPOSE) ps

clean: ## Stop the stack AND delete its volumes (destroys all local data)
	$(COMPOSE) down --volumes --remove-orphans

# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------

migrate: ## Apply all pending migrations
	$(BACKEND_EXEC) alembic upgrade head

migration: ## Autogenerate a migration: make migration m="add scans table"
	@test -n "$(m)" || (echo 'usage: make migration m="description"'; exit 1)
	$(BACKEND_EXEC) alembic revision --autogenerate -m "$(m)"

seed: ## Load development seed data (idempotent, refuses to run in production)
	$(BACKEND_EXEC) python seed.py

create-admin: ## Create the first platform administrator: make create-admin email=... name="..."
	@test -n "$(email)" || (echo 'usage: make create-admin email=ops@example.com name="Ops"'; exit 1)
	@test -n "$(name)" || (echo 'usage: make create-admin email=ops@example.com name="Ops"'; exit 1)
	$(COMPOSE) exec -it backend python -m app.diagnostics.create_admin \
		--email "$(email)" --name "$(name)"

db-shell: ## Open a psql shell
	$(COMPOSE) exec db psql -U $${POSTGRES_USER:-netshield} -d $${POSTGRES_DB:-netshield}

redis-shell: ## Open a redis-cli shell
	$(COMPOSE) exec redis sh -c 'redis-cli -a "$$REDIS_PASSWORD"'

# -----------------------------------------------------------------------------
# Quality gates
# -----------------------------------------------------------------------------

test: ## Run the backend test suite
	$(BACKEND_EXEC) pytest

lint: ## Lint the backend
	$(BACKEND_EXEC) ruff check .

format: ## Format the backend
	$(BACKEND_EXEC) ruff format .
	$(BACKEND_EXEC) ruff check --fix .

typecheck: ## Type-check the backend
	$(BACKEND_EXEC) mypy app alembic tests seed.py

security: ## Run the static security scan
	$(BACKEND_EXEC) bandit -c pyproject.toml -r app -q

audit: ## Check dependencies for known vulnerabilities
	$(BACKEND_EXEC) pip-audit

frontend-lint: ## Lint the frontend
	$(FRONTEND_EXEC) npm run lint

frontend-typecheck: ## Type-check the frontend
	$(FRONTEND_EXEC) npm run typecheck

check: lint typecheck test security frontend-lint frontend-typecheck ## Run every quality gate

# -----------------------------------------------------------------------------
# Worker diagnostics
# -----------------------------------------------------------------------------

worker-ping: ## Dispatch the worker health check through Redis and print the report
	@$(BACKEND_EXEC) python -m app.diagnostics.worker_ping

nmap-caps: ## Show the Nmap privilege model inside the worker container
	$(WORKER_EXEC) sh -c 'id; getcap /usr/bin/nmap; nmap --version | head -1'
