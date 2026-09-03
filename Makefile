.DEFAULT_GOAL := help
SHELL := /bin/bash

COMPOSE ?= docker compose
PYTHON  ?= python3
VENV_BIN ?= .venv/bin
VENV_PYTHON ?= $(VENV_BIN)/python
RUFF ?= $(VENV_BIN)/ruff
MYPY ?= $(VENV_BIN)/mypy
PYTEST ?= $(VENV_BIN)/pytest

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Local development (outside containers)
# ---------------------------------------------------------------------------
.PHONY: venv
venv: ## Create a local virtualenv and install dev dependencies
	$(PYTHON) -m venv .venv
	./.venv/bin/pip install --upgrade pip
	./.venv/bin/pip install -r requirements-dev.txt
	./.venv/bin/pip install -e .

.PHONY: lint
lint: ## Run ruff lint and format checks
	$(RUFF) check src tests scripts migrations
	$(RUFF) format --check src tests scripts migrations

.PHONY: format
format: ## Auto-format the codebase
	$(RUFF) format src tests scripts migrations
	$(RUFF) check --fix src tests scripts migrations

.PHONY: typecheck
typecheck: ## Run mypy in strict mode
	$(MYPY)

.PHONY: test
test: ## Run the unit test suite (no external dependencies required)
	$(PYTEST) -m "not integration and not live_ollama"

.PHONY: test-all
test-all: ## Run every test, including integration (requires a live database)
	ACOP_TEST_DATABASE=1 $(PYTEST)

.PHONY: check
check: lint typecheck test ## Lint, typecheck and unit test

# ---------------------------------------------------------------------------
# Stack lifecycle
# ---------------------------------------------------------------------------
.PHONY: up
up: ## Build and start the stack
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop the stack, keeping data
	$(COMPOSE) down

.PHONY: destroy
destroy: ## Stop the stack AND DELETE THE DATABASE VOLUME
	@echo "This deletes the acop postgres volume and all data in it."
	@read -p "Type 'destroy' to confirm: " confirm && [ "$$confirm" = "destroy" ]
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Follow API logs
	$(COMPOSE) logs -f api

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) ps

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
.PHONY: migrate
migrate: ## Apply database migrations
	$(COMPOSE) run --rm migrate

.PHONY: migration
migration: ## Generate a migration: make migration m="add asset table"
	@[ -n "$(m)" ] || (echo "Usage: make migration m=\"description\"" && exit 1)
	alembic revision --autogenerate -m "$(m)"

.PHONY: db-shell
db-shell: ## Open psql against the running database
	$(COMPOSE) exec postgres psql -U $${ACOP_POSTGRES_USER:-acop} -d $${ACOP_POSTGRES_DB:-acop}

# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
.PHONY: health
health: ## Print the health report from the running API
	@curl -s http://127.0.0.1:$${ACOP_API_PUBLISHED_PORT:-8000}/health?fresh=true \
		| $(PYTHON) -m json.tool

.PHONY: check-qwen
check-qwen: ## Run a real inference round-trip against the configured model
	$(VENV_PYTHON) scripts/check_qwen.py

.PHONY: verify
verify: ## Full Milestone 1 acceptance check against a running stack
	$(VENV_PYTHON) scripts/verify_milestone1.py
