.DEFAULT_GOAL := help

VENV ?= .venv
PY   ?= python

.PHONY: help install test test-fast run-file run-dir stats sources init-db db-up db-down clean verify \
        kafka-up kafka-down topics produce consume stream \
        mitre-index mitre-index-full correlate findings analyze \
        analytics api ui test-api

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime + dev dependencies (torch wheels are big; prefer a venv)
	pip install -r requirements-dev.txt

test: ## Run the full test suite
	pytest -q

test-fast: ## Run tests excluding PostgreSQL-integration cases (no DB required)
	pytest -q -m "not pg_integration"

# -------------------------------- Phase 1-2: pipeline + db ------------------
run-file: ## Process the CloudTrail sample file
	$(PY) -m app.cli process-file sample_logs/cloudtrail.json

run-dir: ## Process the whole sample_logs directory
	$(PY) -m app.cli process-dir sample_logs/

stats: ## Show stored-event statistics
	$(PY) -m app.cli stats

sources: ## List configured log sources
	$(PY) -m app.cli list-sources

init-db: ## Apply db/schema.sql to PostgreSQL
	$(PY) -m app.cli init-db

db-up: ## Start PostgreSQL via Docker Compose
	docker compose up -d postgres

db-down: ## Stop local containers (keep volumes)
	docker compose down

verify: ## deterministic verify: py_compile all modified packages + pytest
	$(PY) -m py_compile $$(find app db spark_jobs scripts -name '*.py') && pytest -q

# -------------------------------- Phase 3: Kafka ----------------------------
kafka-up: ## Start Kafka (and postgres) via Docker Compose
	docker compose up -d postgres kafka

kafka-down: ## Stop Kafka
	docker compose stop kafka

topics: ## List Kafka topics (broker must be running)
	docker compose exec kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list

produce: ## Publish the sample logs to the security-logs topic (--repeat 3 for demo)
	$(PY) scripts/produce_sample_logs.py --repeat 3

consume: ## Drain the Kafka topic through the pipeline (bounded demo)
	$(PY) -m app.cli kafka-consumer --max-messages 300

stream: ## Follow the Kafka topic continuously (production mode; Ctrl+C to stop)
	$(PY) -m app.cli kafka-consumer --continuous

# -------------------------------- Phase 5-6: MITRE RAG + analysis -----------
mitre-index: ## Build the offline MITRE index (builtin 14 techniques, hashing backend)
	$(PY) -m app.cli build-mitre-index --source builtin --embedder hashing

mitre-index-full: ## Build the full index from the official STIX bundle (~60MB download, MiniLM backend)
	$(PY) -m app.cli build-mitre-index --source auto

correlate: ## Re-run the correlation engine over all stored events
	$(PY) -m app.cli correlate

findings: ## List recent security findings (add --verdict malicious)
	$(PY) -m app.cli findings --limit 20

analyze: ## Analyze one stored event: make analyze UID=<uid>
	$(PY) -m app.cli analyze-event $(UID)

# -------------------------------- Phase 4: Spark analytics ------------------
analytics: ## Run PySpark analytics over data/output -> analytics_output/
	$(PY) -m app.cli analytics

# -------------------------------- Phase 7: API + dashboard ------------------
api: ## Serve the FastAPI app + dashboard on :8000
	$(PY) -m uvicorn app.api.main:app --host 0.0.0.0 --port 8000

ui: api ## Alias for api

test-api: ## Quick smoke of the running API (requires `make api` running)
	@curl -s localhost:8000/api/v1/health | $(PY) -m json.tool
	@curl -s 'localhost:8000/api/v1/findings?limit=3' | $(PY) -m json.tool | head -40

# -------------------------------- misc --------------------------------------
clean: ## Remove generated data (output/state/errors/analytics) - keeps config + sample logs
	rm -rf data/output data/state analytics_output
