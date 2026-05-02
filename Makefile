export PATH := $(PATH):/usr/local/go/bin:$(HOME)/go/bin

.PHONY: up down migrate run-idp run-outbox-worker run-docs-api test tidy build fmt vet web-install web-dev web-build sonar-export
.PHONY: up-app down-app restart-app status-app logs-idp logs-outbox-worker logs-docs-api up-all down-all _wait-deps check-deps
.PHONY: dev-secrets dev-reset dev-key dev-user dev-fga dev-seed-alice dev-all dev-serve dev-up dev-down dev-status dev-logs oauth-url dev-flow check-deps-idp up-idp-only

up:
	docker compose up -d

down:
	docker compose down

# Idempotent migration runner. IdP schema only; OpenFGA manages its own schema.
migrate:
	@echo "==> applying IdP Postgres migrations"
	@for f in migrations/*.sql; do \
		echo "--> $$f"; \
		docker compose exec -T postgres-idp psql -v ON_ERROR_STOP=1 -U idp -d idp < "$$f" || exit 1; \
	done

run-idp:
	go run ./cmd/idp serve

run-outbox-worker:
	go run ./cmd/outbox-worker

run-docs-api:
	go run ./cmd/docs-api

test:
	@# web/node_modules contains a third-party package that ships a Go
	@# file (flatted) — `go test ./...` would walk into it. Explicitly
	@# target only our Go module roots.
	go test ./cmd/... ./internal/...

vet:
	go vet ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy

build:
	go build -o bin/idp ./cmd/idp
	go build -o bin/outbox-worker ./cmd/outbox-worker
	go build -o bin/docs-api ./cmd/docs-api

# --- web (Vite + React SPA) ---
web-install:
	cd web && npm install

web-dev:
	cd web && npm run dev

web-build:
	cd web && npm run build

# --- SonarCloud export ---
# Pulls every issue from the SonarCloud project into a local xlsx/csv
# for offline review. Reads SONAR_URL, SONAR_PROJECT_KEY, SONAR_TOKEN
# from env (set them in /tmp/idp-env, which is gitignored).
# See sonar/README.md for details. Override format with FMT=csv.
FMT ?= xlsx
sonar-export: sonar/.venv/bin/python
	cd sonar && .venv/bin/python sonar_export.py --format $(FMT)

# Lazy venv setup. Re-runs are no-ops once the marker file exists.
sonar/.venv/bin/python:
	@echo "==> creating sonar/.venv + installing requests pandas openpyxl"
	@python3 -m venv sonar/.venv
	@sonar/.venv/bin/pip install --quiet requests pandas openpyxl

# --- App process lifecycle (background) ---
# Same pattern as url-shortener. Three processes: idp, outbox-worker, docs-api.
# PID + log files under run/ (gitignored). Preserves graceful-shutdown path.

RUN_DIR := run
APPS    := idp outbox-worker docs-api

up-app: build check-deps
	@mkdir -p $(RUN_DIR)
	@for svc in $(APPS); do $(MAKE) --no-print-directory _start-proc NAME=$$svc; done
	@$(MAKE) --no-print-directory status-app

down-app:
	@for svc in $(APPS); do $(MAKE) --no-print-directory _stop-proc NAME=$$svc; done

restart-app: down-app up-app

status-app:
	@for svc in $(APPS); do \
		pidfile="$(RUN_DIR)/$$svc.pid"; \
		if [ -f "$$pidfile" ] && kill -0 $$(cat "$$pidfile") 2>/dev/null; then \
			echo "$$svc: running (pid $$(cat $$pidfile), log $(RUN_DIR)/$$svc.log)"; \
		else \
			echo "$$svc: stopped"; \
		fi; \
	done

logs-idp:             ; tail -f $(RUN_DIR)/idp.log
logs-outbox-worker:   ; tail -f $(RUN_DIR)/outbox-worker.log
logs-docs-api:        ; tail -f $(RUN_DIR)/docs-api.log

up-all: up _wait-deps up-app
down-all: down-app
	docker compose stop

# --- helpers ---

_start-proc:
	@pidfile="$(RUN_DIR)/$(NAME).pid"; \
	logfile="$(RUN_DIR)/$(NAME).log"; \
	if [ -f "$$pidfile" ] && kill -0 $$(cat "$$pidfile") 2>/dev/null; then \
		echo "$(NAME): already running (pid $$(cat $$pidfile))"; \
		exit 0; \
	fi; \
	rm -f "$$pidfile"; \
	nohup ./bin/$(NAME) > "$$logfile" 2>&1 & echo $$! > "$$pidfile"; \
	echo "$(NAME): started (pid $$(cat $$pidfile), log $$logfile)"

_stop-proc:
	@pidfile="$(RUN_DIR)/$(NAME).pid"; \
	if [ ! -f "$$pidfile" ]; then \
		echo "$(NAME): no pid file, skipping"; \
		exit 0; \
	fi; \
	pid=$$(cat "$$pidfile"); \
	if ! kill -0 $$pid 2>/dev/null; then \
		echo "$(NAME): stale pid file (pid $$pid not running), removing"; \
		rm -f "$$pidfile"; \
		exit 0; \
	fi; \
	kill -TERM $$pid; \
	for i in $$(seq 1 15); do \
		if ! kill -0 $$pid 2>/dev/null; then \
			echo "$(NAME): stopped (pid $$pid)"; \
			rm -f "$$pidfile"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "$(NAME): did not exit within 15s, SIGKILL"; \
	kill -KILL $$pid 2>/dev/null; \
	rm -f "$$pidfile"

check-deps:
	@for svc in postgres-idp postgres-fga openfga; do \
		status=$$(docker inspect --format='{{.State.Health.Status}}' identity-provider-$$svc-1 2>/dev/null || echo "missing"); \
		if [ "$$status" != "healthy" ]; then \
			echo "ERROR: compose service '$$svc' is '$$status' — run 'make up' and wait for deps to be healthy."; \
			exit 1; \
		fi; \
	done

# check-deps-idp is the narrower variant for dev-* targets: only the IdP's
# Postgres needs to be healthy. Layers 1–7 don't touch FGA; requiring
# postgres-fga + openfga here would force people running `make dev-all` to
# spin up services they don't need.
check-deps-idp:
	@status=$$(docker inspect --format='{{.State.Health.Status}}' identity-provider-postgres-idp-1 2>/dev/null || echo "missing"); \
	if [ "$$status" != "healthy" ]; then \
		echo "ERROR: postgres-idp is '$$status' — run 'make up-idp-only' (or 'make up' for full stack)."; \
		exit 1; \
	fi

# up-idp-only brings up just postgres-idp (the IdP's Postgres). Fast path
# for layer 1–7 work. The outbox worker (layer 8) will need the full stack
# via `make up`.
up-idp-only:
	docker compose up -d postgres-idp
	@echo "waiting for postgres-idp to be healthy..."
	@for i in $$(seq 1 30); do \
		status=$$(docker inspect --format='{{.State.Health.Status}}' identity-provider-postgres-idp-1 2>/dev/null || echo "missing"); \
		if [ "$$status" = "healthy" ]; then echo "postgres-idp healthy"; exit 0; fi; \
		sleep 1; \
	done; \
	echo "ERROR: postgres-idp did not become healthy within 30s"; exit 1

_wait-deps:
	@echo "waiting for compose services to be healthy..."
	@for i in $$(seq 1 60); do \
		all_healthy=true; \
		for svc in postgres-idp postgres-fga openfga; do \
			status=$$(docker inspect --format='{{.State.Health.Status}}' identity-provider-$$svc-1 2>/dev/null || echo "missing"); \
			if [ "$$status" != "healthy" ]; then all_healthy=false; break; fi; \
		done; \
		if [ "$$all_healthy" = "true" ]; then \
			echo "all deps healthy"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "ERROR: compose services did not become healthy within 60s"; \
	exit 1

# --- Dev commands ---
#
# Quick iteration on the IdP without hand-crafting SQL or remembering
# env shapes. Everything composes from the real CLI subcommands + psql;
# no hidden magic.
#
# Secrets (KEK + CSRF key) land in /tmp/idp-env which `make dev-serve`
# sources. /tmp is wiped on reboot — run `make dev-secrets FORCE=1` to
# regenerate, or `make dev-all` which regenerates if absent.
#
# `make dev-all` is the all-in-one: secrets + reset + seed key + seed user.
# After that, `make dev-serve` runs the IdP with everything ready.

DEV_ENV_FILE      := /tmp/idp-env
DEV_DATABASE_URL  := postgres://idp:idp@localhost:5434/idp?sslmode=disable
DEV_USER_EMAIL    := smoke-alice@example.com
DEV_USER_PASSWORD := correct-horse-battery-staple
DEV_CLIENT_ID     := localdev

# Write fresh KEK + CSRF keys to /tmp/idp-env. Idempotent: skipped if
# file exists unless FORCE=1 is set.
dev-secrets:
	@if [ -f "$(DEV_ENV_FILE)" ] && [ "$(FORCE)" != "1" ]; then \
		echo "$(DEV_ENV_FILE) exists (use FORCE=1 to regenerate)"; \
		exit 0; \
	fi; \
	kek=$$(head -c 32 /dev/urandom | xxd -p -c 64); \
	csrf=$$(head -c 32 /dev/urandom | xxd -p -c 64); \
	{ \
		echo "export DATABASE_URL=$(DEV_DATABASE_URL)"; \
		echo "export JWT_SIGNING_KEY_ENCRYPTION_KEY=$$kek"; \
		echo "export CSRF_KEY=$$csrf"; \
		echo "export ALLOWED_ORIGINS=http://localhost:5173"; \
	} > "$(DEV_ENV_FILE)"; \
	echo "wrote $(DEV_ENV_FILE)"

# Wipe test state from the IdP database. Keeps the schema.
# Re-seeds the localdev client so /authorize works afterward.
#
# Safe to re-run any time — truncates rows only. DOES delete signing
# keys; after reset you need `make dev-key` again (or `make dev-all`).
dev-reset: check-deps-idp
	@echo "==> truncating IdP state (keeps schema)"
	@docker compose exec -T postgres-idp psql -v ON_ERROR_STOP=1 -U idp -d idp -c "TRUNCATE TABLE authorization_codes, refresh_tokens, consents, sessions, signing_keys, fga_outbox, group_memberships, groups, users, clients RESTART IDENTITY CASCADE;"
	@echo "==> seeding localdev client"
	@docker compose exec -T postgres-idp psql -v ON_ERROR_STOP=1 -U idp -d idp < scripts/seed_client.sql
	@echo "ok"

# Generate + activate a signing key IF none is currently active.
# Idempotent: no-op when an active key exists.
dev-key: build check-deps-idp
	@. "$(DEV_ENV_FILE)" 2>/dev/null && { \
		active=$$(./bin/idp keys list 2>/dev/null | awk '$$3=="active" {print $$1; exit}'); \
		if [ -n "$$active" ]; then \
			echo "active key already present: $$active"; \
			exit 0; \
		fi; \
		pending=$$(./bin/idp keys list 2>/dev/null | awk '$$3=="pending" {print $$1; exit}'); \
		if [ -z "$$pending" ]; then \
			./bin/idp keys generate; \
			pending=$$(./bin/idp keys list 2>/dev/null | awk '$$3=="pending" {print $$1; exit}'); \
		fi; \
		./bin/idp keys activate "$$pending"; \
	} || { echo "ERROR: make sure $(DEV_ENV_FILE) exists (run: make dev-secrets)"; exit 1; }

# Create the default dev user. Idempotent — skips if the email already exists.
dev-user: build check-deps-idp
	@. "$(DEV_ENV_FILE)" 2>/dev/null && { \
		if ./bin/idp users list 2>/dev/null | grep -q "$(DEV_USER_EMAIL)"; then \
			echo "user $(DEV_USER_EMAIL) already exists"; \
			exit 0; \
		fi; \
		./bin/idp users create "$(DEV_USER_EMAIL)" "$(DEV_USER_PASSWORD)"; \
	} || { echo "ERROR: make sure $(DEV_ENV_FILE) exists (run: make dev-secrets)"; exit 1; }

# Initialize OpenFGA store + authorization model. Idempotent: if
# OPENFGA_STORE_ID is already in the env file, skip. Otherwise run
# `idp fga init` and append the printed lines (with `export ` prefix
# so shells source them).
dev-fga: build check-deps-idp
	@if grep -q '^export OPENFGA_STORE_ID=' "$(DEV_ENV_FILE)" 2>/dev/null; then \
		echo "OPENFGA_STORE_ID already in $(DEV_ENV_FILE) (use FORCE=1 to recreate)"; \
		exit 0; \
	fi; \
	. "$(DEV_ENV_FILE)" && ./bin/idp fga init \
		| grep -E '^\s*export OPENFGA_(STORE_ID|AUTHORIZATION_MODEL_ID)=' \
		| sed 's/^[[:space:]]*//' >> "$(DEV_ENV_FILE)"; \
	echo "wrote OPENFGA_STORE_ID + OPENFGA_AUTHORIZATION_MODEL_ID to $(DEV_ENV_FILE)"

# Append DOCS_SEED_ALICE=<alice's UUID> to the env file. Idempotent.
# docs-api reads this to seed FGA tuples that grant alice access to the
# demo doc/folder corpus.
dev-seed-alice: build check-deps-idp
	@if grep -q '^export DOCS_SEED_ALICE=' "$(DEV_ENV_FILE)" 2>/dev/null; then \
		echo "DOCS_SEED_ALICE already in $(DEV_ENV_FILE)"; \
		exit 0; \
	fi; \
	alice=$$(docker compose exec -T postgres-idp psql -U idp -d idp -tAc \
		"SELECT id FROM users WHERE email='$(DEV_USER_EMAIL)'" 2>/dev/null | tr -d '[:space:]'); \
	if [ -z "$$alice" ]; then \
		echo "ERROR: $(DEV_USER_EMAIL) not found in DB (run: make dev-user)"; \
		exit 1; \
	fi; \
	echo "export DOCS_SEED_ALICE=$$alice" >> "$(DEV_ENV_FILE)"; \
	echo "wrote DOCS_SEED_ALICE=$$alice to $(DEV_ENV_FILE)"

# All-in-one: secrets + reset + key + user + FGA + alice seed. The
# "I haven't touched this in a week, just make it work" button.
dev-all: dev-secrets dev-reset dev-key dev-user dev-fga dev-seed-alice
	@echo
	@echo "=== dev environment ready ==="
	@echo "  user:     $(DEV_USER_EMAIL)"
	@echo "  password: $(DEV_USER_PASSWORD)"
	@echo "  client:   $(DEV_CLIENT_ID)"
	@echo
	@echo "next: make dev-up      (background all 3 Go services + Vite)"
	@echo "      make dev-serve   (foreground IdP only — for debugging)"
	@echo "      make oauth-url   (print a ready-to-paste /authorize URL)"
	@echo "      make dev-flow    (drive the full auth-code flow via curl)"

# Run the IdP in the foreground with env from /tmp/idp-env.
# (Use dev-up for backgrounded operation of all four services.)
dev-serve: build check-deps-idp
	@. "$(DEV_ENV_FILE)" && ./bin/idp serve

# --- backgrounded-all-services dev loop ---
#
# `make dev-up` backgrounds idp + outbox-worker + docs-api + vite, with
# logs in /tmp/idp-{idp,outbox,docs,web}.log and PIDs in /tmp/idp-*.pid.
# `make dev-down` kills them. `make dev-status` shows what's running.
# `make dev-logs SVC=docs` tails one of the four logs.
#
# Foreground stays available via `make dev-serve` (idp only) for
# debugging — when you want a crash to be obvious in your terminal.

DEV_LOG_DIR := /tmp
DEV_PIDS    := $(DEV_LOG_DIR)/idp-idp.pid $(DEV_LOG_DIR)/idp-outbox.pid $(DEV_LOG_DIR)/idp-docs.pid $(DEV_LOG_DIR)/idp-web.pid

dev-up: build dev-secrets dev-fga dev-seed-alice
	@if [ ! -d web/node_modules ]; then \
		echo "==> web/node_modules missing — running web-install"; \
		$(MAKE) web-install; \
	fi
	@echo "==> starting backgrounded services (logs in $(DEV_LOG_DIR)/idp-*.log)"
	@. "$(DEV_ENV_FILE)" && nohup ./bin/idp serve > $(DEV_LOG_DIR)/idp-idp.log 2>&1 & echo $$! > $(DEV_LOG_DIR)/idp-idp.pid
	@. "$(DEV_ENV_FILE)" && nohup ./bin/outbox-worker > $(DEV_LOG_DIR)/idp-outbox.log 2>&1 & echo $$! > $(DEV_LOG_DIR)/idp-outbox.pid
	@. "$(DEV_ENV_FILE)" && \
		TRUSTED_ISSUERS=http://localhost:8080 \
		REQUIRED_AUD=docs-api \
		ALLOWED_ORIGINS=http://localhost:5173 \
		nohup ./bin/docs-api > $(DEV_LOG_DIR)/idp-docs.log 2>&1 & \
		echo $$! > $(DEV_LOG_DIR)/idp-docs.pid
	@cd web && nohup npm run dev > $(DEV_LOG_DIR)/idp-web.log 2>&1 & echo $$! > $(DEV_LOG_DIR)/idp-web.pid
	@sleep 1
	@echo
	@echo "=== services ==="
	@echo "  idp           :8080  (log: $(DEV_LOG_DIR)/idp-idp.log)"
	@echo "  outbox-worker        (log: $(DEV_LOG_DIR)/idp-outbox.log)"
	@echo "  docs-api      :8083  (log: $(DEV_LOG_DIR)/idp-docs.log)"
	@echo "  web (vite)    :5173  (log: $(DEV_LOG_DIR)/idp-web.log)"
	@echo
	@echo "  browser:  http://localhost:5173"
	@echo "  user:     $(DEV_USER_EMAIL) / $(DEV_USER_PASSWORD)"
	@echo
	@echo "  make dev-status   — check what's running"
	@echo "  make dev-logs SVC=idp|outbox|docs|web   — tail one log"
	@echo "  make dev-down     — stop everything"

dev-down:
	@for pidfile in $(DEV_PIDS); do \
		if [ -f "$$pidfile" ]; then \
			pid=$$(cat "$$pidfile"); \
			if kill -0 "$$pid" 2>/dev/null; then \
				echo "stopping $$pidfile (pid $$pid)"; \
				kill "$$pid" 2>/dev/null || true; \
			fi; \
			rm -f "$$pidfile"; \
		fi; \
	done

dev-status:
	@for pidfile in $(DEV_PIDS); do \
		name=$$(basename "$$pidfile" .pid | sed 's/^idp-//'); \
		if [ -f "$$pidfile" ] && kill -0 "$$(cat $$pidfile)" 2>/dev/null; then \
			printf "  %-10s  RUNNING  pid=%s\n" "$$name" "$$(cat $$pidfile)"; \
		else \
			printf "  %-10s  stopped\n" "$$name"; \
		fi; \
	done

dev-logs:
	@if [ -z "$(SVC)" ]; then \
		echo "usage: make dev-logs SVC=idp|outbox|docs|web"; \
		exit 1; \
	fi; \
	tail -f $(DEV_LOG_DIR)/idp-$(SVC).log

# Print a ready-to-paste /authorize URL with a fresh PKCE challenge.
# Prints the code_verifier too — you'll need it when exchanging the
# code for a token at /token.
oauth-url:
	@verifier=$$(head -c 32 /dev/urandom | base64 | tr -d '=/+' | head -c 43); \
	challenge=$$(printf "%s" "$$verifier" | openssl dgst -binary -sha256 | base64 | tr -d '=' | tr '+/' '-_'); \
	state=$$(head -c 12 /dev/urandom | xxd -p); \
	nonce=$$(head -c 12 /dev/urandom | xxd -p); \
	echo "# code_verifier (keep for /token exchange):"; \
	echo "$$verifier"; \
	echo; \
	echo "# /authorize URL (paste into browser):"; \
	echo "http://localhost:8080/authorize?response_type=code&client_id=$(DEV_CLIENT_ID)&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback&scope=openid+read%3Adocs&state=$$state&code_challenge=$$challenge&code_challenge_method=S256&nonce=$$nonce"

# Drive the full auth-code flow via curl: GET /authorize → /login →
# POST /login → back to /authorize → /consent → POST approve →
# back to /authorize → redirect to client with code.
#
# Requires: IdP running (make dev-serve in another terminal).
# Captures cookies in a jar so session + CSRF work across requests.
dev-flow:
	@echo "=== driving OAuth auth-code flow via curl ==="
	@scripts/dev_flow.sh
