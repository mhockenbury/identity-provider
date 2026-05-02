export PATH := $(PATH):/usr/local/go/bin:$(HOME)/go/bin

.PHONY: up down migrate migrate-docs test tidy build fmt vet web-install web-dev web-build sonar-export
.PHONY: dev-secrets dev-reset dev-key dev-user dev-fga dev-grant dev-all dev-serve dev-up dev-down dev-status dev-logs dev-tail oauth-url dev-flow check-deps-idp up-idp-only

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

# Goose-driven migrations for postgres-docs. Tracks applied versions in
# the goose_db_version table so re-running is idempotent.
DOCS_DSN := postgres://docs:docs@localhost:5435/docs?sslmode=disable

migrate-docs:
	@command -v goose >/dev/null || { \
		echo "ERROR: goose not found — install: go install github.com/pressly/goose/v3/cmd/goose@latest"; \
		exit 1; \
	}
	@echo "==> applying docs-api migrations (goose)"
	@goose -dir cmd/docs-api/migrations postgres "$(DOCS_DSN)" up

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

# check-deps-idp is the narrower dep-check used by dev-* targets: only
# the IdP's Postgres needs to be healthy. Layers 1–7 don't touch FGA;
# requiring postgres-fga + openfga here would force people running
# `make dev-all` to spin up services they don't need.
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
# Stable UUID for the dev user. Pinned so seeded FGA tuples + tests
# don't drift across `make dev-reset`. Production user creation does
# not pin UUIDs — only this dev seed path uses --id.
DEV_USER_ID       := aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
# IDs from cmd/docs-api/migrations/0002_seed.sql (and seed_ids.go).
DEV_FOLDER_PUBLIC      := 11111111-1111-1111-1111-000000000003
DEV_FOLDER_ENGINEERING := 11111111-1111-1111-1111-000000000001
DEV_DOC_PRIVATE        := 22222222-2222-2222-2222-000000000005

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
		echo "export LOG_LEVEL=debug"; \
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

# Create the default dev user with a stable, hardcoded UUID. Pinning the
# UUID lets seed grants (dev-grant) and integration tests reference alice
# without re-discovering her ID after every dev-reset.
dev-user: build check-deps-idp
	@. "$(DEV_ENV_FILE)" 2>/dev/null && { \
		if ./bin/idp users list 2>/dev/null | grep -q "$(DEV_USER_EMAIL)"; then \
			echo "user $(DEV_USER_EMAIL) already exists"; \
			exit 0; \
		fi; \
		./bin/idp users create "$(DEV_USER_EMAIL)" "$(DEV_USER_PASSWORD)" --id "$(DEV_USER_ID)"; \
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

# Grant alice the seeded-corpus permissions. Calls `docs-api grant`
# directly — service boundary stays clean (no envvar for "alice's UUID";
# the IdP and docs-api don't need to share that). Idempotent because
# FGA Write with OnDuplicateWrites=ignore is a no-op on existing tuples.
#
# Defaults:
#   • viewer on Public folder      — alice can read public docs
#   • editor on Engineering folder — alice can edit eng docs
#   • owner  on Private Notes      — alice can do anything to one doc
dev-grant: build
	@. "$(DEV_ENV_FILE)" && \
		./bin/docs-api grant $(DEV_USER_ID) viewer folder:$(DEV_FOLDER_PUBLIC) && \
		./bin/docs-api grant $(DEV_USER_ID) editor folder:$(DEV_FOLDER_ENGINEERING) && \
		./bin/docs-api grant $(DEV_USER_ID) owner  document:$(DEV_DOC_PRIVATE)

# All-in-one: secrets + reset + key + user + FGA + grants. The
# "I haven't touched this in a week, just make it work" button.
#
# migrate-docs runs before dev-grant so the seeded folder/document IDs
# the grants reference actually exist in postgres-docs.
dev-all: dev-secrets dev-reset dev-key dev-user dev-fga migrate-docs dev-grant
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

dev-up: build dev-secrets migrate-docs dev-fga dev-grant
	@if [ ! -d web/node_modules ]; then \
		echo "==> web/node_modules missing — running web-install"; \
		$(MAKE) web-install; \
	fi
	@echo "==> starting backgrounded services (logs in $(DEV_LOG_DIR)/idp-*.log)"
	@# Each service launched via `setsid` so the recorded PID is also a
	@# process-group leader. `dev-down` then signals the whole group,
	@# which catches Vite's child processes (esbuild workers, the real
	@# vite binary spawned by `npm run dev`) that would otherwise orphan.
	@. "$(DEV_ENV_FILE)" && LOG_FORMAT=pretty setsid ./bin/idp serve > $(DEV_LOG_DIR)/idp-idp.log 2>&1 < /dev/null & echo $$! > $(DEV_LOG_DIR)/idp-idp.pid
	@. "$(DEV_ENV_FILE)" && LOG_FORMAT=pretty setsid ./bin/outbox-worker > $(DEV_LOG_DIR)/idp-outbox.log 2>&1 < /dev/null & echo $$! > $(DEV_LOG_DIR)/idp-outbox.pid
	@. "$(DEV_ENV_FILE)" && \
		TRUSTED_ISSUERS=http://localhost:8080 \
		REQUIRED_AUD=docs-api \
		ALLOWED_ORIGINS=http://localhost:5173 \
		LOG_FORMAT=pretty \
		setsid ./bin/docs-api > $(DEV_LOG_DIR)/idp-docs.log 2>&1 < /dev/null & \
		echo $$! > $(DEV_LOG_DIR)/idp-docs.pid
	@cd web && setsid npm run dev > $(DEV_LOG_DIR)/idp-web.log 2>&1 < /dev/null & echo $$! > $(DEV_LOG_DIR)/idp-web.pid
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
	@# Recorded PID is also the process-group leader (we used setsid in
	@# dev-up). Two-phase kill: SIGTERM the whole group for graceful
	@# shutdown, sleep a beat, then SIGKILL anything still alive. The
	@# kill-the-group form (-pgid) catches Vite's `node vite` child even
	@# when the npm wrapper exits before forwarding signals.
	@# Enumerate all members of each process group BEFORE signaling. Once
	@# the group leader exits (npm in particular exits quickly on SIGTERM),
	@# Linux stops accepting `kill -- -pgid` even if other members of the
	@# group are still alive. So: list members via `pgrep -g`, then send
	@# the signal directly to each PID.
	@for pidfile in $(DEV_PIDS); do \
		if [ -f "$$pidfile" ]; then \
			p=$$(cat "$$pidfile"); \
			if kill -0 "$$p" 2>/dev/null; then \
				members=$$(pgrep -g "$$p" 2>/dev/null | tr '\n' ' '); \
				echo "stopping $$pidfile (pgid $$p, members: $$members)"; \
				echo "$$members" | xargs -r kill -TERM 2>/dev/null || :; \
			fi; \
			rm -f "$$pidfile"; \
		fi; \
	done
	@# Belt-and-suspenders: catch Go binaries whose PID file got out of
	@# sync (e.g. from a half-failed dev-up). pgrep -x is exact-match
	@# on the basename, so this won't match make/sh wrapper processes.
	@# We don't auto-clean orphan vite here because the obvious argv
	@# pattern (node + path-to-vite) also matches make's own recipe
	@# shell. If vite ever survives despite the group-kill above, run
	@# `pkill -f node.*/web/node_modules/.bin/vite` from a real shell.
	@for binname in idp outbox-worker docs-api; do \
		pids=$$(pgrep -x "$$binname" 2>/dev/null || true); \
		if [ -n "$$pids" ]; then \
			echo "stopping orphan $$binname (pids $$pids)"; \
			kill $$pids 2>/dev/null || :; \
		fi; \
	done
	@:

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

# Tail all four service logs in a tmux 2x2 grid. Each pane runs
# `tail -f` on one of the log files; tint colors render natively.
# Ctrl-B then arrows to navigate panes, Ctrl-B [ for scrollback,
# Ctrl-B d to detach (services keep running), Ctrl-B & to kill the
# session.
#
# Reuses an existing session if one is already attached.
DEV_TAIL_SESSION := idp-dev

dev-tail:
	@command -v tmux >/dev/null || { \
		echo "ERROR: tmux not found — run: sudo apt install tmux"; \
		exit 1; \
	}
	@if tmux has-session -t $(DEV_TAIL_SESSION) 2>/dev/null; then \
		tmux attach -t $(DEV_TAIL_SESSION); \
	else \
		tmux new-session -d -s $(DEV_TAIL_SESSION) -n logs \
			"tail -fn 200 $(DEV_LOG_DIR)/idp-idp.log"; \
		tmux split-window  -h -t $(DEV_TAIL_SESSION):logs \
			"tail -fn 200 $(DEV_LOG_DIR)/idp-outbox.log"; \
		tmux split-window  -v -t $(DEV_TAIL_SESSION):logs.0 \
			"tail -fn 200 $(DEV_LOG_DIR)/idp-docs.log"; \
		tmux split-window  -v -t $(DEV_TAIL_SESSION):logs.2 \
			"tail -fn 200 $(DEV_LOG_DIR)/idp-web.log"; \
		tmux select-layout -t $(DEV_TAIL_SESSION):logs tiled; \
		tmux set-option -t $(DEV_TAIL_SESSION) -g pane-border-status top; \
		tmux set-option -t $(DEV_TAIL_SESSION) -g pane-border-format " #{pane_index}: #{pane_current_command} #{pane_title} "; \
		tmux select-pane -t $(DEV_TAIL_SESSION):logs.0 -T "idp"; \
		tmux select-pane -t $(DEV_TAIL_SESSION):logs.1 -T "docs"; \
		tmux select-pane -t $(DEV_TAIL_SESSION):logs.2 -T "outbox"; \
		tmux select-pane -t $(DEV_TAIL_SESSION):logs.3 -T "web"; \
		tmux attach -t $(DEV_TAIL_SESSION); \
	fi

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
