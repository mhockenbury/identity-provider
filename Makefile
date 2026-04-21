export PATH := $(PATH):/usr/local/go/bin:$(HOME)/go/bin

.PHONY: up down migrate run-idp run-outbox-worker run-demo-api test tidy build fmt vet
.PHONY: up-app down-app restart-app status-app logs-idp logs-outbox-worker logs-demo-api up-all down-all _wait-deps check-deps

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
	go run ./cmd/idp

run-outbox-worker:
	go run ./cmd/outbox-worker

run-demo-api:
	go run ./cmd/demo-api

test:
	go test ./...

vet:
	go vet ./...

fmt:
	go fmt ./...

tidy:
	go mod tidy

build:
	go build -o bin/idp ./cmd/idp
	go build -o bin/outbox-worker ./cmd/outbox-worker
	go build -o bin/demo-api ./cmd/demo-api

# --- App process lifecycle (background) ---
# Same pattern as url-shortener. Three processes: idp, outbox-worker, demo-api.
# PID + log files under run/ (gitignored). Preserves graceful-shutdown path.

RUN_DIR := run
APPS    := idp outbox-worker demo-api

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
logs-demo-api:        ; tail -f $(RUN_DIR)/demo-api.log

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
