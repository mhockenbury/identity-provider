// The idp binary hosts both the HTTP server and the admin CLI.
//
// Subcommands:
//   idp serve                                       — run the OIDC HTTP server
//   idp keys generate                               — create a new PENDING signing key
//   idp keys list                                   — show all signing keys with status
//   idp keys activate <kid>                         — transition PENDING → ACTIVE
//   idp keys retire   <kid>                         — transition ACTIVE → RETIRED
//   idp users create <email> <pass>                 — create a user (argon2id-hashed password)
//   idp users list                                  — list all users
//   idp groups create <name>                        — create a group
//   idp groups list                                  — list all groups
//   idp groups add-member <group> <user-email>       — add user to group (enqueues outbox event)
//   idp groups remove-member <group> <user-email>    — remove user from group (enqueues outbox event)
//   idp groups list-members <group>                  — list members of a group
//   idp fga init                                      — bootstrap: create OpenFGA store + upload auth model
//                                                       prints OPENFGA_STORE_ID + OPENFGA_AUTHORIZATION_MODEL_ID
//   idp outbox list [--pending|--failed|--all]         — inspect fga_outbox rows (default: --pending)
//   idp outbox retry <id>                              — reset attempt_count + clear last_error on a row
//   idp outbox purge <id> [--force]                    — delete an outbox row (refuses pending rows unless --force)
//
// Env vars:
//   DATABASE_URL                     required; e.g. postgres://idp:idp@localhost:5434/idp?sslmode=disable
//   JWT_SIGNING_KEY_ENCRYPTION_KEY   required for keys subcommand + serve; 64 hex chars
//   CSRF_KEY                         required for serve; 64 hex chars
//   ISSUER_URL                       serve only; issuer string baked into tokens (default http://localhost:8080)
//   ALLOWED_ORIGINS                  serve only; comma-separated CORS origins for /.well-known/*, /token, /userinfo
//   HTTP_ADDR                        serve only; listen address (default :8080)
//   SHUTDOWN_GRACE                   serve only; drain window on SIGTERM (default 15s)
//   LOG_LEVEL                        debug|info|warn|error (default info)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	nethttp "net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/clients"
	"github.com/mhockenbury/identity-provider/internal/consent"
	"github.com/mhockenbury/identity-provider/internal/fga"
	myhttp "github.com/mhockenbury/identity-provider/internal/http"
	"github.com/mhockenbury/identity-provider/internal/oauth"
	"github.com/mhockenbury/identity-provider/internal/oidc"
	"github.com/mhockenbury/identity-provider/internal/outbox"
	"github.com/mhockenbury/identity-provider/internal/tokens"
	"github.com/mhockenbury/identity-provider/internal/users"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return usageErr("no subcommand")
	}

	switch args[0] {
	case "serve":
		return runServe()
	case "keys":
		return runKeys(args[1:])
	case "users":
		return runUsers(args[1:])
	case "groups":
		return runGroups(args[1:])
	case "fga":
		return runFGA(args[1:])
	case "outbox":
		return runOutbox(args[1:])
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return usageErr(fmt.Sprintf("unknown subcommand %q", args[0]))
	}
}

// runFGA handles the `idp fga` subcommands. Today: init. Future stretch:
// update-model (deploy a new model version), list-stores, etc.
func runFGA(args []string) error {
	if len(args) < 1 {
		return usageErr("fga: no subcommand")
	}

	switch args[0] {
	case "init":
		return runFGAInit()
	default:
		return usageErr(fmt.Sprintf("fga: unknown subcommand %q", args[0]))
	}
}

// runFGAInit creates a new OpenFGA store, uploads the authorization
// model, and prints both IDs. The operator copies them into .env
// (OPENFGA_STORE_ID + OPENFGA_AUTHORIZATION_MODEL_ID) for the worker
// + docs-api to use.
//
// Idempotency note: this IS NOT idempotent. Each call creates a NEW
// store and a NEW model. For the lab that's fine (you run this once
// per fresh compose-up). A production-grade version would check
// OPENFGA_STORE_ID and only create if absent. We add that in 8f when
// `make dev-all` wants to be idempotent across reruns.
func runFGAInit() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	apiURL := envOr("OPENFGA_API_URL", "http://localhost:8081")

	c, err := fga.NewClient(fga.Config{
		APIURL: apiURL,
	})
	if err != nil {
		return fmt.Errorf("build FGA client: %w", err)
	}

	storeID, err := fga.CreateStore(ctx, c, "identity-provider")
	if err != nil {
		return fmt.Errorf("create store: %w", err)
	}
	fmt.Printf("created store: %s\n", storeID)

	// Re-build the client with the store bound so WriteAuthorizationModel
	// knows which store to target. The SDK uses the StoreId field from
	// the ClientConfiguration, not from the method call.
	c, err = fga.NewClient(fga.Config{
		APIURL:  apiURL,
		StoreID: storeID,
	})
	if err != nil {
		return fmt.Errorf("rebuild client with store id: %w", err)
	}

	modelID, err := fga.UploadModelFromDSL(ctx, c, fga.ModelDSL())
	if err != nil {
		return fmt.Errorf("upload model: %w", err)
	}
	fmt.Printf("uploaded authorization model: %s\n", modelID)

	fmt.Println()
	fmt.Println("add these to /tmp/idp-env (or your .env):")
	fmt.Printf("  export OPENFGA_STORE_ID=%s\n", storeID)
	fmt.Printf("  export OPENFGA_AUTHORIZATION_MODEL_ID=%s\n", modelID)
	return nil
}

// --- outbox admin ---
//
// `idp outbox` is the operator's view into fga_outbox. It doesn't run the
// worker (that's cmd/outbox-worker); it just lets you inspect and nudge
// rows when something goes wrong.
//
//	idp outbox list [--pending|--failed|--all]  (default: --pending)
//	idp outbox retry <id>                        reset attempt_count+last_error
//	idp outbox purge <id>                        delete a row permanently
//
// All three read DATABASE_URL from env.

func runOutbox(args []string) error {
	if len(args) < 1 {
		return usageErr("outbox: no subcommand")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL not set")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("pgxpool.New: %w", err)
	}
	defer pool.Close()

	switch args[0] {
	case "list":
		return runOutboxList(ctx, pool, args[1:])
	case "retry":
		if len(args) < 2 {
			return usageErr("outbox retry: need <id>")
		}
		return runOutboxRetry(ctx, pool, args[1])
	case "purge":
		return runOutboxPurge(ctx, pool, args[1:])
	default:
		return usageErr(fmt.Sprintf("outbox: unknown subcommand %q", args[0]))
	}
}

// runOutboxList prints outbox rows in a tab-aligned table. The filter
// selects which rows to show; default is --pending (unprocessed,
// attempt_count below the retry ceiling — the set the worker would claim).
// --failed shows rows that hit the ceiling (poison pills). --all shows
// everything including already-processed rows.
func runOutboxList(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	filter := "pending"
	if len(args) > 0 {
		switch args[0] {
		case "--pending":
			filter = "pending"
		case "--failed":
			filter = "failed"
		case "--all":
			filter = "all"
		default:
			return usageErr(fmt.Sprintf("outbox list: unknown flag %q (want --pending|--failed|--all)", args[0]))
		}
	}

	// The retry ceiling is the worker's OUTBOX_MAX_ATTEMPTS — we read it
	// the same way the worker does so the admin view matches what the
	// worker is actually claiming. Default 5 matches cmd/outbox-worker.
	maxAttempts := 5
	if v := os.Getenv("OUTBOX_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxAttempts = n
		}
	}

	var q string
	var qArgs []any
	switch filter {
	case "pending":
		q = `SELECT id, event_type, payload, created_at, processed_at, attempt_count, last_error
		     FROM fga_outbox
		     WHERE processed_at IS NULL AND attempt_count < $1
		     ORDER BY id`
		qArgs = []any{maxAttempts}
	case "failed":
		q = `SELECT id, event_type, payload, created_at, processed_at, attempt_count, last_error
		     FROM fga_outbox
		     WHERE processed_at IS NULL AND attempt_count >= $1
		     ORDER BY id`
		qArgs = []any{maxAttempts}
	case "all":
		q = `SELECT id, event_type, payload, created_at, processed_at, attempt_count, last_error
		     FROM fga_outbox
		     ORDER BY id`
	}

	rows, err := pool.Query(ctx, q, qArgs...)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tSTATUS\tATTEMPTS\tCREATED\tPAYLOAD\tLAST_ERROR")
	count := 0
	for rows.Next() {
		var (
			id           int64
			eventType    string
			payload      []byte
			createdAt    time.Time
			processedAt  *time.Time
			attemptCount int
			lastError    *string
		)
		if err := rows.Scan(&id, &eventType, &payload, &createdAt, &processedAt, &attemptCount, &lastError); err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		status := "pending"
		if processedAt != nil {
			status = "processed"
		} else if attemptCount >= maxAttempts {
			status = "failed"
		}

		errStr := ""
		if lastError != nil {
			errStr = truncate(*lastError, 60)
		}

		fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\t%s\n",
			id, eventType, status, attemptCount,
			createdAt.Format(time.RFC3339),
			truncate(string(payload), 60),
			errStr,
		)
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate: %w", err)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if count == 0 {
		fmt.Fprintf(os.Stderr, "(no %s rows)\n", filter)
	}
	return nil
}

// runOutboxRetry resets attempt_count to 0 and clears last_error for a
// single row. Intended for poison-pill recovery after you've fixed the
// underlying cause (e.g. missing FGA type in the model). The row must
// not already be processed — that would be a silent re-send.
func runOutboxRetry(ctx context.Context, pool *pgxpool.Pool, idStr string) error {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse id %q: %w", idStr, err)
	}

	const q = `
        UPDATE fga_outbox
        SET attempt_count = 0,
            last_error    = NULL
        WHERE id = $1
          AND processed_at IS NULL`

	ct, err := pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("row %d not found or already processed", id)
	}
	fmt.Printf("reset row %d (attempt_count=0, last_error cleared)\n", id)
	return nil
}

// runOutboxPurge deletes a row outright. Use for events that should never
// be retried — typically a poison-pill row whose payload is malformed
// past the point the worker can translate it, AFTER the underlying
// identity change has been reconciled to FGA out-of-band.
//
// By default, refuses to purge a row that's still in the worker's claim
// set (pending, below the retry ceiling). The common mistake is purging
// a fresh pending row whose identity-side DB change has already
// committed — that silently desyncs identity vs FGA. Pass --force to
// override when you know what you're doing.
func runOutboxPurge(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) < 1 {
		return usageErr("outbox purge: need <id>")
	}
	force := false
	var idStr string
	for _, a := range args {
		if a == "--force" {
			force = true
			continue
		}
		idStr = a
	}
	if idStr == "" {
		return usageErr("outbox purge: need <id>")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return fmt.Errorf("parse id %q: %w", idStr, err)
	}

	if !force {
		maxAttempts := 5
		if v := os.Getenv("OUTBOX_MAX_ATTEMPTS"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				maxAttempts = n
			}
		}
		var (
			processedAt  *time.Time
			attemptCount int
		)
		err := pool.QueryRow(ctx,
			`SELECT processed_at, attempt_count FROM fga_outbox WHERE id = $1`,
			id,
		).Scan(&processedAt, &attemptCount)
		if err != nil {
			return fmt.Errorf("row %d not found: %w", id, err)
		}
		if processedAt == nil && attemptCount < maxAttempts {
			return fmt.Errorf("row %d is still pending (attempt_count=%d < %d); "+
				"purging it can desync identity state vs FGA — pass --force if you're sure",
				id, attemptCount, maxAttempts)
		}
	}

	const q = `DELETE FROM fga_outbox WHERE id = $1`
	ct, err := pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("row %d not found", id)
	}
	fmt.Printf("deleted row %d\n", id)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// runGroups dispatches the `idp groups` subcommands. These are the
// FIRST callers of outbox.Enqueue — each membership mutation commits
// the identity row and the outbox row in a single Postgres transaction.
//
// Group identifiers in the CLI are NAMES (human-readable) rather than
// UUIDs, resolved to IDs inside each subcommand. Users are identified
// by email for the same reason.
func runGroups(args []string) error {
	if len(args) < 1 {
		return usageErr("groups: no subcommand")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL not set")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("pgxpool.New: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres ping: %w", err)
	}

	groups := users.NewGroupStore(pool)
	userStore := users.NewPostgresStore(pool)

	switch args[0] {
	case "create":
		if len(args) < 2 {
			return usageErr("groups create: need <name>")
		}
		g, err := groups.Create(ctx, args[1])
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		fmt.Printf("created group: id=%s name=%s\n", g.ID, g.Name)
		return nil

	case "list":
		all, err := groups.List(ctx)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		if len(all) == 0 {
			fmt.Println("(no groups — run: idp groups create <name>)")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tCREATED_AT")
		for _, g := range all {
			fmt.Fprintf(w, "%s\t%s\t%s\n", g.ID, g.Name, g.CreatedAt.Format(time.RFC3339))
		}
		return w.Flush()

	case "add-member":
		if len(args) < 3 {
			return usageErr("groups add-member: need <group-name> <user-email>")
		}
		groupName, userEmail := args[1], args[2]

		g, err := groups.GetByName(ctx, groupName)
		if err != nil {
			return fmt.Errorf("lookup group %q: %w", groupName, err)
		}
		u, err := userStore.GetByEmail(ctx, userEmail)
		if err != nil {
			return fmt.Errorf("lookup user %q: %w", userEmail, err)
		}

		// THE critical transaction: identity row + outbox row commit
		// atomically. If either fails, neither is visible.
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		defer tx.Rollback(ctx) // no-op after Commit

		if err := groups.AddMemberTx(ctx, tx, u.ID, g.ID); err != nil {
			return fmt.Errorf("add member: %w", err)
		}
		event := outbox.GroupMembershipAdded{UserID: u.ID, GroupID: g.ID}
		if err := outbox.Enqueue(ctx, tx, event); err != nil {
			return fmt.Errorf("enqueue outbox event: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit: %w", err)
		}
		fmt.Printf("added %s to %s (outbox event enqueued)\n", u.Email, g.Name)
		return nil

	case "remove-member":
		if len(args) < 3 {
			return usageErr("groups remove-member: need <group-name> <user-email>")
		}
		groupName, userEmail := args[1], args[2]

		g, err := groups.GetByName(ctx, groupName)
		if err != nil {
			return fmt.Errorf("lookup group %q: %w", groupName, err)
		}
		u, err := userStore.GetByEmail(ctx, userEmail)
		if err != nil {
			return fmt.Errorf("lookup user %q: %w", userEmail, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx: %w", err)
		}
		defer tx.Rollback(ctx)

		if err := groups.RemoveMemberTx(ctx, tx, u.ID, g.ID); err != nil {
			return fmt.Errorf("remove member: %w", err)
		}
		event := outbox.GroupMembershipRemoved{UserID: u.ID, GroupID: g.ID}
		if err := outbox.Enqueue(ctx, tx, event); err != nil {
			return fmt.Errorf("enqueue outbox event: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit: %w", err)
		}
		fmt.Printf("removed %s from %s (outbox event enqueued)\n", u.Email, g.Name)
		return nil

	case "list-members":
		if len(args) < 2 {
			return usageErr("groups list-members: need <group-name>")
		}
		g, err := groups.GetByName(ctx, args[1])
		if err != nil {
			return fmt.Errorf("lookup group: %w", err)
		}
		members, err := groups.ListMembers(ctx, g.ID)
		if err != nil {
			return fmt.Errorf("list members: %w", err)
		}
		if len(members) == 0 {
			fmt.Printf("(group %q has no members)\n", g.Name)
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USER_ID\tEMAIL")
		for _, m := range members {
			fmt.Fprintf(w, "%s\t%s\n", m.ID, m.Email)
		}
		return w.Flush()

	default:
		return usageErr(fmt.Sprintf("groups: unknown subcommand %q", args[0]))
	}
}

// runUsers dispatches the `idp users` subcommands. Users subcommands
// don't need the KEK — password hashing is inside the users package.
func runUsers(args []string) error {
	if len(args) < 1 {
		return usageErr("users: no subcommand")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL not set")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("pgxpool.New: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres ping: %w", err)
	}
	store := users.NewPostgresStore(pool)

	switch args[0] {
	case "create":
		if len(args) < 3 {
			return usageErr("users create: need <email> <password>")
		}
		email, password := args[1], args[2]
		u, err := store.Create(ctx, email, password)
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		fmt.Printf("created user: id=%s email=%s\n", u.ID, u.Email)
		return nil

	case "list":
		const q = `SELECT id, email, created_at FROM users ORDER BY created_at DESC`
		rows, err := pool.Query(ctx, q)
		if err != nil {
			return fmt.Errorf("query users: %w", err)
		}
		defer rows.Close()

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tEMAIL\tCREATED_AT")
		count := 0
		for rows.Next() {
			var id uuid.UUID
			var email string
			var createdAt time.Time
			if err := rows.Scan(&id, &email, &createdAt); err != nil {
				return fmt.Errorf("scan user: %w", err)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", id, email, createdAt.Format(time.RFC3339))
			count++
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate users: %w", err)
		}
		if count == 0 {
			fmt.Println("(no users — run: idp users create <email> <password>)")
			return nil
		}
		return w.Flush()

	default:
		return usageErr(fmt.Sprintf("users: unknown subcommand %q", args[0]))
	}
}

// runServe boots the HTTP server and blocks until SIGINT/SIGTERM. On signal
// it asks the server to drain in-flight requests for SHUTDOWN_GRACE before
// returning. Any other lifecycle error (bind failure, dep ping failure)
// returns immediately with a non-zero exit.
func runServe() error {
	cfg, err := loadServeConfig()
	if err != nil {
		return err
	}

	// Structured JSON logs so `logs-idp` in the Makefile's background
	// runner pattern can be ingested by anything grep-friendly.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.logLevel}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Open Postgres. Fail loudly if it's not reachable — downstream
	// handlers would all error anyway; failing at boot gives a cleaner
	// diagnostic.
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	pool, err := pgxpool.New(pingCtx, cfg.databaseURL)
	if err != nil {
		pingCancel()
		return fmt.Errorf("pgxpool.New: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(pingCtx); err != nil {
		pingCancel()
		return fmt.Errorf("postgres ping: %w", err)
	}
	pingCancel()
	slog.Info("postgres connected", "addr", redactDSN(cfg.databaseURL))

	// Load the KEK and build the key store. No signing keys required yet
	// (this commit only serves JWKS + discovery); /token will require one.
	kek, err := tokens.NewEnvKEKFromHex(cfg.kekHex)
	if err != nil {
		return fmt.Errorf("KEK: %w", err)
	}
	keyStore := tokens.NewKeyStore(pool, kek)

	// Warn (don't error) if there are no active keys. The /jwks.json
	// endpoint will still serve an empty JWKS; /token (when implemented)
	// will fail loudly. Operator runs `idp keys generate && idp keys activate`
	// to fix.
	if _, err := keyStore.GetActive(ctx); err != nil {
		if errors.Is(err, tokens.ErrNoActiveKey) {
			slog.Warn("no active signing key — JWKS will be empty; token issuance will fail until a key is activated")
		} else {
			return fmt.Errorf("check active key: %w", err)
		}
	}

	// Layer 5 + 6 wiring: all the Postgres-backed stores the HTTP layer needs.
	userStore := users.NewPostgresStore(pool)
	sessionStore := users.NewPostgresSessionStore(pool)
	clientStore := clients.NewPostgresStore(pool)
	consentStore := consent.NewPostgresStore(pool)
	codeStore := oauth.NewPostgresAuthCodeStore(pool)
	refreshStore := tokens.NewPostgresRefreshTokenStore(pool)
	signer := tokens.NewSigner(keyStore, kek, cfg.issuerURL, nil)

	templates, err := myhttp.ParseTemplates()
	if err != nil {
		return fmt.Errorf("parse templates: %w", err)
	}

	csrfKey, err := myhttp.ParseCSRFKey(cfg.csrfKeyHex)
	if err != nil {
		return fmt.Errorf("CSRF key: %w", err)
	}

	secure := strings.HasPrefix(cfg.issuerURL, "https://")

	// Adapter: clients.PostgresStore → http.ClientLookup. The handler
	// only needs GetByID returning a narrow display struct; define the
	// adapter locally as a closure-bearing struct.
	clientLookup := &clientLookupAdapter{store: clientStore}

	loginCfg := myhttp.LoginConfig{
		Users:      userStore,
		Sessions:   sessionStore,
		Templates:  templates,
		BaseURL:    cfg.issuerURL,
		SessionTTL: users.DefaultSessionTTL,
		Secure:     secure,
	}
	consentCfg := myhttp.ConsentConfig{
		Consent:   consentStore,
		Users:     userStore,
		Clients:   clientLookup,
		Templates: templates,
		BaseURL:   cfg.issuerURL,
	}
	authorizeCfg := oauth.AuthorizeConfig{
		Clients:   clientStore,
		Consent:   consentStore,
		AuthCodes: codeStore,
		CodeTTL:   oauth.DefaultCodeTTL,
		CurrentSessionUser: func(r *nethttp.Request) (uuid.UUID, bool) {
			sess := myhttp.SessionFromContext(r.Context())
			if sess == nil {
				return uuid.Nil, false
			}
			return sess.UserID, true
		},
	}
	tokenCfg := oauth.TokenConfig{
		Clients:         clientStore,
		AuthCodes:       codeStore,
		RefreshTokens:   refreshStore,
		Signer:          signer,
		AccessTokenTTL:  cfg.accessTokenTTL,
		IDTokenTTL:      cfg.idTokenTTL,
		RefreshTokenTTL: cfg.refreshTokenTTL,
		Issuer:          cfg.issuerURL,
		UserInfo:        &userInfoAdapter{store: userStore},
	}

	// /userinfo: verify tokens against our own key store directly (no
	// round-trip through our public JWKS endpoint). Pass audience="" so
	// the verifier accepts tokens issued to any client.
	selfResolver := tokens.NewKeyStoreResolver(keyStore)
	selfVerifier := tokens.NewVerifier(
		map[string]tokens.KeyResolver{cfg.issuerURL: selfResolver},
		"", // any audience
		nil,
	)
	userInfoCfg := oidc.UserInfoConfig{
		Verifier:  selfVerifier,
		UserStore: &userInfoOIDCAdapter{store: userStore},
	}

	indexCfg := myhttp.IndexConfig{
		Templates: templates,
		Users:     userStore,
	}
	logoutCfg := myhttp.LogoutConfig{
		Sessions: sessionStore,
		Secure:   secure,
		Clients:  clientLookup,
	}

	router := myhttp.New(myhttp.RouterConfig{
		Discovery: oidc.DiscoveryConfig{
			Issuer:          cfg.issuerURL,
			ScopesSupported: []string{"openid", "profile", "email", "read:docs", "write:docs", "admin:users"},
		},
		KeyStore:     keyStore,
		PostgresPing: func() error { return pool.Ping(context.Background()) },

		Sessions: sessionStore,
		CSRFKey:  csrfKey,
		Secure:   secure,

		Index:       myhttp.Index(indexCfg),
		Logout:      myhttp.Logout(logoutCfg),
		Authorize:   oauth.Authorize(authorizeCfg),
		LoginGET:    myhttp.LoginGET(loginCfg),
		LoginPOST:   myhttp.LoginPOST(loginCfg),
		ConsentGET:  myhttp.ConsentGET(consentCfg),
		ConsentPOST: myhttp.ConsentPOST(consentCfg),
		Token:          oauth.Token(tokenCfg),
		UserInfo:       oidc.UserInfoHandler(userInfoCfg),
		AllowedOrigins: cfg.allowedOrigins,
	})

	srv := &nethttp.Server{
		Addr:              cfg.httpAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Run ListenAndServe in a goroutine so main can wait on the signal.
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("http server listening",
			"addr", cfg.httpAddr,
			"issuer", cfg.issuerURL,
			"allowed_origins", cfg.allowedOrigins,
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		slog.Info("shutdown signal received, draining")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	slog.Info("shutdown complete")
	return nil
}

type serveConfig struct {
	databaseURL     string
	kekHex          string
	csrfKeyHex      string
	issuerURL       string
	httpAddr        string
	allowedOrigins  []string
	accessTokenTTL  time.Duration
	idTokenTTL      time.Duration
	refreshTokenTTL time.Duration
	shutdownGrace   time.Duration
	logLevel        slog.Level
}

// clientLookupAdapter bridges *clients.PostgresStore → http.ClientLookup.
// Translates the concrete client struct into the narrow display shape
// the consent handler needs. Lives here because it's a wiring concern.
type clientLookupAdapter struct {
	store *clients.PostgresStore
}

func (a *clientLookupAdapter) GetByID(ctx context.Context, id string) (myhttp.ClientDisplay, error) {
	c, err := a.store.GetByID(ctx, id)
	if err != nil {
		return myhttp.ClientDisplay{}, err
	}
	return myhttp.ClientDisplay{ID: c.ID, RedirectURIs: c.RedirectURIs}, nil
}

// userInfoAdapter bridges *users.PostgresStore → oauth.UserInfoLookup,
// exposing only ID + Email for ID-token issuance.
type userInfoAdapter struct {
	store *users.PostgresStore
}

func (a *userInfoAdapter) GetByID(ctx context.Context, id uuid.UUID) (oauth.UserInfo, error) {
	u, err := a.store.GetByID(ctx, id)
	if err != nil {
		return oauth.UserInfo{}, err
	}
	return oauth.UserInfo{ID: u.ID, Email: u.Email}, nil
}

// userInfoOIDCAdapter bridges *users.PostgresStore → oidc.UserInfoStore.
// Emits oidc.UserInfoData which is a superset of oauth.UserInfo (adds
// EmailVerified). In this lab we treat every stored email as verified —
// real signup would flip this after email-confirmation flow.
type userInfoOIDCAdapter struct {
	store *users.PostgresStore
}

func (a *userInfoOIDCAdapter) GetByID(ctx context.Context, id uuid.UUID) (oidc.UserInfoData, error) {
	u, err := a.store.GetByID(ctx, id)
	if err != nil {
		return oidc.UserInfoData{}, err
	}
	return oidc.UserInfoData{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: true,
	}, nil
}

func loadServeConfig() (serveConfig, error) {
	var c serveConfig
	c.databaseURL = os.Getenv("DATABASE_URL")
	if c.databaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL not set")
	}
	c.kekHex = os.Getenv("JWT_SIGNING_KEY_ENCRYPTION_KEY")
	if c.kekHex == "" {
		return c, fmt.Errorf("JWT_SIGNING_KEY_ENCRYPTION_KEY not set (need 64 hex chars)")
	}
	c.csrfKeyHex = os.Getenv("CSRF_KEY")
	if c.csrfKeyHex == "" {
		return c, fmt.Errorf("CSRF_KEY not set (need 64 hex chars for CSRF token signing)")
	}

	c.issuerURL = envOr("ISSUER_URL", "http://localhost:8080")
	c.httpAddr = envOr("HTTP_ADDR", ":8080")

	// CORS origins for browser OIDC clients (discovery, token, userinfo).
	// Empty → no CORS headers. Example: http://localhost:5173 for the
	// Vite dev server.
	if origins := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS")); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				c.allowedOrigins = append(c.allowedOrigins, o)
			}
		}
	}

	var err error

	// Token TTLs — defaults per README §6 decisions.
	c.accessTokenTTL, err = envDur("ACCESS_TOKEN_TTL", 15*time.Minute)
	if err != nil {
		return c, err
	}
	c.idTokenTTL, err = envDur("ID_TOKEN_TTL", 5*time.Minute)
	if err != nil {
		return c, err
	}
	c.refreshTokenTTL, err = envDur("REFRESH_TOKEN_TTL", 30*24*time.Hour)
	if err != nil {
		return c, err
	}

	c.shutdownGrace, err = envDur("SHUTDOWN_GRACE", 15*time.Second)
	if err != nil {
		return c, err
	}

	c.logLevel = parseLogLevel(os.Getenv("LOG_LEVEL"))
	return c, nil
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envDur(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", key, v, err)
	}
	return d, nil
}

func parseLogLevel(v string) slog.Level {
	switch strings.ToLower(v) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "", "info":
		return slog.LevelInfo
	default:
		fmt.Fprintf(os.Stderr, "invalid LOG_LEVEL=%q; using info\n", v)
		return slog.LevelInfo
	}
}

// redactDSN hides the password in a Postgres connection string for log
// output. Handles the common postgres://user:pass@host/db shape; falls
// back to the original if the shape is unrecognized.
func redactDSN(dsn string) string {
	scheme := strings.Index(dsn, "://")
	at := strings.Index(dsn, "@")
	if scheme < 0 || at < 0 || at <= scheme+3 {
		return dsn
	}
	userinfo := dsn[scheme+3 : at]
	colon := strings.Index(userinfo, ":")
	if colon < 0 {
		return dsn
	}
	return dsn[:scheme+3] + userinfo[:colon] + ":***" + dsn[at:]
}

func runKeys(args []string) error {
	if len(args) < 1 {
		return usageErr("keys: no subcommand")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, kek, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	store := tokens.NewKeyStore(pool, kek)

	switch args[0] {
	case "generate":
		k, err := store.Generate(ctx)
		if err != nil {
			return fmt.Errorf("generate: %w", err)
		}
		fmt.Printf("generated PENDING key: kid=%s alg=%s\n", k.KID, k.Alg)
		fmt.Println("next: idp keys activate " + k.KID)
		return nil

	case "list":
		keys, err := store.List(ctx)
		if err != nil {
			return fmt.Errorf("list: %w", err)
		}
		if len(keys) == 0 {
			fmt.Println("(no signing keys — run: idp keys generate)")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KID\tALG\tSTATUS\tAGE(d)\tACTIVATED_AT\tRETIRED_AT")
		for _, k := range keys {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n",
				k.KID, k.Alg, k.Status(), k.AgeDays(),
				ts(k.ActivatedAt), ts(k.RetiredAt))
		}
		return w.Flush()

	case "activate":
		if len(args) < 2 {
			return usageErr("keys activate: missing <kid>")
		}
		kid := args[1]
		if err := store.Activate(ctx, kid); err != nil {
			return fmt.Errorf("activate %s: %w", kid, err)
		}
		fmt.Printf("activated: %s\n", kid)
		return nil

	case "retire":
		if len(args) < 2 {
			return usageErr("keys retire: missing <kid>")
		}
		kid := args[1]
		if err := store.Retire(ctx, kid); err != nil {
			return fmt.Errorf("retire %s: %w", kid, err)
		}
		fmt.Printf("retired: %s (key still appears in JWKS until dropped; wait access_token_ttl + skew)\n", kid)
		return nil

	default:
		return usageErr(fmt.Sprintf("keys: unknown subcommand %q", args[0]))
	}
}

// openDeps opens the Postgres pool + loads the KEK from env. Shared between
// all `keys` subcommands.
func openDeps(ctx context.Context) (*pgxpool.Pool, tokens.KEK, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, nil, fmt.Errorf("DATABASE_URL not set")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("postgres ping: %w", err)
	}

	hexKEK := os.Getenv("JWT_SIGNING_KEY_ENCRYPTION_KEY")
	if hexKEK == "" {
		pool.Close()
		return nil, nil, fmt.Errorf("JWT_SIGNING_KEY_ENCRYPTION_KEY not set (need 64 hex chars)")
	}
	kek, err := tokens.NewEnvKEKFromHex(hexKEK)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("KEK: %w", err)
	}
	return pool, kek, nil
}

// ts formats a nullable timestamp for the list table.
func ts(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usageErr(msg string) error {
	printUsage()
	return &usageError{msg: msg}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: idp <command> [args]

Subcommands:
  serve                             run the OIDC HTTP server
  keys generate                     create a new PENDING signing key
  keys list                         show all signing keys with status + age
  keys activate <kid>               PENDING -> ACTIVE (at most one active)
  keys retire <kid>                 ACTIVE  -> RETIRED
  users create <email> <password>   create a user (argon2id-hashed)
  users list                        show all users
  groups create <name>              create a group
  groups list                       show all groups
  groups add-member <grp> <email>   add user (enqueues FGA outbox event)
  groups remove-member <grp> <email> remove user (enqueues FGA outbox event)
  groups list-members <group>       show group membership
  fga init                          create OpenFGA store + upload model
  outbox list [--pending|--failed|--all]  inspect fga_outbox rows
  outbox retry <id>                 reset attempt_count + clear last_error
  outbox purge <id> [--force]       delete a row (refuses pending rows unless --force)
  help                              print this message

Env (shared):
  DATABASE_URL                     postgres://... (required)
  JWT_SIGNING_KEY_ENCRYPTION_KEY   32 bytes hex-encoded (required for keys + serve)

Env (serve only):
  CSRF_KEY                         32 bytes hex-encoded (required)
  ISSUER_URL                       default http://localhost:8080
  ALLOWED_ORIGINS                  CORS origins for browser OIDC clients (e.g. http://localhost:5173)
  HTTP_ADDR                        default :8080
  SHUTDOWN_GRACE                   default 15s
  LOG_LEVEL                        debug|info|warn|error (default info)`)
}
