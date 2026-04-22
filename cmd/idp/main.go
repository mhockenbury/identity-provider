// The idp binary hosts both the HTTP server and the admin CLI.
//
// Subcommands:
//   idp serve                          — run the OIDC HTTP server
//   idp keys generate                  — create a new PENDING signing key
//   idp keys list                      — show all signing keys with status
//   idp keys activate <kid>            — transition PENDING → ACTIVE
//   idp keys retire   <kid>            — transition ACTIVE → RETIRED
//   idp users create <email> <pass>    — create a user (argon2id-hashed password)
//   idp users list                     — list all users
//
// Env vars:
//   DATABASE_URL                     required; e.g. postgres://idp:idp@localhost:5434/idp?sslmode=disable
//   JWT_SIGNING_KEY_ENCRYPTION_KEY   required for keys subcommand + serve; 64 hex chars
//   CSRF_KEY                         required for serve; 64 hex chars
//   ISSUER_URL                       serve only; issuer string baked into tokens (default http://localhost:8080)
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
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/clients"
	"github.com/mhockenbury/identity-provider/internal/consent"
	myhttp "github.com/mhockenbury/identity-provider/internal/http"
	"github.com/mhockenbury/identity-provider/internal/oauth"
	"github.com/mhockenbury/identity-provider/internal/oidc"
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
	case "-h", "--help", "help":
		printUsage()
		return nil
	default:
		return usageErr(fmt.Sprintf("unknown subcommand %q", args[0]))
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

	// Layer 5 wiring: sessions, clients, consent, codes, handlers. Each
	// store is Postgres-backed; handlers are constructed from narrow
	// configs that inject these stores + HTML templates.
	userStore := users.NewPostgresStore(pool)
	sessionStore := users.NewPostgresSessionStore(pool)
	clientStore := clients.NewPostgresStore(pool)
	consentStore := consent.NewPostgresStore(pool)
	codeStore := oauth.NewPostgresAuthCodeStore(pool)

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

		Authorize:   oauth.Authorize(authorizeCfg),
		LoginGET:    myhttp.LoginGET(loginCfg),
		LoginPOST:   myhttp.LoginPOST(loginCfg),
		ConsentGET:  myhttp.ConsentGET(consentCfg),
		ConsentPOST: myhttp.ConsentPOST(consentCfg),
	})

	srv := &nethttp.Server{
		Addr:              cfg.httpAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Run ListenAndServe in a goroutine so main can wait on the signal.
	serverErr := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", cfg.httpAddr, "issuer", cfg.issuerURL)
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
	databaseURL   string
	kekHex        string
	csrfKeyHex    string
	issuerURL     string
	httpAddr      string
	shutdownGrace time.Duration
	logLevel      slog.Level
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

	if v := os.Getenv("SHUTDOWN_GRACE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("SHUTDOWN_GRACE=%q: %w", v, err)
		}
		c.shutdownGrace = d
	} else {
		c.shutdownGrace = 15 * time.Second
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
  help                              print this message

Env (shared):
  DATABASE_URL                     postgres://... (required)
  JWT_SIGNING_KEY_ENCRYPTION_KEY   32 bytes hex-encoded (required for keys + serve)

Env (serve only):
  CSRF_KEY                         32 bytes hex-encoded (required)
  ISSUER_URL                       default http://localhost:8080
  HTTP_ADDR                        default :8080
  SHUTDOWN_GRACE                   default 15s
  LOG_LEVEL                        debug|info|warn|error (default info)`)
}
