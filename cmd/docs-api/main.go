// Package main is the docs-api entrypoint.
//
// docs-api is a small resource server that:
//   - validates OAuth2 access tokens locally against one-or-more trusted
//     issuers via their JWKS endpoints,
//   - enforces OAuth scopes via middleware,
//   - enforces fine-grained authorization via OpenFGA Check,
//   - serves a small in-memory "documents" corpus so a downstream SPA can
//     exercise the full protocol triangle (browser ↔ IdP ↔ resource server).
//
// Deliberately a separate binary from the IdP. That's the point — it
// demonstrates the downstream-service view: tokens are verified
// *without* a backchannel to the IdP, purely via the JWKS public
// endpoint + a local cache.
//
// Layers added here:
//   - 9a: internal/jwks (HTTP JWKS cache)
//   - 9b: this file — config + server skeleton
//   - 9c: middleware (authenticate + require_scope) — next file(s)
//   - 9d: resource handlers — next file(s)
//
// Env vars:
//
//	HTTP_ADDR          listen address (default :8083)
//	TRUSTED_ISSUERS    comma-separated issuer URLs (required). Each issuer's
//	                   JWKS is fetched + cached independently. This is where
//	                   the "multi-issuer validation" learning objective lives.
//	REQUIRED_AUD       expected `aud` claim (default docs-api)
//	OPENFGA_API_URL    where to send Check requests (default http://localhost:8081)
//	OPENFGA_STORE_ID   store ID from `idp fga init` (required)
//	OPENFGA_AUTHORIZATION_MODEL_ID  model ID from `idp fga init` (required)
//	OPENFGA_API_TOKEN  optional; local OpenFGA runs without auth
//	ALLOWED_ORIGINS    comma-separated CORS origins (e.g. http://localhost:5173
//	                   for the Vite dev server). Empty → same-origin only.
//	SHUTDOWN_GRACE     drain window on SIGTERM (default 15s)
//	LOG_LEVEL          debug|info|warn|error (default info)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	openfgaclient "github.com/openfga/go-sdk/client"

	"github.com/mhockenbury/identity-provider/internal/fga"
	"github.com/mhockenbury/identity-provider/internal/jwks"
	"github.com/mhockenbury/identity-provider/internal/tokens"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.logLevel}))
	slog.SetDefault(logger)

	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Build one JWKS cache per trusted issuer. tokens.Verifier uses the
	// issuer map as an allowlist — tokens from any iss not in the map are
	// rejected before we even look at the kid. That's the multi-issuer
	// enforcement point.
	resolvers := make(map[string]tokens.KeyResolver, len(cfg.trustedIssuers))
	for _, iss := range cfg.trustedIssuers {
		resolvers[iss] = jwks.NewCache(jwks.Config{
			Issuer:          iss,
			RefreshInterval: 10 * time.Minute,
			StaleWindow:     1 * time.Hour,
		})
	}
	verifier := tokens.NewVerifier(resolvers, cfg.requiredAud, nil)

	fgaClient, err := fga.NewClient(cfg.fga)
	if err != nil {
		return fmt.Errorf("build fga client: %w", err)
	}

	// Sanity-check FGA is reachable before we start serving. Catches the
	// common footgun of starting docs-api before OpenFGA is up.
	pingCtx, pingCancel := context.WithTimeout(rootCtx, 3*time.Second)
	defer pingCancel()
	if _, err := fga.Check(pingCtx, fgaClient, "user:_probe", "viewer", "document:_probe"); err != nil {
		// The call itself can legitimately return allowed=false; we only
		// warn if the HTTP/gRPC layer returned an error. Don't bail — the
		// operator might be bringing FGA up alongside docs-api.
		slog.Warn("openfga ping failed — starting anyway", "err", err)
	}

	// Build the in-memory doc store + seed it. The owner on every
	// seeded doc is a placeholder "seed" sub; per-user permissions
	// come from FGA tuples, not from the OwnerSub field, so this only
	// affects the displayed "owner" string.
	store := NewStore()
	SeedCorpus(store, "seed")

	// Seed FGA tuples for the demo corpus. People map comes from env:
	// DOCS_SEED_ALICE, DOCS_SEED_BOB, DOCS_SEED_CAROL, each set to the
	// user's sub (UUID) as printed by `idp users list`.
	//
	// Empty values skip that user's tuples — the corpus still loads,
	// the smoke test can inject fresh users via direct FGA writes.
	seedCtx, seedCancel := context.WithTimeout(rootCtx, 5*time.Second)
	defer seedCancel()
	if err := SeedFGA(seedCtx, fgaClient, SeedPeople{
		Alice: os.Getenv("DOCS_SEED_ALICE"),
		Bob:   os.Getenv("DOCS_SEED_BOB"),
		Carol: os.Getenv("DOCS_SEED_CAROL"),
	}); err != nil {
		slog.Warn("fga seed failed — starting anyway", "err", err)
	}

	router := newRouter(routerDeps{
		verifier:       verifier,
		fga:            &fgaCheckAdapter{client: fgaClient},
		fgaRaw:         fgaClient,
		store:          store,
		requiredAud:    cfg.requiredAud,
		allowedOrigins: cfg.allowedOrigins,
	})

	srv := &http.Server{
		Addr:              cfg.httpAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("docs-api listening",
			"addr", cfg.httpAddr,
			"trusted_issuers", cfg.trustedIssuers,
			"required_aud", cfg.requiredAud,
			"allowed_origins", cfg.allowedOrigins,
			"fga_store", cfg.fga.StoreID,
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("http server: %w", err)
	case <-rootCtx.Done():
		slog.Info("shutdown signal received, draining")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.shutdownGrace)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	slog.Info("shutdown complete")
	return nil
}

// --- config ---

type config struct {
	httpAddr       string
	trustedIssuers []string
	requiredAud    string
	allowedOrigins []string
	fga            fga.Config
	shutdownGrace  time.Duration
	logLevel       slog.Level
}

func loadConfig() (config, error) {
	cfg := config{
		httpAddr:    envOr("HTTP_ADDR", ":8083"),
		requiredAud: envOr("REQUIRED_AUD", "docs-api"),
		fga: fga.Config{
			APIURL:               envOr("OPENFGA_API_URL", "http://localhost:8081"),
			StoreID:              os.Getenv("OPENFGA_STORE_ID"),
			AuthorizationModelID: os.Getenv("OPENFGA_AUTHORIZATION_MODEL_ID"),
			APIToken:             os.Getenv("OPENFGA_API_TOKEN"),
		},
		shutdownGrace: durEnv("SHUTDOWN_GRACE", 15*time.Second),
		logLevel:      parseLogLevel(os.Getenv("LOG_LEVEL")),
	}

	// CORS. Comma-separated origins allowed to call docs-api from a
	// browser. Empty → no CORS headers (same-origin only). Dev SPA runs
	// on :5173 (Vite's default); prod would be whatever the SPA is
	// deployed to.
	if origins := strings.TrimSpace(os.Getenv("ALLOWED_ORIGINS")); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				cfg.allowedOrigins = append(cfg.allowedOrigins, o)
			}
		}
	}

	issuers := strings.TrimSpace(os.Getenv("TRUSTED_ISSUERS"))
	if issuers == "" {
		return cfg, errors.New("TRUSTED_ISSUERS is required (comma-separated issuer URLs)")
	}
	for _, iss := range strings.Split(issuers, ",") {
		iss = strings.TrimSpace(iss)
		if iss != "" {
			cfg.trustedIssuers = append(cfg.trustedIssuers, iss)
		}
	}
	if len(cfg.trustedIssuers) == 0 {
		return cfg, errors.New("TRUSTED_ISSUERS had no non-empty entries")
	}

	if cfg.fga.StoreID == "" {
		return cfg, errors.New("OPENFGA_STORE_ID is required (run `idp fga init`)")
	}
	if cfg.fga.AuthorizationModelID == "" {
		return cfg, errors.New("OPENFGA_AUTHORIZATION_MODEL_ID is required")
	}

	return cfg, nil
}

// --- router ---

// routerDeps is the set of dependencies the handlers need. Pulled out as
// a struct so the handler files can accept a single parameter.
type routerDeps struct {
	verifier       *tokens.Verifier
	fga            fgaChecker
	fgaRaw         *openfgaclient.OpenFgaClient // for tuple writes (POST/DELETE docs)
	store          *Store
	requiredAud    string
	allowedOrigins []string
}

// fgaChecker is the narrow interface the handlers depend on. Lets tests
// swap in a fake without a full OpenFGA SDK client. Implemented by
// fgaCheckAdapter (real) and test fakes.
type fgaChecker interface {
	Check(ctx context.Context, user, relation, object string) (bool, error)
}

// fgaCheckAdapter binds an SDK client to the narrow fgaChecker interface.
// Thin wrapper; the real work is in internal/fga.Check.
type fgaCheckAdapter struct {
	client *openfgaclient.OpenFgaClient
}

func (a *fgaCheckAdapter) Check(ctx context.Context, user, relation, object string) (bool, error) {
	return fga.Check(ctx, a.client, user, relation, object)
}

// newRouter wires middleware + routes. Kept small; the handler files
// register themselves here via registerRoutes().
func newRouter(deps routerDeps) http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(accessLog)

	// CORS. Registered BEFORE auth so OPTIONS preflight requests aren't
	// rejected as unauthenticated — the CORS middleware short-circuits
	// OPTIONS before the chain gets to authenticate.
	if len(deps.allowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   deps.allowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Authorization", "Content-Type"},
			ExposedHeaders:   []string{"WWW-Authenticate"},
			AllowCredentials: false, // Bearer-only; we don't use cookies cross-origin
			MaxAge:           300,
		}))
	}

	r.Get("/healthz", healthHandler())

	// Authenticated route group. Every handler inside this Group sees
	// verified claims via claimsFromCtx. Per-route scope requirements
	// layer on top with requireScope("...").
	r.Group(func(r chi.Router) {
		r.Use(authenticate(deps.verifier))
		registerResourceRoutes(r, handlerDeps{
			store:        deps.store,
			fga:          deps.fga,
			fgaRawClient: deps.fgaRaw,
		})
	})

	return r
}

// accessLog is the same JSON-per-request shape as the IdP's accessLog
// middleware. Reproduced here rather than imported because internal/http
// is the IdP's router; docs-api is a separate deployable with its own
// middleware needs.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.InfoContext(r.Context(), "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}

// --- tiny utilities ---

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func parseLogLevel(v string) slog.Level {
	switch v {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
