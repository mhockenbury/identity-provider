// Package http builds the chi-based HTTP surface of the IdP.
//
// Each OIDC/OAuth endpoint is registered here and delegates to a handler
// from the oidc or oauth packages. The router itself owns cross-cutting
// concerns: request IDs, panic recovery, per-request timeouts, structured
// access logging.
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/mhockenbury/identity-provider/internal/oidc"
	"github.com/mhockenbury/identity-provider/internal/tokens"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// RouterConfig wires the router. All real work lives behind interfaces
// so tests can supply fakes without a DB or full service stack.
//
// The layer-5 handlers (Authorize / LoginGET / LoginPOST / ConsentGET /
// ConsentPOST) plus Sessions + CSRFKey are optional as a group. When
// Sessions is nil the router skips /login, /consent, /authorize and the
// CSRF + WithSession middleware — useful for a minimal "discovery + JWKS
// only" smoke-test boot.
type RouterConfig struct {
	Discovery oidc.DiscoveryConfig
	KeyStore  oidc.JWKSKeyStore
	// PostgresPing is used by /healthz; nil-safe.
	PostgresPing func() error

	// Layer 5 wiring. If Sessions is nil, the whole set is skipped.
	Sessions    users.SessionStore
	CSRFKey     []byte // 32 bytes; only used when Sessions != nil
	Secure      bool   // TLS flag (session cookies + CSRF mode)
	Authorize   http.HandlerFunc
	LoginGET    http.HandlerFunc
	LoginPOST   http.HandlerFunc
	ConsentGET  http.HandlerFunc
	ConsentPOST http.HandlerFunc

	// Root landing page + logout. Both session-aware so the landing page
	// can show login state. Registered alongside the other session-aware
	// routes. Nil-safe: if unset, no route registered and a GET / falls
	// through to chi's default 404.
	Index  http.HandlerFunc
	Logout http.HandlerFunc

	// Layer 6 wiring. /token is a back-channel endpoint: no session
	// middleware, no CSRF (the client authenticates with credentials,
	// not a cookie). Safe to register independently.
	Token http.HandlerFunc

	// Layer 7: /userinfo. Bearer-authenticated, no session, no CSRF.
	// OIDC Core §5.3.
	UserInfo http.HandlerFunc
}

// requestTimeout bounds per-request work end-to-end. The IdP has no
// expensive handlers (the argon2 hash on /login is by far the slowest),
// so 10s is generous.
const requestTimeout = 10 * time.Second

// New builds and returns the chi router. Exported so `cmd/idp serve`
// wires it into http.Server.
func New(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()

	// Middleware stack, outside-in:
	//   RequestID   — attach X-Request-Id + propagate through request context
	//   RealIP      — set r.RemoteAddr to the client IP (X-Forwarded-For honest)
	//   Recoverer   — catch panics, log, return 500
	//   accessLog   — structured JSON line per request (our own, slog-based)
	//   Timeout     — bounded request context
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(accessLog)
	r.Use(middleware.Timeout(requestTimeout))

	// Discovery + JWKS. Both are read-only, no auth.
	r.Get("/.well-known/openid-configuration", oidc.Handler(cfg.Discovery).ServeHTTP)
	r.Get("/.well-known/jwks.json", oidc.JWKSHandler(cfg.KeyStore).ServeHTTP)

	// Liveness + dependency probe. Intentionally lenient: returns 503
	// on first failure so container orchestrators can react, but
	// degradation doesn't cascade to the whole handler surface.
	r.Get("/healthz", healthHandler(cfg.PostgresPing))

	// Layer 5: /authorize + login + consent. Only registered when the
	// session store is wired (otherwise we don't have the primitives
	// these endpoints need).
	if cfg.Sessions != nil {
		withSession := WithSession(cfg.Sessions)
		csrfMW := CSRFMiddleware(cfg.CSRFKey, cfg.Secure)

		// Root + logout: session-aware (for "signed in as..." display)
		// but no CSRF — logout is GET-or-POST tolerant, / is read-only.
		r.Group(func(r chi.Router) {
			r.Use(withSession)
			if cfg.Index != nil {
				r.Get("/", cfg.Index)
			}
			if cfg.Logout != nil {
				r.Get("/logout", cfg.Logout)
				r.Post("/logout", cfg.Logout)
			}
		})

		// /authorize reads session but doesn't mutate state itself.
		// It redirects to /login or /consent as needed.
		r.Group(func(r chi.Router) {
			r.Use(withSession)
			if cfg.Authorize != nil {
				r.Get("/authorize", cfg.Authorize)
			}
		})

		// /login GET and POST. CSRF on POST. No session middleware
		// needed — the POST establishes the session.
		r.Group(func(r chi.Router) {
			r.Use(csrfMW)
			if cfg.LoginGET != nil {
				r.Get("/login", cfg.LoginGET)
			}
			if cfg.LoginPOST != nil {
				r.Post("/login", cfg.LoginPOST)
			}
		})

		// /consent GET and POST. Both need a session AND CSRF (GET to
		// issue the token, POST to verify it).
		r.Group(func(r chi.Router) {
			r.Use(withSession)
			r.Use(csrfMW)
			if cfg.ConsentGET != nil {
				r.Get("/consent", cfg.ConsentGET)
			}
			if cfg.ConsentPOST != nil {
				r.Post("/consent", cfg.ConsentPOST)
			}
		})
	}

	// Layer 6: /token. Back-channel — no session, no CSRF. Client
	// authentication happens inside the handler via Basic/form fields.
	if cfg.Token != nil {
		r.Post("/token", cfg.Token)
	}

	// Layer 7: /userinfo. Bearer-authenticated, no session, no CSRF.
	if cfg.UserInfo != nil {
		r.Get("/userinfo", cfg.UserInfo)
	}

	return r
}

// accessLog is a tiny structured-logging middleware. slog.InfoContext lets
// handlers downstream add context via slog.With; we don't do that yet but
// the hook is here so future observability work doesn't need a rewrite.
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

// healthHandler returns 200 when configured dependencies respond.
// Cheap enough to run per-request; no caching. pingPG may be nil.
func healthHandler(pingPG func() error) http.HandlerFunc {
	type response struct {
		Status   string `json:"status"`
		Postgres string `json:"postgres,omitempty"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := response{Status: "ok"}
		code := http.StatusOK

		if pingPG != nil {
			if err := pingPG(); err != nil {
				resp.Status = "degraded"
				resp.Postgres = "down: " + err.Error()
				code = http.StatusServiceUnavailable
			} else {
				resp.Postgres = "ok"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// Tiny compile-time check that *tokens.KeyStore satisfies the JWKS interface.
// Not strictly necessary but protects against a refactor that silently breaks
// the http↔oidc↔tokens seam.
var _ oidc.JWKSKeyStore = (*tokens.KeyStore)(nil)

// Similarly, users.PostgresSessionStore satisfies users.SessionStore (and
// thus the router's session type).
var _ users.SessionStore = (*users.PostgresSessionStore)(nil)
