package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// Session cookie handling. See internal/users/sessions.go for the
// intentional "unsigned cookie" tradeoff.

// SessionCookieName is the cookie holding the session ID. A client with
// a valid ID is logged in; without one or with an invalid one, they're
// anonymous.
const SessionCookieName = "idp_session"

// ctxKey is our private context-value key type. Using an unexported named
// type per https://pkg.go.dev/context#WithValue so nobody outside this
// package can collide with it.
type ctxKey int

const (
	ctxKeySession ctxKey = iota + 1
)

// SetSessionCookie attaches a Set-Cookie header establishing the session.
// secure is true when the IdP is served over https (ISSUER_URL scheme).
func SetSessionCookie(w http.ResponseWriter, sessionID uuid.UUID, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID.String(),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		// Lax lets top-level redirects from other sites carry the cookie
		// (needed: OAuth client app redirects the browser to /authorize,
		// which needs our cookie to check logged-in state). Strict would
		// break that entry path.
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie emits a Set-Cookie that deletes the session cookie.
// Used on logout; Secure must match how the cookie was set.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ReadSessionCookie returns the session ID from the request, or a zero
// UUID + error if the cookie is missing or malformed.
func ReadSessionCookie(r *http.Request) (uuid.UUID, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return uuid.Nil, err
	}
	id, err := uuid.Parse(c.Value)
	if err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

// WithSession wraps a handler to attach the resolved users.Session to
// the request context when present. Does NOT gate access — handlers
// that require a session call SessionFromContext and route the missing
// case themselves (e.g. /authorize redirects to /login). That lets the
// same middleware cover "optional session" (e.g. /consent renders the
// email) and "required session" paths.
//
// Expired or invalid session cookies are treated as no session. The
// invalid cookie is NOT cleared here — that's the /login POST's job
// after successful authentication, so a stale cookie from a prior
// deployment silently becomes a no-op login prompt instead of losing
// state we shouldn't touch.
func WithSession(store users.SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := ReadSessionCookie(r)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			sess, err := store.Get(r.Context(), id)
			if err != nil {
				if errors.Is(err, users.ErrSessionNotFound) ||
					errors.Is(err, users.ErrSessionExpired) {
					next.ServeHTTP(w, r)
					return
				}
				// A real DB error is logged at the router-level accessLog
				// middleware's status line; here we just fall through to
				// unauthenticated rather than returning a 500, because a
				// handler that doesn't require auth shouldn't fail.
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKeySession, &sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SessionFromContext returns the resolved session, or nil if the request
// is unauthenticated. Handlers that need auth redirect to /login.
func SessionFromContext(ctx context.Context) *users.Session {
	sess, _ := ctx.Value(ctxKeySession).(*users.Session)
	return sess
}
