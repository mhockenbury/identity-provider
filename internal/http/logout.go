package http

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// LogoutConfig wires the logout handler.
type LogoutConfig struct {
	Sessions users.SessionStore
	Secure   bool
}

// Logout deletes the session row, clears the session cookie, and
// redirects to "/". Intentionally accepts both GET and POST:
//   - GET is convenient for a plain <a href="/logout"> link from the
//     landing page
//   - POST is the RFC-stricter form that CSRF protection would usually
//     gate; we don't gate it here because /logout doesn't change anything
//     beyond terminating the user's own session (no lateral damage to
//     other users; nothing an attacker gains from forcing a victim to
//     log out beyond annoyance).
//
// No session → no-op 302 to /. Graceful.
func Logout(cfg LogoutConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sess := SessionFromContext(r.Context()); sess != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := cfg.Sessions.Delete(ctx, sess.ID); err != nil {
				// Non-fatal — we'll still clear the cookie; the stale
				// session row will time out on its own TTL.
				slog.WarnContext(r.Context(), "logout: delete session", "err", err)
			}
		}
		ClearSessionCookie(w, cfg.Secure)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
