package http

import (
	"bytes"
	"log/slog"
	"net/http"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// IndexConfig wires the root-handler. All fields optional beyond Templates:
// Users lets the page show the logged-in email; nil disables that bit
// (renders "Not signed in" unconditionally).
type IndexConfig struct {
	Templates *Templates
	Users     users.Store
}

// indexPage is the template data for templates/index.html.
type indexPage struct {
	Email string
}

// Index renders the root landing page at GET /. Shows login state + a
// short list of protocol endpoints. Exists so a user who navigates to
// http://localhost:8080/ (by hand, after a successful login redirect
// to "/", or just out of curiosity) doesn't hit a bare 404.
//
// Deliberately not cacheable: the logged-in state changes between
// requests, and a proxy caching "anonymous" for a freshly-signed-in
// user would be a surprise.
func Index(cfg IndexConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only answer /; chi routes "/" specifically, but a fallthrough
		// from a missing route would hit here if NotFoundHandler routed
		// to us. Explicit check keeps the contract obvious.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		data := indexPage{}
		if sess := SessionFromContext(r.Context()); sess != nil && cfg.Users != nil {
			u, err := cfg.Users.GetByID(r.Context(), sess.UserID)
			if err == nil {
				data.Email = u.Email
			}
			// A lookup failure is non-fatal — the page still renders,
			// just as "not signed in." Logged for visibility.
			// (Unlike /userinfo where GetByID failure is a 401, the
			// landing page is informational and a stale session id
			// isn't security-sensitive here.)
			if err != nil {
				slog.InfoContext(r.Context(), "index: user lookup failed for active session", "err", err)
			}
		}

		var buf bytes.Buffer
		if err := cfg.Templates.set.ExecuteTemplate(&buf, "index.html", data); err != nil {
			slog.ErrorContext(r.Context(), "render index template", "err", err)
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = buf.WriteTo(w)
	}
}
