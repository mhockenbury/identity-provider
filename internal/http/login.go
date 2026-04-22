package http

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/csrf"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// LoginConfig wires the login handlers. Handlers are small; the config is
// what makes them testable — inject a user store, session store, and the
// base URL for same-origin return_to validation.
type LoginConfig struct {
	Users     users.Store
	Sessions  users.SessionStore
	Templates *Templates
	// BaseURL is the IdP's issuer URL. Used to reject return_to values
	// that don't share the same scheme+host+port; that's the defense
	// against open-redirect attacks via /login?return_to=evil.com.
	BaseURL    string
	SessionTTL time.Duration
	// Secure is true when the server is reached over https. Passed to
	// SetSessionCookie.
	Secure bool
}

// loginPage carries the data html/template gets for templates/login.html.
type loginPage struct {
	CSRFField    template.HTML // from csrf.TemplateField
	ReturnTo     string
	Email        string
	ErrorMessage string
}

// LoginGET handles rendering the login form. Accepts ?return_to=... so
// /authorize can redirect here and come back after successful login.
func LoginGET(cfg LoginConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		returnTo := validateReturnTo(r.URL.Query().Get("return_to"), cfg.BaseURL)

		renderLogin(w, r, cfg.Templates, loginPage{
			CSRFField: csrf.TemplateField(r),
			ReturnTo:  returnTo,
		})
	}
}

// LoginPOST verifies credentials and creates a session on success.
//
// On failure we re-render the login form with a generic error message
// AND keep the email field pre-populated for UX. The error is deliberately
// identical for "no such user" and "wrong password" — avoids user
// enumeration.
func LoginPOST(cfg LoginConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		email := r.PostFormValue("email")
		password := r.PostFormValue("password")
		returnTo := validateReturnTo(r.PostFormValue("return_to"), cfg.BaseURL)

		// Authenticate. ErrNotFound and ErrPasswordMismatch both map to
		// the same generic error — do not leak existence.
		u, err := cfg.Users.Authenticate(r.Context(), email, password)
		if err != nil {
			if !errors.Is(err, users.ErrNotFound) && !errors.Is(err, users.ErrPasswordMismatch) {
				slog.ErrorContext(r.Context(), "login authenticate", "err", err)
			}
			// Generic message; don't echo whether email existed.
			w.WriteHeader(http.StatusUnauthorized)
			renderLogin(w, r, cfg.Templates, loginPage{
				CSRFField:    csrf.TemplateField(r),
				ReturnTo:     returnTo,
				Email:        email,
				ErrorMessage: "Invalid email or password.",
			})
			return
		}

		// Successful auth. Create session, set cookie, redirect.
		sessCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		sess, err := cfg.Sessions.Create(sessCtx, u.ID, cfg.SessionTTL)
		if err != nil {
			slog.ErrorContext(r.Context(), "login create session", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		SetSessionCookie(w, sess.ID, cfg.Secure)

		// Fall back to "/" if return_to was empty or rejected.
		if returnTo == "" {
			returnTo = "/"
		}
		http.Redirect(w, r, returnTo, http.StatusFound)
	}
}

// renderLogin executes templates/login.html into a buffer first, then
// writes to the response. Buffering means a template error produces a
// clean 500 instead of a half-written page.
func renderLogin(w http.ResponseWriter, r *http.Request, t *Templates, data loginPage) {
	var buf bytes.Buffer
	if err := t.set.ExecuteTemplate(&buf, "login.html", data); err != nil {
		slog.ErrorContext(r.Context(), "render login template", "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Login form must never be cached; a fresh CSRF token per render.
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// validateReturnTo returns the return_to value iff it's same-origin with
// baseURL, else empty string. Open-redirect defense: without this check,
// /login?return_to=https://evil.com could phish users after successful login.
//
// The check normalizes both URLs — a relative path ("/authorize?...") is
// always same-origin; an absolute URL must match scheme + host + port.
//
// Returns empty string for anything invalid or cross-origin. Caller
// substitutes a default ("/" typically).
func validateReturnTo(raw, baseURL string) string {
	if raw == "" {
		return ""
	}
	// Relative URLs are always same-origin.
	ref, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	// Absolute URL: require scheme+host+port match.
	if ref.IsAbs() {
		base, err := url.Parse(baseURL)
		if err != nil {
			return ""
		}
		if ref.Scheme != base.Scheme || ref.Host != base.Host {
			return ""
		}
	}
	// Rewrite to path+query+fragment only (drop the host even on absolute
	// URLs) so downstream can redirect with a relative path.
	out := ref.Path
	if ref.RawQuery != "" {
		out += "?" + ref.RawQuery
	}
	if ref.Fragment != "" {
		out += "#" + ref.Fragment
	}
	// Path must start with "/"; "evil.com" without a scheme is a path-only
	// URL that would get treated as a relative path. Reject by requiring
	// a leading slash on the output.
	if out == "" || out[0] != '/' {
		return ""
	}
	return out
}
