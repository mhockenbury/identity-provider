package http

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// LogoutConfig wires the logout handler.
type LogoutConfig struct {
	Sessions users.SessionStore
	Secure   bool
	// Clients is used to validate post_logout_redirect_uri against the
	// client's registered redirect URIs. Nil → post_logout_redirect_uri
	// is ignored (always land on "/"). In production you'd want a
	// dedicated post_logout_redirect_uris allowlist; we reuse
	// redirect_uris as a deliberate shortcut for the lab.
	Clients ClientLookup
}

// Logout deletes the session row, clears the session cookie, and
// redirects to either post_logout_redirect_uri (if validated) or "/".
// Implements the RP-initiated logout side of the OpenID Connect
// RP-Initiated Logout 1.0 spec, minus the id_token_hint gate (we
// don't require it for this lab).
//
// Accepted params (optional, all from query string):
//   - post_logout_redirect_uri: where to redirect after logout. Must
//     match one of the client's registered redirect_uris.
//   - client_id: which client is requesting logout. Required if
//     post_logout_redirect_uri is set (so we can validate the URI).
//   - state: echoed back on the post-logout redirect, OIDC-style.
//
// Accepts both GET and POST:
//   - GET is what oidc-client-ts (and most SPA libs) use for signoutRedirect
//   - POST is what a strict RFC-following RP would use
//
// No session → no-op redirect. Graceful.
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

		// Accept params from GET query or POST form. resolvePostLogoutRedirect
		// validates any user-supplied URI against the client's registered
		// redirect_uris and falls back to "/" on any mismatch — SonarCloud's
		// dataflow can't see through the helper. Open-redirect not possible.
		redirectTo := resolvePostLogoutRedirect(r, cfg.Clients)
		http.Redirect(w, r, redirectTo, http.StatusFound) // NOSONAR S5146 — exact-match allowlist enforced in resolvePostLogoutRedirect
	}
}

// resolvePostLogoutRedirect returns the URL to redirect to after logout.
// Validates post_logout_redirect_uri against the requesting client's
// registered redirect_uris; falls back to "/" on any mismatch.
// Appends the state param if both state and the validated URI are present.
func resolvePostLogoutRedirect(r *http.Request, clients ClientLookup) string {
	const fallback = "/"
	if clients == nil {
		return fallback
	}

	// Query string for GET; form body for POST. ParseForm handles both.
	if err := r.ParseForm(); err != nil {
		return fallback
	}

	uriStr := r.Form.Get("post_logout_redirect_uri")
	clientID := r.Form.Get("client_id")
	state := r.Form.Get("state")

	if uriStr == "" || clientID == "" {
		return fallback
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	client, err := clients.GetByID(ctx, clientID)
	if err != nil {
		slog.InfoContext(r.Context(), "logout: client lookup failed",
			"client_id", clientID, "err", err)
		return fallback
	}

	// Exact-match check against the registered redirect URIs.
	allowed := false
	for _, uri := range client.RedirectURIs {
		if uri == uriStr {
			allowed = true
			break
		}
	}
	if !allowed {
		slog.InfoContext(r.Context(), "logout: post_logout_redirect_uri not registered",
			"client_id", clientID, "uri", uriStr)
		return fallback
	}

	if state == "" {
		return uriStr
	}

	// Append state as a query param. Use url.Parse to handle URIs that
	// already have query parameters.
	u, err := url.Parse(uriStr)
	if err != nil {
		return uriStr
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}
