package http

import (
	"bytes"
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/csrf"

	"github.com/mhockenbury/identity-provider/internal/consent"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// ConsentConfig wires the consent handlers.
//
// ClientsLookup is a narrow interface over what the clients package
// provides, so the consent handler can verify client existence + read
// the display id without dragging the whole clients.Store type in as
// a hard dep.
type ConsentConfig struct {
	Consent   consent.Store
	Users     users.Store
	Clients   ClientLookup
	Templates *Templates
	BaseURL   string
}

// ClientLookup is the narrow surface the consent handler actually
// needs from the clients package.
type ClientLookup interface {
	GetByID(ctx context.Context, id string) (ClientDisplay, error)
}

// ClientDisplay is the subset of client fields we show or verify at
// consent time. Package internal/clients provides a tiny adapter to
// produce this.
type ClientDisplay struct {
	ID           string
	RedirectURIs []string
}

// consentPage carries the data html/template gets for consent.html.
type consentPage struct {
	CSRFField   template.HTML
	ClientID    string
	UserEmail   string
	Scopes      []string
	RedirectURI string
	State       string
	ReturnTo    string
}

// ConsentGET renders the consent form. Requires an authenticated session
// (WithSession middleware attached upstream). Redirects to /login?return_to=...
// if the user isn't logged in.
//
// Required query params:
//   client_id, redirect_uri, scope (space-separated), return_to
// Optional: state
//
// The /authorize handler passes all of these through — /consent is
// effectively an internal continuation of that flow.
func ConsentGET(cfg ConsentConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess == nil {
			// Not logged in. Loop back to /login with return_to pointing at
			// THIS URL so we come back here after login.
			redirectToLogin(w, r)
			return
		}

		q := r.URL.Query()
		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		scopeRaw := q.Get("scope")
		state := q.Get("state")
		returnTo := validateReturnTo(q.Get("return_to"), cfg.BaseURL)

		if clientID == "" || redirectURI == "" || scopeRaw == "" {
			http.Error(w, "missing required params", http.StatusBadRequest)
			return
		}

		// Verify client exists + the redirect_uri we're asked to later
		// redirect to is one the client registered. Prevents a tampered
		// consent URL from directing error responses to an attacker's site.
		client, err := cfg.Clients.GetByID(r.Context(), clientID)
		if err != nil {
			http.Error(w, "unknown client", http.StatusBadRequest)
			return
		}
		if !containsExact(client.RedirectURIs, redirectURI) {
			http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
			return
		}

		scopes := strings.Fields(scopeRaw)

		// Load user for display.
		u, err := cfg.Users.GetByID(r.Context(), sess.UserID)
		if err != nil {
			slog.ErrorContext(r.Context(), "consent get user", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		renderConsent(w, r, cfg.Templates, consentPage{
			CSRFField:   csrf.TemplateField(r),
			ClientID:    clientID,
			UserEmail:   u.Email,
			Scopes:      scopes,
			RedirectURI: redirectURI,
			State:       state,
			ReturnTo:    returnTo,
		})
	}
}

// ConsentPOST records the approve/deny decision and redirects.
//
// Approve: upsert consent row + redirect to return_to (which is our own
// /authorize URL with the original params so authorize can finish the
// flow).
//
// Deny: redirect to the client's registered redirect_uri with
// error=access_denied per RFC 6749 §4.1.2.1.
func ConsentPOST(cfg ConsentConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := SessionFromContext(r.Context())
		if sess == nil {
			redirectToLogin(w, r)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}

		decision := r.PostFormValue("decision")
		clientID := r.PostFormValue("client_id")
		redirectURI := r.PostFormValue("redirect_uri")
		state := r.PostFormValue("state")
		returnTo := validateReturnTo(r.PostFormValue("return_to"), cfg.BaseURL)
		scopes := r.PostForm["scope"] // repeated field, one per scope

		if clientID == "" || redirectURI == "" {
			http.Error(w, "missing required params", http.StatusBadRequest)
			return
		}

		// Re-verify the redirect_uri against the client's allow list.
		// Forms are user-controlled; never skip this just because GET
		// already checked. Defense in depth.
		client, err := cfg.Clients.GetByID(r.Context(), clientID)
		if err != nil {
			http.Error(w, "unknown client", http.StatusBadRequest)
			return
		}
		if !containsExact(client.RedirectURIs, redirectURI) {
			http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
			return
		}

		switch decision {
		case "approve":
			// Gate the `admin` scope: only is_admin users can grant it.
			// We silently filter rather than erroring — non-admins simply
			// don't get the scope, which the admin API will then reject
			// at request time. Cleaner UX than a "you can't have admin"
			// error page on the consent screen.
			grantScopes := scopes
			if containsExact(scopes, "admin") {
				u, err := cfg.Users.GetByID(r.Context(), sess.UserID)
				if err != nil {
					slog.ErrorContext(r.Context(), "consent: get user for admin gate", "err", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				if !u.IsAdmin {
					grantScopes = filterScope(scopes, "admin")
					slog.InfoContext(r.Context(), "consent: dropped admin scope (user not admin)",
						"user_id", sess.UserID, "client_id", clientID)
				}
			}
			if err := cfg.Consent.Grant(r.Context(), sess.UserID, clientID, grantScopes); err != nil {
				slog.ErrorContext(r.Context(), "consent grant", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if returnTo == "" {
				returnTo = "/"
			}
			http.Redirect(w, r, returnTo, http.StatusFound)

		case "deny":
			// RFC 6749 §4.1.2.1: redirect back to the client with
			// error=access_denied + the original state.
			u, _ := url.Parse(redirectURI)
			q := u.Query()
			q.Set("error", "access_denied")
			q.Set("error_description", "The user denied the request.")
			if state != "" {
				q.Set("state", state)
			}
			u.RawQuery = q.Encode()
			// redirectURI was already validated against client.RedirectURIs
			// at line 165 (containsExact check); SonarCloud's dataflow
			// can't see across the helper. Open-redirect not possible.
			http.Redirect(w, r, u.String(), http.StatusFound) // NOSONAR S5146 — exact-match allowlist enforced upstream

		default:
			http.Error(w, "invalid decision", http.StatusBadRequest)
		}
	}
}

// redirectToLogin sends the browser to /login?return_to=<current url>.
// Used by consent handlers when the session is missing/expired.
func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.RequestURI()
	http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
}

// renderConsent buffers the template into memory before writing so a
// template error produces a clean 500.
func renderConsent(w http.ResponseWriter, r *http.Request, t *Templates, data consentPage) {
	var buf bytes.Buffer
	if err := t.set.ExecuteTemplate(&buf, "consent.html", data); err != nil {
		slog.ErrorContext(r.Context(), "render consent template", "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// containsExact reports whether s contains v exactly (no substring match,
// no normalization). Used for redirect_uri checks; exact match is what
// RFC 6749 §3.1.2.2 requires.
func containsExact(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// filterScope returns a new slice with all occurrences of v removed.
// Used by the admin-scope gate at consent time.
func filterScope(s []string, v string) []string {
	out := make([]string, 0, len(s))
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
