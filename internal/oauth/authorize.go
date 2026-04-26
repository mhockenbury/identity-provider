package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/clients"
	"github.com/mhockenbury/identity-provider/internal/consent"
)

// AuthorizeConfig wires the /authorize handler.
//
// Handlers depend on these narrow interfaces rather than concrete types
// so the flow can be unit-tested without a DB. Production wiring passes
// the real store adapters in cmd/idp.
type AuthorizeConfig struct {
	Clients      ClientStore
	Consent      consent.Store
	AuthCodes    AuthCodeStore
	CodeTTL      time.Duration
	// CurrentSessionUser returns the logged-in user's UUID, or uuid.Nil +
	// false if the request is anonymous. Typically reads the session from
	// the request context (populated by the session middleware).
	CurrentSessionUser func(r *http.Request) (uuid.UUID, bool)
}

// ClientStore is the subset of the clients package the /authorize handler
// needs. Methods are a direct subset of clients.PostgresStore.
type ClientStore interface {
	GetByID(ctx context.Context, id string) (clients.Client, error)
}

// Authorize handles GET /authorize. This is the protocol glue that
// pulls together session, consent, and code issuance to walk the user
// through the auth-code flow.
//
// Per RFC 6749 §4.1.1 + OIDC Core §3.1.2.1. Flow:
//
//   1. Validate client_id + redirect_uri. If either is bad, we CANNOT
//      redirect the error back to the client (that's what the attacker
//      would want us to do) — render a plain error page instead.
//   2. Validate the rest of the params. From here on, errors redirect
//      to redirect_uri with ?error=...&state=... per §4.1.2.1.
//   3. If no session, redirect to /login?return_to=<this URL>.
//   4. If consent isn't on file for these exact scopes, redirect to
//      /consent?... passing enough state to continue the flow.
//   5. Issue a code, redirect to redirect_uri with ?code=...&state=...
func Authorize(cfg AuthorizeConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")

		// Step 1: client + redirect_uri. These must both check out
		// before we can safely redirect errors anywhere.
		if clientID == "" || redirectURI == "" {
			http.Error(w, "missing client_id or redirect_uri", http.StatusBadRequest)
			return
		}

		client, err := cfg.Clients.GetByID(r.Context(), clientID)
		if err != nil {
			if errors.Is(err, clients.ErrNotFound) {
				http.Error(w, "unknown client", http.StatusBadRequest)
				return
			}
			slog.ErrorContext(r.Context(), "authorize: get client", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := client.CheckRedirectURI(redirectURI); err != nil {
			http.Error(w, "redirect_uri not registered for this client", http.StatusBadRequest)
			return
		}

		// Step 2: other params. From here, errors redirect back to the
		// (now-trusted) redirect_uri with ?error=...
		responseType := q.Get("response_type")
		scopeRaw := q.Get("scope")
		state := q.Get("state")
		codeChallenge := q.Get("code_challenge")
		codeChallengeMethod := q.Get("code_challenge_method")
		nonce := q.Get("nonce")

		if responseType != "code" {
			redirectError(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
			return
		}
		if err := client.CheckGrant("authorization_code"); err != nil {
			redirectError(w, r, redirectURI, state, "unauthorized_client", "client not allowed to use authorization_code grant")
			return
		}
		if codeChallenge == "" || codeChallengeMethod == "" {
			redirectError(w, r, redirectURI, state, "invalid_request", "PKCE is required: code_challenge and code_challenge_method")
			return
		}
		if codeChallengeMethod != "S256" {
			redirectError(w, r, redirectURI, state, "invalid_request", "only S256 code_challenge_method is supported")
			return
		}

		scopes := strings.Fields(scopeRaw)
		if err := client.CheckScopes(scopes); err != nil {
			redirectError(w, r, redirectURI, state, "invalid_scope", err.Error())
			return
		}

		// Step 3: session. If anonymous, pivot to /login and return here.
		userID, loggedIn := cfg.CurrentSessionUser(r)
		if !loggedIn {
			http.Redirect(w, r, "/login?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}

		// Step 4: consent. Re-prompt if the scope set isn't fully covered
		// by prior consent.
		ok, err := cfg.Consent.HasScopes(r.Context(), userID, clientID, scopes)
		if err != nil {
			slog.ErrorContext(r.Context(), "authorize: consent check", "err", err)
			redirectError(w, r, redirectURI, state, "server_error", "consent check failed")
			return
		}
		if !ok {
			consentURL := buildConsentURL(r.URL.RequestURI(), clientID, redirectURI, state, scopes)
			http.Redirect(w, r, consentURL, http.StatusFound)
			return
		}

		// Step 5: issue code. Persist everything /token will need later:
		// the user, PKCE challenge, scopes, nonce.
		code, err := cfg.AuthCodes.Issue(r.Context(), NewAuthCodeInput{
			ClientID:            clientID,
			UserID:              userID,
			RedirectURI:         redirectURI,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Scopes:              scopes,
			Nonce:               nonce,
		}, cfg.CodeTTL)
		if err != nil {
			slog.ErrorContext(r.Context(), "authorize: issue code", "err", err)
			redirectError(w, r, redirectURI, state, "server_error", "could not issue code")
			return
		}

		// Redirect back to the client with the code + state.
		// redirectURI was validated against client.RedirectURIs earlier in
		// this handler (CheckRedirectURI exact-match per RFC 6749 §3.1.2.2);
		// SonarCloud's dataflow can't see that. Open-redirect not possible.
		u, _ := url.Parse(redirectURI)
		params := u.Query()
		params.Set("code", code)
		if state != "" {
			params.Set("state", state)
		}
		u.RawQuery = params.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound) // NOSONAR S5146 — exact-match allowlist enforced upstream
	}
}

// redirectError sends an OAuth error redirect back to the client per
// RFC 6749 §4.1.2.1. Safe to call only after redirect_uri has been
// validated; otherwise we'd be handing an attacker a redirection vector.
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// Should not happen — caller validated. Belt-and-suspenders.
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// buildConsentURL packs everything /consent needs into query params,
// plus a return_to that points back at this /authorize URL so the
// consent POST approve path brings the user right back here.
func buildConsentURL(authorizeURL, clientID, redirectURI, state string, scopes []string) string {
	v := url.Values{}
	v.Set("return_to", authorizeURL)
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	v.Set("scope", strings.Join(scopes, " "))
	if state != "" {
		v.Set("state", state)
	}
	return "/consent?" + v.Encode()
}

// Compile-time check that *clients.PostgresStore satisfies our narrow
// interface. Catches a later refactor that silently breaks the seam.
var _ ClientStore = (*clients.PostgresStore)(nil)

// Avoid "imported but not used" if fmt is dropped during edits.
var _ = fmt.Sprintf
