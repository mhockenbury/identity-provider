// Package admin implements the IdP's management JSON API. Endpoints
// live under /admin/api/* and are gated by:
//
//   1. A valid IdP-issued access token (via tokens.Verifier).
//   2. The token's scope claim contains `admin`.
//   3. The token's subject (user UUID) has is_admin=true in the DB.
//
// Three checks for defense in depth: the consent-time gate prevents
// non-admins from getting the scope in the first place, but the runtime
// is_admin check catches the case where someone is demoted between
// consent and the API call (token still valid until expiry).
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/tokens"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// claimsKey is the unexported ctx key under which verified claims live.
type claimsKey struct{}

// claimsFromCtx retrieves the verified AccessClaims placed by Authenticate.
func claimsFromCtx(ctx context.Context) *tokens.AccessClaims {
	c, _ := ctx.Value(claimsKey{}).(*tokens.AccessClaims)
	return c
}

// Authenticate parses Authorization: Bearer <jwt>, verifies it via the
// supplied verifier, then enforces:
//   - scope contains `admin`
//   - the subject's user row exists and is_admin=true
//
// Failures are returned as RFC 6750-style JSON errors with the
// appropriate WWW-Authenticate header.
func Authenticate(verifier *tokens.Verifier, store users.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := bearerFromRequest(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid_request", err.Error())
				return
			}

			claims, err := verifier.Verify(r.Context(), raw)
			if err != nil {
				slog.InfoContext(r.Context(), "admin api: token verify failed", "err", err)
				writeAuthError(w, http.StatusUnauthorized, "invalid_token", "token invalid or expired")
				return
			}

			if !hasScope(claims.Scope, "admin") {
				writeAuthError(w, http.StatusForbidden, "insufficient_scope", "required scope: admin")
				return
			}

			// Defense-in-depth is_admin check. If the user was demoted
			// after the token was issued, this rejects the call.
			subID, err := uuid.Parse(claims.Subject)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid_token", "subject not a UUID")
				return
			}
			u, err := store.GetByID(r.Context(), subID)
			if err != nil {
				if errors.Is(err, users.ErrNotFound) {
					writeAuthError(w, http.StatusUnauthorized, "invalid_token", "user not found")
					return
				}
				slog.ErrorContext(r.Context(), "admin api: user lookup", "err", err)
				writeAuthError(w, http.StatusInternalServerError, "server_error", "lookup failed")
				return
			}
			if !u.IsAdmin {
				slog.InfoContext(r.Context(), "admin api: user demoted after token issued",
					"sub", claims.Subject)
				writeAuthError(w, http.StatusForbidden, "insufficient_scope", "user is not an admin")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// --- helpers (parallel to cmd/docs-api/auth.go; kept local to avoid
// cross-package coupling) ---

func bearerFromRequest(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", errors.New("Authorization header must use Bearer scheme")
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", errors.New("empty bearer token")
	}
	return tok, nil
}

func hasScope(scope, want string) bool {
	if scope == "" || want == "" {
		return false
	}
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func writeAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("content-type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
