package main

// Auth middleware for docs-api.
//
// Two independent pieces:
//
//   authenticate  — parses Authorization: Bearer <token>, verifies via
//                   tokens.Verifier (which talks to our JWKS cache),
//                   and stashes the verified claims in the request ctx.
//                   Unauthenticated requests get 401.
//
//   requireScope  — reads claims from ctx, checks the scope claim
//                   contains the named scope (RFC 6749 §3.3 space-sep).
//                   Missing scope → 403.
//
// Split on purpose: authenticate runs on *every* protected route;
// requireScope is per-route (different endpoints require different
// scopes: read:docs, write:docs, etc.).

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// claimsKey is the ctx key under which verified claims are stored. Using
// a private unexported type means no other package can collide with it
// by accident.
type claimsKey struct{}

// claimsFromCtx retrieves claims placed by authenticate. Handlers call
// this after the middleware runs; returns nil if called outside a
// protected route (shouldn't happen in practice).
func claimsFromCtx(ctx context.Context) *tokens.AccessClaims {
	c, _ := ctx.Value(claimsKey{}).(*tokens.AccessClaims)
	return c
}

// authenticate is the middleware that verifies an incoming access token
// and populates the request context with claims. Any downstream handler
// can pull them via claimsFromCtx.
//
// Error mapping:
//   - missing / malformed header          → 401 invalid_request
//   - expired / bad signature / bad aud   → 401 invalid_token
//   - unknown issuer (not on allowlist)   → 401 invalid_token
//
// Always responds with a JSON error body and the standard
// WWW-Authenticate: Bearer header per RFC 6750 §3. Body shape:
// {"error":"invalid_token","error_description":"..."}.
func authenticate(verifier *tokens.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, err := bearerFromRequest(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid_request", err.Error())
				return
			}

			claims, err := verifier.Verify(r.Context(), raw)
			if err != nil {
				// Log the specific reason at info — useful during dev; the
				// client only sees "invalid_token" to avoid leaking why.
				slog.InfoContext(r.Context(), "token verification failed", "err", err)
				writeAuthError(w, http.StatusUnauthorized, "invalid_token", classifyVerifyErr(err))
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// requireScope returns middleware that 403s when the authenticated
// token's scope claim doesn't contain `want`. Must run AFTER authenticate
// (reads claims from ctx).
//
// Per RFC 6749 §3.3, scopes are space-separated. We split on whitespace
// (handles tab + newline too) and require exact match — no hierarchical
// matching ("read:docs" does NOT match "read"). Keeps the policy
// explicit; if we ever want hierarchy we add an opt-in.
func requireScope(want string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsFromCtx(r.Context())
			if claims == nil {
				// Programming error: requireScope without authenticate.
				writeAuthError(w, http.StatusInternalServerError, "server_error", "missing claims in context")
				return
			}
			if !hasScope(claims.Scope, want) {
				writeAuthError(w, http.StatusForbidden, "insufficient_scope", "required scope: "+want)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- helpers ---

// bearerFromRequest returns the token from an Authorization: Bearer <x>
// header. Accepts the header case-insensitively but requires the scheme
// "Bearer" (case-sensitive per RFC 6750).
//
// Distinguishes "missing header" from "wrong scheme" so logs are clearer.
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

// hasScope splits `scope` on whitespace and reports whether `want` is
// present. Empty scope claim → always false.
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

// classifyVerifyErr turns a verifier error into a short error_description
// suitable for logging AND returning to the caller. Doesn't leak which
// sentinel matched to the WWW-Authenticate body — all verification
// failures look the same to the client (just "invalid_token").
func classifyVerifyErr(err error) string {
	switch {
	case errors.Is(err, tokens.ErrIssuerMismatch):
		return "issuer not on allowlist"
	case errors.Is(err, tokens.ErrUnknownKID):
		return "unknown signing key"
	case errors.Is(err, tokens.ErrUnexpectedAlg):
		return "unsupported algorithm"
	case errors.Is(err, tokens.ErrAudienceMissing):
		return "audience mismatch"
	default:
		// Catches signature failures, expired tokens, malformed JWTs.
		return "token invalid or expired"
	}
}

// writeAuthError emits an RFC 6750-style JSON error response. Sets the
// WWW-Authenticate header with the error code (required for 401s,
// helpful on 403s per RFC 6750 §3).
func writeAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("content-type", "application/json")
	// WWW-Authenticate is REQUIRED on 401 (RFC 6750 §3), conventional
	// on 403 for the same kinds of errors.
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
