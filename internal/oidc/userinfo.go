package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// UserInfoConfig wires the /userinfo handler.
type UserInfoConfig struct {
	Verifier  TokenVerifier
	UserStore UserInfoStore
}

// TokenVerifier is the narrow surface /userinfo needs to validate an
// access token. *tokens.Verifier satisfies this. The verifier MUST be
// configured with audience="" so it accepts tokens issued to any client
// (every client's token is valid for /userinfo).
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (*tokens.AccessClaims, error)
}

// UserInfoStore returns the identity claims for a user ID. Implemented
// by an adapter over users.Store in the wiring layer.
type UserInfoStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (UserInfoData, error)
}

// UserInfoData is the minimal shape /userinfo exposes. More fields go
// here as more scopes get implemented (profile → name, picture, etc.).
type UserInfoData struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
}

// userInfoResponse is the JSON shape per OIDC Core §5.3.1. Fields are
// omitted when the token's scope doesn't authorize them — `sub` is
// always present, everything else is scope-gated.
type userInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

// UserInfoHandler returns a handler for GET /userinfo.
//
// Flow:
//   1. Extract Bearer token from Authorization header (RFC 6750 §2.1).
//      Missing → 401 + WWW-Authenticate: Bearer.
//   2. Verify JWT: signature, exp, nbf, iss (via TokenVerifier). Invalid →
//      401 + WWW-Authenticate: Bearer error="invalid_token".
//   3. Require "openid" in the token's scope claim. Missing →
//      403 + WWW-Authenticate: Bearer error="insufficient_scope".
//   4. Parse sub as UUID, look up user. Unknown → 401 (treat as invalid
//      token; the user was deleted out from under us).
//   5. Filter claims by scope. Return 200 JSON.
//
// Per OIDC Core §5.3.2, the response Content-Type is application/json;
// signed responses (application/jwt) are a stretch we don't support.
func UserInfoHandler(cfg UserInfoConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := extractBearer(r)
		if !ok {
			writeBearerChallenge(w, http.StatusUnauthorized, "", "")
			return
		}

		claims, err := cfg.Verifier.Verify(r.Context(), raw)
		if err != nil {
			writeBearerChallenge(w, http.StatusUnauthorized, "invalid_token", err.Error())
			return
		}

		// Scope check: openid is required to hit /userinfo.
		scopes := strings.Fields(claims.Scope)
		if !slices.Contains(scopes, "openid") {
			writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope",
				"token requires the openid scope")
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			// Valid-signature tokens should always have parseable sub. If
			// we're here it's a bug upstream — either our own /token
			// emitted a malformed sub, or an attacker got a forged token
			// through verification (shouldn't be possible but let's not
			// assume). Log it for investigation; surface invalid_token.
			slog.ErrorContext(r.Context(), "userinfo: unparseable sub", "sub", claims.Subject, "err", err)
			writeBearerChallenge(w, http.StatusUnauthorized, "invalid_token", "")
			return
		}

		u, err := cfg.UserStore.GetByID(r.Context(), userID)
		if err != nil {
			// Most likely the user was deleted. Treat as invalid_token
			// rather than leaking existence info.
			slog.InfoContext(r.Context(), "userinfo: user lookup failed", "sub", userID, "err", err)
			writeBearerChallenge(w, http.StatusUnauthorized, "invalid_token", "")
			return
		}

		// Build scope-filtered response. sub is always present.
		resp := userInfoResponse{
			Sub: u.ID.String(),
		}
		if slices.Contains(scopes, "email") {
			resp.Email = u.Email
			verified := u.EmailVerified
			resp.EmailVerified = &verified
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// extractBearer pulls the token out of "Authorization: Bearer <token>".
// Per RFC 6750 §2.1: scheme match is case-insensitive, single space separator.
// We also accept the lowercase "authorization" form that Go's header map
// normalizes anyway.
func extractBearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false
	}
	// Scheme (7 chars) + space + token. Case-insensitive scheme match.
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// writeBearerChallenge writes a 401/403 response with WWW-Authenticate
// formatted per RFC 6750 §3. errorCode and errorDesc are empty for the
// "no token supplied" case.
func writeBearerChallenge(w http.ResponseWriter, status int, errorCode, errorDesc string) {
	parts := []string{`Bearer realm="userinfo"`}
	if errorCode != "" {
		parts = append(parts, `error="`+escapeQuoted(errorCode)+`"`)
	}
	if errorDesc != "" {
		parts = append(parts, `error_description="`+escapeQuoted(errorDesc)+`"`)
	}
	if errorCode == "insufficient_scope" {
		parts = append(parts, `scope="openid"`)
	}
	w.Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
	w.WriteHeader(status)

	// Also return a JSON body for clients that don't read WWW-Authenticate.
	// Matches the same OAuth error shape /token uses.
	body := map[string]string{}
	if errorCode != "" {
		body["error"] = errorCode
	}
	if errorDesc != "" {
		body["error_description"] = errorDesc
	}
	if len(body) > 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

// escapeQuoted escapes backslash + double-quote for safe inclusion in a
// WWW-Authenticate quoted-string. Per RFC 7235 §2.1.
func escapeQuoted(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Compile-time proof that *tokens.Verifier satisfies TokenVerifier.
// UserInfoStore is satisfied by an adapter in cmd/idp.
var _ TokenVerifier = (*tokens.Verifier)(nil)
