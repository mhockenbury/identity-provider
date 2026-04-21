package tokens

import (
	"github.com/golang-jwt/jwt/v5"
)

// BaseClaims holds the RFC 7519 registered claims that every JWT we issue
// must have. Composed into AccessClaims and IDClaims rather than duplicated.
//
// Field tags use the standard JWT names so jwt-go's validator recognizes
// them for exp/nbf/iat auto-checks and we stay wire-compatible with any
// standard OIDC client library.
type BaseClaims struct {
	// RegisteredClaims carries iss, sub, aud, exp, nbf, iat, jti as
	// time.Time / []string / string — the library's typed wrapper around
	// RFC 7519 §4.1. We avoid re-declaring these fields ourselves so we
	// get the library's validation for free.
	jwt.RegisteredClaims
}

// AccessClaims is the payload of an access token (Authorization: Bearer).
// The scope field is space-separated per RFC 6749 §3.3. We store it as a
// string, not []string, because that's what the spec puts on the wire —
// clients that parse the token's claims expect a single string.
type AccessClaims struct {
	BaseClaims
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// IDClaims is the payload of an OpenID Connect ID token. Not sent to APIs;
// only the client consumes it for authentication state. Has identity
// claims (email, etc.) plus OIDC-specific fields (nonce, auth_time).
//
// OIDC Core §2 defines the full set; we carry a minimal subset.
type IDClaims struct {
	BaseClaims
	// Nonce is echoed from the /authorize request. Protects against token
	// replay: the client generates a nonce before the flow and verifies
	// the ID token carries the same value.
	Nonce string `json:"nonce,omitempty"`
	// AuthTime is when the user last authenticated (Unix seconds). The
	// client can use this to enforce its own max-age policy.
	AuthTime int64 `json:"auth_time,omitempty"`
	// Email + email_verified are OIDC "email" scope claims. Populated
	// when the client requested the "email" scope at /authorize.
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}
