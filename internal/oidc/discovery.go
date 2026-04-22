// Package oidc implements the OIDC-specific surface: discovery document,
// JWKS endpoint, ID token claims (shared via internal/tokens), userinfo.
package oidc

import (
	"encoding/json"
	"net/http"
)

// Discovery is the JSON shape of /.well-known/openid-configuration.
// Per OpenID Connect Discovery 1.0 §4. Field names match the spec exactly.
//
// We emit a conservative subset — only the fields we actually support.
// Extending this is safe (clients ignore unknown fields) but we avoid
// claiming support for things we haven't built: no registration_endpoint,
// no revocation_endpoint, no introspection.
//
// Content-Type MUST be application/json per §4.1 — we set it in the
// handler, not here. Cache-Control should be set to something sensible
// by the handler too.
type Discovery struct {
	// REQUIRED by spec.
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`

	// OPTIONAL but standard enough that omitting them causes client-side
	// warnings in mainstream libraries.
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
}

// DiscoveryConfig is the input to BuildDiscovery. Keeps the endpoint-URL
// construction in one place and makes the handler trivially testable
// without a live server.
type DiscoveryConfig struct {
	// Issuer is the issuer URL. Must match the `iss` claim in every
	// token we sign. Clients canonicalize this, so avoid trailing slash.
	Issuer string

	// ScopesSupported advertises what the IdP will accept in /authorize.
	// Include all the scopes the seeded clients are allowed to request.
	ScopesSupported []string
}

// BuildDiscovery returns the Discovery document for the given config.
// Endpoint paths are hard-coded — they match internal/http router wiring.
// The handler JSON-encodes the result and serves it.
func BuildDiscovery(cfg DiscoveryConfig) Discovery {
	iss := cfg.Issuer
	return Discovery{
		Issuer:                iss,
		AuthorizationEndpoint: iss + "/authorize",
		TokenEndpoint:         iss + "/token",
		UserinfoEndpoint:      iss + "/userinfo",
		EndSessionEndpoint:    iss + "/logout",
		JWKSURI:               iss + "/.well-known/jwks.json",

		// We only support code flow; implicit and hybrid are deprecated
		// (OAuth 2.1 BCP) and out of scope.
		ResponseTypesSupported: []string{"code"},

		// We only issue pairwise or public subject identifiers. "public"
		// is the default shape — same sub across clients for the same user.
		SubjectTypesSupported: []string{"public"},

		// Matches our signing key alg (EdDSA / Ed25519).
		IDTokenSigningAlgValuesSupported: []string{"EdDSA"},

		ScopesSupported:                   cfg.ScopesSupported,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},

		// Conservative list — we emit these for sure; clients shouldn't
		// be surprised. Extended claims (email, email_verified, etc.)
		// appear when the relevant scope is requested.
		ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "jti", "nonce", "auth_time"},
	}
}

// Handler returns an http.Handler serving the discovery document at
// /.well-known/openid-configuration. The doc is computed once at handler
// construction since the inputs don't change after startup.
//
// Cache-Control: the spec recommends caching, and clients do cache
// aggressively. We set a short max-age (5 min) so rotating the issuer
// URL or adding scopes doesn't strand clients on a stale config.
func Handler(cfg DiscoveryConfig) http.Handler {
	doc := BuildDiscovery(cfg)
	body, _ := json.Marshal(doc) // marshaling a well-formed struct cannot fail

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}
