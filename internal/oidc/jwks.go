package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// JWKSKeyStore is the narrow surface the JWKS handler needs. Typed here
// rather than imported as *tokens.KeyStore so tests can substitute a
// fake without a live Postgres.
type JWKSKeyStore interface {
	ForJWKS(ctx context.Context) ([]*tokens.SigningKey, error)
}

// JWKSHandler serves /.well-known/jwks.json. Each request hits the store —
// no in-process caching on the server side. Clients cache via HTTP
// (Cache-Control header below) and via their own JWKS-cache logic;
// the server stays simple.
//
// Response is always 200 with a valid JWKS, even if the key set is empty.
// An empty set is a legitimate state ("IdP has no active keys, can't
// verify anything right now"), distinct from an error.
func JWKSHandler(store JWKSKeyStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		keys, err := store.ForJWKS(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "jwks: fetch keys", "err", err)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		jwks := tokens.BuildJWKS(keys)
		body, _ := json.Marshal(jwks) // serializing a validated struct cannot fail

		w.Header().Set("Content-Type", "application/json")
		// Aggressive cache: downstream services cache JWKS; 5 minutes is a
		// common default. Rotation is not invalidated by Cache-Control —
		// downstream clients must refetch on unknown kid too (docs-api does).
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}
