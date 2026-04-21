package oidc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mhockenbury/identity-provider/internal/oidc"
	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// fakeKeyStore implements oidc.JWKSKeyStore without a DB. Tests can
// inject a list, or an error, or both.
type fakeKeyStore struct {
	keys []*tokens.SigningKey
	err  error
}

func (f *fakeKeyStore) ForJWKS(ctx context.Context) ([]*tokens.SigningKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.keys, nil
}

func makeKey(t *testing.T, kid string) *tokens.SigningKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &tokens.SigningKey{
		KID: kid, Alg: tokens.AlgEdDSA, PublicKey: pub,
		CreatedAt: time.Now(),
	}
}

func TestJWKSHandler_ServesJWKS(t *testing.T) {
	store := &fakeKeyStore{keys: []*tokens.SigningKey{
		makeKey(t, "k_1"),
		makeKey(t, "k_2"),
	}}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	oidc.JWKSHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}

	var jwks tokens.JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Errorf("Keys = %d, want 2", len(jwks.Keys))
	}
	kids := map[string]bool{}
	for _, k := range jwks.Keys {
		kids[k.Kid] = true
	}
	if !kids["k_1"] || !kids["k_2"] {
		t.Errorf("missing kids in response: %v", kids)
	}
}

// Empty key set is a valid state — the IdP might be freshly started with
// no keys activated. The handler must return 200 with keys:[] not an error.
func TestJWKSHandler_EmptyKeySetReturns200(t *testing.T) {
	store := &fakeKeyStore{keys: nil}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	oidc.JWKSHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"keys":[]`) {
		t.Errorf("empty response should have keys:[], got %s", rec.Body.String())
	}
}

// Store errors become 500. Handler must not leak error details in the
// response body — just log and return a generic error.
func TestJWKSHandler_StoreErrorBecomes500(t *testing.T) {
	store := &fakeKeyStore{err: errors.New("db down")}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	oidc.JWKSHandler(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "db down") {
		t.Errorf("handler leaked error detail: %s", rec.Body.String())
	}
}

// Response must be parseable by tokens.ParseJWKS — that's the contract
// downstream services rely on. Exercises the full build→serve→parse path.
func TestJWKSHandler_OutputParsedByDownstream(t *testing.T) {
	k := makeKey(t, "k_downstream")
	store := &fakeKeyStore{keys: []*tokens.SigningKey{k}}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	oidc.JWKSHandler(store).ServeHTTP(rec, req)

	parsed, err := tokens.ParseJWKS(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(parsed.Keys) != 1 {
		t.Fatalf("parsed keys = %d", len(parsed.Keys))
	}
	// Recover the public key and confirm it matches.
	got, err := parsed.Keys[0].PublicKey()
	if err != nil {
		t.Fatalf("JWK.PublicKey: %v", err)
	}
	if !equalBytes(got, k.PublicKey) {
		t.Error("recovered public key does not match original")
	}
}

func equalBytes(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
