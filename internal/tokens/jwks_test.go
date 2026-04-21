package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// These tests exercise JWKS serialization/parsing in isolation — no DB,
// no real KeyStore. They stay in the tokens package (not tokens_test) so
// they can construct SigningKey values directly without an exported factory.

func makeTestSigningKey(t *testing.T, kid string) *SigningKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &SigningKey{
		KID:       kid,
		Alg:       AlgEdDSA,
		PublicKey: pub,
		CreatedAt: time.Now(),
	}
}

func TestBuildJWKS_ShapeMatchesRFC7517(t *testing.T) {
	k1 := makeTestSigningKey(t, "k_test1")
	k2 := makeTestSigningKey(t, "k_test2")

	jwks := BuildJWKS([]*SigningKey{k1, k2})

	if len(jwks.Keys) != 2 {
		t.Fatalf("Keys = %d, want 2", len(jwks.Keys))
	}

	for _, jwk := range jwks.Keys {
		if jwk.Kty != "OKP" {
			t.Errorf("Kty = %q, want OKP", jwk.Kty)
		}
		if jwk.Crv != "Ed25519" {
			t.Errorf("Crv = %q, want Ed25519", jwk.Crv)
		}
		if jwk.Use != "sig" {
			t.Errorf("Use = %q, want sig", jwk.Use)
		}
		if jwk.Alg != "EdDSA" {
			t.Errorf("Alg = %q, want EdDSA", jwk.Alg)
		}
		if jwk.Kid == "" {
			t.Errorf("Kid empty")
		}
		if jwk.X == "" {
			t.Errorf("X empty")
		}
		// X must be base64url, no padding.
		if strings.Contains(jwk.X, "=") || strings.Contains(jwk.X, "+") || strings.Contains(jwk.X, "/") {
			t.Errorf("X=%q is not base64url (no padding, url-safe chars)", jwk.X)
		}
	}
}

func TestBuildJWKS_EmptyInputProducesEmptyArray(t *testing.T) {
	// Not a nil-vs-empty-slice test — specifically checking that the JSON
	// encodes as `"keys":[]` and not `"keys":null`. Clients parsing the
	// document need a valid empty array, not a null they'd have to handle.
	jwks := BuildJWKS(nil)

	raw, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"keys":[]`) {
		t.Errorf("expected keys:[], got %s", raw)
	}
}

func TestBuildAndParse_RoundTrip(t *testing.T) {
	// Build a JWKS, serialize, parse back. The parsed PublicKey() must
	// match the original bytes for every key.
	k1 := makeTestSigningKey(t, "k_alpha")
	k2 := makeTestSigningKey(t, "k_beta")
	original := BuildJWKS([]*SigningKey{k1, k2})

	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	parsed, err := ParseJWKS(raw)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}

	if len(parsed.Keys) != 2 {
		t.Fatalf("round-trip key count = %d, want 2", len(parsed.Keys))
	}

	// Re-extract public keys from parsed JWKS and compare to originals.
	byKID := map[string]ed25519.PublicKey{k1.KID: k1.PublicKey, k2.KID: k2.PublicKey}
	for _, jwk := range parsed.Keys {
		want, ok := byKID[jwk.Kid]
		if !ok {
			t.Errorf("unexpected kid in parsed JWKS: %q", jwk.Kid)
			continue
		}
		got, err := jwk.PublicKey()
		if err != nil {
			t.Errorf("JWK.PublicKey: %v", err)
			continue
		}
		if !publicKeysEqual(got, want) {
			t.Errorf("kid=%q: round-trip public key mismatch", jwk.Kid)
		}
	}
}

func TestJWK_PublicKey_RejectsWrongKty(t *testing.T) {
	jwk := JWK{Kty: "RSA", Crv: "Ed25519", X: "anything"}
	if _, err := jwk.PublicKey(); err == nil {
		t.Error("expected error for non-OKP kty")
	}
}

func TestJWK_PublicKey_RejectsWrongCurve(t *testing.T) {
	jwk := JWK{Kty: "OKP", Crv: "X25519", X: "anything"}
	if _, err := jwk.PublicKey(); err == nil {
		t.Error("expected error for non-Ed25519 curve")
	}
}

func TestJWK_PublicKey_RejectsMalformedX(t *testing.T) {
	jwk := JWK{Kty: "OKP", Crv: "Ed25519", X: "not@valid@base64!"}
	if _, err := jwk.PublicKey(); err == nil {
		t.Error("expected error for malformed X")
	}
}

func TestJWK_PublicKey_RejectsWrongSize(t *testing.T) {
	// Valid base64url but wrong byte length — Ed25519 public keys are 32 bytes.
	jwk := JWK{Kty: "OKP", Crv: "Ed25519", X: "Zm9vYmFy"} // "foobar" = 6 bytes
	if _, err := jwk.PublicKey(); err == nil {
		t.Error("expected error for wrong key size")
	}
}

func publicKeysEqual(a, b ed25519.PublicKey) bool {
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
