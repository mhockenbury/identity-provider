package tokens

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWKS (JSON Web Key Set) is the wire format at /.well-known/jwks.json.
// RFC 7517 §5.
//
// Downstream services fetch this document, cache it, and look up signing
// keys by kid when verifying tokens. The "kid" in a JWT's header must
// match a "kid" in this set.

// JWK is the JSON shape of a single key. Fields are per RFC 7517 §4 and
// RFC 8037 §2 (OKP key type for Ed25519).
//
// Fields that don't apply to Ed25519 (n, e for RSA; x, y for EC) are
// omitted via the json tag empty-omission. We issue only EdDSA keys,
// so only OKP/Ed25519 fields appear.
type JWK struct {
	// Kty is the key type. "OKP" for Octet Key Pair, used for Ed25519.
	Kty string `json:"kty"`

	// Crv is the curve, "Ed25519" for our case.
	Crv string `json:"crv"`

	// X is the public-key value, base64url (no padding) encoded.
	X string `json:"x"`

	// Kid is the key identifier — matches the JWT header "kid".
	Kid string `json:"kid"`

	// Use is the intended use: "sig" (signature) or "enc" (encryption).
	// Always "sig" for signing keys.
	Use string `json:"use"`

	// Alg is the algorithm this key is used with. "EdDSA" for Ed25519.
	Alg string `json:"alg"`
}

// JWKS wraps a list of keys. The only wrapping key is "keys".
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// BuildJWKS serializes a slice of SigningKeys into the JWKS wire format.
// Retired keys should already have been filtered out by the caller
// (SigningKey.ForJWKS does this). No validation here — we trust the
// input to be well-formed, which it is if it came from the KeyStore.
func BuildJWKS(keys []*SigningKey) JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		out.Keys = append(out.Keys, JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(k.PublicKey),
			Kid: k.KID,
			Use: "sig",
			Alg: k.Alg, // "EdDSA"
		})
	}
	return out
}

// ParseJWKS reads a JWKS JSON document into the wire struct. Used by
// downstream services that fetch and cache the set — tests simulate this
// path, and demo-api will use it for real when that's wired up.
func ParseJWKS(raw []byte) (JWKS, error) {
	var j JWKS
	if err := json.Unmarshal(raw, &j); err != nil {
		return JWKS{}, fmt.Errorf("unmarshal jwks: %w", err)
	}
	return j, nil
}

// PublicKey extracts the Ed25519 public key from a JWK. Returns an error
// if the key is the wrong type/curve or the X field is malformed base64.
// Used by the verifier's JWKS cache to resolve kid → public key.
func (j JWK) PublicKey() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" {
		return nil, fmt.Errorf("jwk: kty=%q, want OKP", j.Kty)
	}
	if j.Crv != "Ed25519" {
		return nil, fmt.Errorf("jwk: crv=%q, want Ed25519", j.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("jwk: decode x: %w", err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("jwk: x is %d bytes, want %d", len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}
