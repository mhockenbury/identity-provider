package tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// KEK (Key Encryption Key) wraps signing-key private halves at rest via
// AES-256-GCM envelope encryption.
//
// Design posture (see docs/tradeoffs.md):
//   - 32-byte symmetric key loaded once at startup from the
//     JWT_SIGNING_KEY_ENCRYPTION_KEY env var (hex-encoded)
//   - This would be a KMS in production; the KEK interface is deliberately
//     small so swapping to KMS means changing the implementation only
//   - Wrapping binds `kid` as Additional Authenticated Data so blobs can't
//     be silently swapped between signing-key rows
//
// A compromise of the KEK compromises the signing authority. Protecting
// the env/process is outside this code's scope.

// KEKKeyLength is the required key size in bytes. AES-256 → 32 bytes.
const KEKKeyLength = 32

// gcmNonceLength is fixed at 12 bytes per NIST SP 800-38D §5.2.1.1.
const gcmNonceLength = 12

// ErrInvalidKEK indicates a malformed key at load time.
// ErrCiphertextTampered indicates GCM authentication failure at unwrap time
// (wrong key, wrong kid, corrupted blob, or truncated input).
var (
	ErrInvalidKEK         = errors.New("invalid KEK")
	ErrCiphertextTampered = errors.New("ciphertext failed authentication")
)

// KEK is the wrapping interface. Implementations can source keys however
// they like (env var, KMS, file). Wrap/Unwrap take a context identifier
// (kid) bound into the ciphertext as AAD so a blob for key A cannot
// verify under the identifier for key B — a cheap but effective defense
// against row-swap bugs.
type KEK interface {
	Wrap(plaintext []byte, kid string) ([]byte, error)
	Unwrap(ciphertext []byte, kid string) ([]byte, error)
}

// EnvKEK is the env-var-backed implementation. Single symmetric key, no
// rotation. The zero value is not usable — construct via NewEnvKEK.
type EnvKEK struct {
	aead cipher.AEAD
}

// NewEnvKEKFromHex parses a hex string (64 chars = 32 bytes) into a KEK.
// The string comes from JWT_SIGNING_KEY_ENCRYPTION_KEY or equivalent.
func NewEnvKEKFromHex(hexKey string) (*EnvKEK, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: hex decode: %v", ErrInvalidKEK, err)
	}
	return NewEnvKEK(key)
}

// NewEnvKEK wraps raw key bytes. Prefer NewEnvKEKFromHex at startup.
func NewEnvKEK(key []byte) (*EnvKEK, error) {
	if len(key) != KEKKeyLength {
		return nil, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidKEK, len(key), KEKKeyLength)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		// aes.NewCipher only errors on invalid key lengths, which we've
		// already filtered; map to our sentinel for consistency.
		return nil, fmt.Errorf("%w: aes: %v", ErrInvalidKEK, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: gcm: %v", ErrInvalidKEK, err)
	}
	return &EnvKEK{aead: aead}, nil
}

// Wrap encrypts plaintext under the KEK with kid bound as AAD. Output
// format: nonce || ciphertext_with_tag. Nonce is random per call.
func (k *EnvKEK) Wrap(plaintext []byte, kid string) ([]byte, error) {
	nonce := make([]byte, gcmNonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// Seal returns dst || ciphertext || tag. We pass nonce as dst so the
	// returned slice is already nonce-prefixed; avoids a concat.
	sealed := k.aead.Seal(nonce, nonce, plaintext, []byte(kid))
	return sealed, nil
}

// Unwrap decrypts a blob produced by Wrap under the same KEK and the same
// kid. Returns ErrCiphertextTampered on any mismatch: wrong KEK, wrong kid,
// corrupted ciphertext, or truncated input. Caller should not distinguish
// between these — they're all "this isn't what we sealed."
func (k *EnvKEK) Unwrap(ciphertext []byte, kid string) ([]byte, error) {
	if len(ciphertext) < gcmNonceLength+k.aead.Overhead() {
		return nil, fmt.Errorf("%w: blob too short (%d bytes)", ErrCiphertextTampered, len(ciphertext))
	}
	nonce, ct := ciphertext[:gcmNonceLength], ciphertext[gcmNonceLength:]

	plaintext, err := k.aead.Open(nil, nonce, ct, []byte(kid))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCiphertextTampered, err)
	}
	return plaintext, nil
}
