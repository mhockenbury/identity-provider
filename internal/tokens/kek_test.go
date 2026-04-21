package tokens

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func makeKEK(t *testing.T) *EnvKEK {
	t.Helper()
	key := make([]byte, KEKKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	kek, err := NewEnvKEK(key)
	if err != nil {
		t.Fatalf("NewEnvKEK: %v", err)
	}
	return kek
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	kek := makeKEK(t)

	payload := []byte("ed25519-private-key-bytes-32xxx!")
	kid := "k_abcdef012345"

	blob, err := kek.Wrap(payload, kid)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := kek.Unwrap(blob, kid)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round trip mismatch: got %x, want %x", got, payload)
	}
}

func TestWrap_DifferentNonceEachCall(t *testing.T) {
	// Same plaintext, same kid, same KEK — ciphertexts must differ because
	// the nonce is fresh per call. This is a security property, not an
	// implementation detail.
	kek := makeKEK(t)
	payload := []byte("same-input-every-time")

	a, _ := kek.Wrap(payload, "k1")
	b, _ := kek.Wrap(payload, "k1")

	if bytes.Equal(a, b) {
		t.Error("two Wrap calls with identical inputs produced identical ciphertexts; nonce is not fresh")
	}
}

func TestUnwrap_WrongKidFails(t *testing.T) {
	// The kid is bound into the GCM tag via AAD; using the wrong kid
	// at unwrap time must fail authentication.
	kek := makeKEK(t)
	blob, err := kek.Wrap([]byte("secret"), "correct-kid")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, err = kek.Unwrap(blob, "different-kid")
	if !errors.Is(err, ErrCiphertextTampered) {
		t.Errorf("err = %v, want ErrCiphertextTampered", err)
	}
}

func TestUnwrap_WrongKEKFails(t *testing.T) {
	// A blob sealed under one KEK must not open under a different KEK,
	// even with the correct kid. This is the main confidentiality claim.
	kek1 := makeKEK(t)
	kek2 := makeKEK(t)

	blob, err := kek1.Wrap([]byte("secret"), "k1")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, err = kek2.Unwrap(blob, "k1")
	if !errors.Is(err, ErrCiphertextTampered) {
		t.Errorf("err = %v, want ErrCiphertextTampered", err)
	}
}

func TestUnwrap_TamperedCiphertextFails(t *testing.T) {
	kek := makeKEK(t)
	blob, err := kek.Wrap([]byte("secret"), "k1")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Flip one byte somewhere in the ciphertext body (past the nonce).
	tampered := make([]byte, len(blob))
	copy(tampered, blob)
	tampered[gcmNonceLength+1] ^= 0xff

	_, err = kek.Unwrap(tampered, "k1")
	if !errors.Is(err, ErrCiphertextTampered) {
		t.Errorf("err = %v, want ErrCiphertextTampered", err)
	}
}

func TestUnwrap_TruncatedBlobFails(t *testing.T) {
	kek := makeKEK(t)

	cases := [][]byte{
		nil,
		{},
		make([]byte, 5),                      // < nonce length
		make([]byte, gcmNonceLength),         // nonce only, no ciphertext
		make([]byte, gcmNonceLength+5),       // < GCM overhead after nonce
	}
	for _, c := range cases {
		_, err := kek.Unwrap(c, "k1")
		if !errors.Is(err, ErrCiphertextTampered) {
			t.Errorf("len=%d: err = %v, want ErrCiphertextTampered", len(c), err)
		}
	}
}

func TestNewEnvKEK_RejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		t.Run(strings.TrimSpace("len-"), func(t *testing.T) {
			_, err := NewEnvKEK(make([]byte, n))
			if !errors.Is(err, ErrInvalidKEK) {
				t.Errorf("len=%d: err = %v, want ErrInvalidKEK", n, err)
			}
		})
	}
}

func TestNewEnvKEKFromHex_ParsesValidHex(t *testing.T) {
	// 32 bytes → 64 hex chars.
	raw := make([]byte, KEKKeyLength)
	for i := range raw {
		raw[i] = byte(i)
	}
	hexKey := hex.EncodeToString(raw)

	kek, err := NewEnvKEKFromHex(hexKey)
	if err != nil {
		t.Fatalf("NewEnvKEKFromHex: %v", err)
	}

	// Sanity: round trip still works with this constructed key.
	blob, err := kek.Wrap([]byte("x"), "k1")
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := kek.Unwrap(blob, "k1"); err != nil {
		t.Errorf("Unwrap: %v", err)
	}
}

func TestNewEnvKEKFromHex_RejectsBadInput(t *testing.T) {
	cases := []string{
		"",                  // empty
		"not-hex",           // not hex at all
		"abcd",              // right charset, wrong length (2 bytes)
		strings.Repeat("a", 63), // odd number of chars (invalid hex length)
		strings.Repeat("a", 62), // 31 bytes: parses OK but wrong key length
		strings.Repeat("z", 64), // correct length, invalid hex chars
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := NewEnvKEKFromHex(c)
			if !errors.Is(err, ErrInvalidKEK) {
				t.Errorf("err = %v, want ErrInvalidKEK", err)
			}
		})
	}
}
