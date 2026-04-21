package users

import (
	"errors"
	"strings"
	"testing"
)

// Use a weaker parameter set for tests so they run fast. HashPassword encodes
// these into the output, so VerifyPassword will use them on the way back.
var testArgon2Params = Argon2Params{
	Memory:      8 * 1024, // 8 MiB — weak, just for test speed
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

func TestHashAndVerify_RoundTrip(t *testing.T) {
	encoded, err := HashPassword("correct-horse-battery-staple", testArgon2Params)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := VerifyPassword("correct-horse-battery-staple", encoded); err != nil {
		t.Errorf("VerifyPassword with correct password: %v", err)
	}
}

func TestVerify_WrongPasswordReturnsMismatch(t *testing.T) {
	encoded, err := HashPassword("correct", testArgon2Params)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	err = VerifyPassword("wrong", encoded)
	if !errors.Is(err, ErrPasswordMismatch) {
		t.Errorf("err = %v, want ErrPasswordMismatch", err)
	}
}

func TestHash_ProducesPHCFormat(t *testing.T) {
	encoded, err := HashPassword("pw", testArgon2Params)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=") {
		t.Errorf("expected PHC prefix, got %q", encoded)
	}
	// Structure: $argon2id$v=X$m=Y,t=Z,p=W$salt$hash → 6 parts split by $ (first is empty)
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		t.Errorf("expected 6 $-separated parts, got %d: %q", len(parts), encoded)
	}
}

func TestHash_DifferentSaltEachCall(t *testing.T) {
	// Same password, different hash strings every time (salt differs).
	a, _ := HashPassword("same-password", testArgon2Params)
	b, _ := HashPassword("same-password", testArgon2Params)
	if a == b {
		t.Errorf("two hashes of the same password should differ (random salt); both=%q", a)
	}
}

func TestVerify_RejectsBadFormats(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$bcrypt$v=19$m=1,t=1,p=1$salt$hash",            // wrong algorithm
		"$argon2id$v=99$m=1,t=1,p=1$YWFh$YWFh",          // wrong version
		"$argon2id$v=19$badparams$YWFh$YWFh",            // malformed params
		"$argon2id$v=19$m=1,t=1,p=1$!!!invalid-b64$YWFh", // bad salt b64
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			err := VerifyPassword("anything", c)
			if !errors.Is(err, ErrBadPasswordHashFormat) {
				t.Errorf("err = %v, want ErrBadPasswordHashFormat", err)
			}
		})
	}
}

// VerifyPassword should work across parameter changes — a hash generated with
// one set of params must still verify even if DefaultArgon2Params was bumped
// since it was stored. (Enforces "PHC-encoded" design choice.)
func TestVerify_WorksWithOlderParameters(t *testing.T) {
	oldParams := Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1,
		SaltLength: 16, KeyLength: 32,
	}
	encoded, err := HashPassword("pw", oldParams)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	// Pretend DefaultArgon2Params got bumped to stronger values — VerifyPassword
	// reads the actual params from the hash, not from the defaults, so this
	// still works.
	if err := VerifyPassword("pw", encoded); err != nil {
		t.Errorf("verification against older-params hash failed: %v", err)
	}
}
