package users

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters matching OWASP 2024 guidance. Tunable per-deployment
// via env, but these defaults are the starting point.
//
// Reference: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
// — minimum recommended memory=46MB, iterations=1, parallelism=1; stronger
// defaults used here since login is not a hot path.
type Argon2Params struct {
	Memory      uint32 // in KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params are the ones encoded into every password hash unless
// explicitly overridden. Changing these later is safe — stored hashes encode
// their own parameters so verification works across versions.
var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// ErrBadPasswordHashFormat is returned when a stored hash can't be parsed.
// Split from ErrPasswordMismatch so callers can tell "your hash is corrupt"
// apart from "wrong password."
var ErrBadPasswordHashFormat = errors.New("invalid argon2id password hash format")

// ErrPasswordMismatch is returned by VerifyPassword when the password does
// not match the stored hash. Deliberately generic — caller should not
// distinguish "no such user" from "wrong password" in the response.
var ErrPasswordMismatch = errors.New("password mismatch")

// HashPassword produces a self-describing encoded hash string in the
// standard PHC format:
//
//	$argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt-b64>$<hash-b64>
//
// Encoding the parameters in the hash lets VerifyPassword work even if
// DefaultArgon2Params changes later.
func HashPassword(password string, params Argon2Params) (string, error) {
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword checks a plaintext password against an encoded hash.
// Returns nil on match, ErrPasswordMismatch on wrong password,
// ErrBadPasswordHashFormat on a malformed hash string.
//
// Uses subtle.ConstantTimeCompare so hash-comparison time doesn't leak
// info about which byte differed.
func VerifyPassword(password, encoded string) error {
	params, salt, hash, err := decodePHC(encoded)
	if err != nil {
		return err
	}

	candidate := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	if subtle.ConstantTimeCompare(hash, candidate) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// decodePHC parses the encoded hash produced by HashPassword.
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func decodePHC(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// Leading "$" produces an empty first part; expect 6 total.
	if len(parts) != 6 || parts[0] != "" {
		return Argon2Params{}, nil, nil, ErrBadPasswordHashFormat
	}
	if parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: unsupported algorithm %q", ErrBadPasswordHashFormat, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: bad version field", ErrBadPasswordHashFormat)
	}
	if version != argon2.Version {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: unsupported argon2 version %d", ErrBadPasswordHashFormat, version)
	}

	var params Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: bad params field", ErrBadPasswordHashFormat)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: decode salt: %v", ErrBadPasswordHashFormat, err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Argon2Params{}, nil, nil, fmt.Errorf("%w: decode hash: %v", ErrBadPasswordHashFormat, err)
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
