package tokens

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Signing-key three-state machine, by timestamp columns:
//
//   PENDING:  activated_at IS NULL  AND  retired_at IS NULL
//   ACTIVE:   activated_at NOT NULL AND  retired_at IS NULL     (at most one, DB-enforced)
//   RETIRED:  activated_at NOT NULL AND  retired_at NOT NULL
//
// Transitions are one-way: PENDING → ACTIVE → RETIRED. See docs/architecture.md
// and the rotation discussion for why retired keys stay in the signing_keys
// table (audit) and in JWKS output (verification of in-flight tokens) until
// they fully age out.

const (
	// AlgEdDSA is the JOSE alg name for Ed25519. We only support one alg
	// for the lab; RS256 support would add a column and a branch.
	AlgEdDSA = "EdDSA"
)

// Sentinel errors.
var (
	ErrKeyNotFound      = errors.New("signing key not found")
	ErrNoActiveKey      = errors.New("no active signing key")
	ErrInvalidKeyState  = errors.New("signing key is not in the required state")
	ErrKeyAlreadyActive = errors.New("another signing key is already active")
)

// KeyStatus is the derived three-state value. Computed from timestamps,
// not stored — the timestamps are the source of truth.
type KeyStatus string

const (
	StatusPending KeyStatus = "pending"
	StatusActive  KeyStatus = "active"
	StatusRetired KeyStatus = "retired"
)

// SigningKey is the in-memory view of a signing_keys row, with the private
// half unwrapped only after Unwrap().
type SigningKey struct {
	KID          string
	Alg          string // AlgEdDSA
	PublicKey    ed25519.PublicKey
	privateKey   ed25519.PrivateKey // zero until Unwrap()
	privateKeyEnc []byte            // KEK-wrapped; what lives in the DB
	CreatedAt    time.Time
	ActivatedAt  *time.Time
	RetiredAt    *time.Time
}

// Status derives the three-state value from the timestamps. Keeps the
// source-of-truth question unambiguous: timestamps decide, never a column.
func (k *SigningKey) Status() KeyStatus {
	switch {
	case k.ActivatedAt == nil:
		return StatusPending
	case k.RetiredAt == nil:
		return StatusActive
	default:
		return StatusRetired
	}
}

// AgeDays is a convenience for CLI `keys list`. Rounds down.
func (k *SigningKey) AgeDays() int {
	return int(time.Since(k.CreatedAt).Hours() / 24)
}

// PrivateKey returns the ed25519 private key after Unwrap() has been called.
// Panics if Unwrap() has not been called — this is a programming-error
// assertion, not a runtime condition; callers should always Unwrap first.
func (k *SigningKey) PrivateKey() ed25519.PrivateKey {
	if k.privateKey == nil {
		panic("signing key private half not unwrapped; call Unwrap first")
	}
	return k.privateKey
}

// Unwrap decrypts the stored ciphertext under the given KEK and memoizes
// the private key into the struct. Idempotent — calling twice with the
// same KEK is a no-op.
func (k *SigningKey) Unwrap(kek KEK) error {
	if k.privateKey != nil {
		return nil
	}
	plaintext, err := kek.Unwrap(k.privateKeyEnc, k.KID)
	if err != nil {
		return fmt.Errorf("unwrap signing key %s: %w", k.KID, err)
	}
	if len(plaintext) != ed25519.PrivateKeySize {
		return fmt.Errorf("unwrap %s: private key is %d bytes, want %d",
			k.KID, len(plaintext), ed25519.PrivateKeySize)
	}
	k.privateKey = ed25519.PrivateKey(plaintext)
	return nil
}

// KeyStore manages the signing_keys table + state-machine transitions.
type KeyStore struct {
	pool *pgxpool.Pool
	kek  KEK
}

func NewKeyStore(pool *pgxpool.Pool, kek KEK) *KeyStore {
	return &KeyStore{pool: pool, kek: kek}
}

// Generate creates a new Ed25519 key pair, wraps the private half under the
// KEK, and inserts it as a PENDING row. The returned SigningKey already
// has the plaintext private half loaded so the caller can use it
// immediately if desired (though normally Generate → Activate → use).
func (s *KeyStore) Generate(ctx context.Context) (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519: %w", err)
	}
	kid := "k_" + uuid.NewString()

	enc, err := s.kek.Wrap(priv, kid)
	if err != nil {
		return nil, fmt.Errorf("wrap private key: %w", err)
	}

	const q = `
        INSERT INTO signing_keys (kid, alg, public_key_jwk, private_key_enc)
        VALUES ($1, $2, $3, $4)
        RETURNING created_at`

	var createdAt time.Time
	// For the lab we store the raw public key bytes; JWKS serialization
	// happens at the /.well-known/jwks.json endpoint rather than at write
	// time, so we can change JWK representation without a migration.
	err = s.pool.QueryRow(ctx, q, kid, AlgEdDSA, []byte(pub), enc).Scan(&createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert signing key: %w", err)
	}

	return &SigningKey{
		KID:           kid,
		Alg:           AlgEdDSA,
		PublicKey:     pub,
		privateKey:    priv,
		privateKeyEnc: enc,
		CreatedAt:     createdAt,
	}, nil
}

// Activate transitions a PENDING key to ACTIVE.
//
// Safety: the signing_keys_one_active_idx partial unique index makes
// "two active keys" impossible at the DB level. If a second Activate races
// with the first, one of them gets a unique_violation and we surface it as
// ErrKeyAlreadyActive. Same story if the operator tries to activate a
// second key without retiring the first.
func (s *KeyStore) Activate(ctx context.Context, kid string) error {
	const q = `
        UPDATE signing_keys
        SET activated_at = now()
        WHERE kid = $1
          AND activated_at IS NULL
          AND retired_at IS NULL
        RETURNING kid`

	var got string
	err := s.pool.QueryRow(ctx, q, kid).Scan(&got)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			// The partial unique index fired — another key is already active.
			return ErrKeyAlreadyActive
		}
		if errors.Is(err, pgx.ErrNoRows) {
			// Either the kid doesn't exist, or it's already active/retired.
			return fmt.Errorf("%w: not in PENDING state or does not exist", ErrInvalidKeyState)
		}
		return fmt.Errorf("activate signing key: %w", err)
	}
	return nil
}

// Retire transitions an ACTIVE key to RETIRED. After retirement the key
// still appears in JWKS for some overlap window (caller's responsibility
// to wait before calling Retire after flipping Active) so in-flight tokens
// can still be verified.
func (s *KeyStore) Retire(ctx context.Context, kid string) error {
	const q = `
        UPDATE signing_keys
        SET retired_at = now()
        WHERE kid = $1
          AND activated_at IS NOT NULL
          AND retired_at IS NULL
        RETURNING kid`

	var got string
	err := s.pool.QueryRow(ctx, q, kid).Scan(&got)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: not in ACTIVE state or does not exist", ErrInvalidKeyState)
		}
		return fmt.Errorf("retire signing key: %w", err)
	}
	return nil
}

// GetActive returns the one currently-active key, or ErrNoActiveKey if
// there isn't one. Used by the /token endpoint to pick the signing key.
func (s *KeyStore) GetActive(ctx context.Context) (*SigningKey, error) {
	const q = `
        SELECT kid, alg, public_key_jwk, private_key_enc, created_at, activated_at, retired_at
        FROM signing_keys
        WHERE activated_at IS NOT NULL
          AND retired_at IS NULL
        ORDER BY activated_at DESC
        LIMIT 1`

	k, err := s.scanOne(ctx, q)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoActiveKey
		}
		return nil, err
	}
	return k, nil
}

// GetByID returns one key by kid. Intended for rewrap / debug / tests —
// normal traffic never selects a specific kid this way.
func (s *KeyStore) GetByID(ctx context.Context, kid string) (*SigningKey, error) {
	const q = `
        SELECT kid, alg, public_key_jwk, private_key_enc, created_at, activated_at, retired_at
        FROM signing_keys
        WHERE kid = $1`

	k, err := s.scanOne(ctx, q, kid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	return k, nil
}

// List returns every row, ordered created_at descending. Used by the
// CLI `keys list` subcommand. Private halves are left wrapped.
func (s *KeyStore) List(ctx context.Context) ([]*SigningKey, error) {
	const q = `
        SELECT kid, alg, public_key_jwk, private_key_enc, created_at, activated_at, retired_at
        FROM signing_keys
        ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query signing keys: %w", err)
	}
	defer rows.Close()

	var out []*SigningKey
	for rows.Next() {
		var k SigningKey
		var pub []byte
		if err := rows.Scan(&k.KID, &k.Alg, &pub, &k.privateKeyEnc,
			&k.CreatedAt, &k.ActivatedAt, &k.RetiredAt); err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}
		k.PublicKey = ed25519.PublicKey(pub)
		out = append(out, &k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate signing keys: %w", err)
	}
	return out, nil
}

// ForJWKS returns all keys that should appear in /.well-known/jwks.json:
// active + non-retired pending + retired keys during their overlap window.
// For the lab we simply include every non-retired row (ACTIVE or PENDING).
// The retire operation is the caller's cue to drop the key from JWKS.
func (s *KeyStore) ForJWKS(ctx context.Context) ([]*SigningKey, error) {
	const q = `
        SELECT kid, alg, public_key_jwk, private_key_enc, created_at, activated_at, retired_at
        FROM signing_keys
        WHERE retired_at IS NULL
        ORDER BY created_at DESC`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query signing keys for JWKS: %w", err)
	}
	defer rows.Close()

	var out []*SigningKey
	for rows.Next() {
		var k SigningKey
		var pub []byte
		if err := rows.Scan(&k.KID, &k.Alg, &pub, &k.privateKeyEnc,
			&k.CreatedAt, &k.ActivatedAt, &k.RetiredAt); err != nil {
			return nil, fmt.Errorf("scan signing key: %w", err)
		}
		k.PublicKey = ed25519.PublicKey(pub)
		out = append(out, &k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate signing keys: %w", err)
	}
	return out, nil
}

// scanOne runs a single-row query returning one *SigningKey.
// Returns pgx.ErrNoRows unchanged so callers can distinguish "not found"
// from other errors; other errors are wrapped.
func (s *KeyStore) scanOne(ctx context.Context, q string, args ...any) (*SigningKey, error) {
	var k SigningKey
	var pub []byte
	err := s.pool.QueryRow(ctx, q, args...).Scan(
		&k.KID, &k.Alg, &pub, &k.privateKeyEnc,
		&k.CreatedAt, &k.ActivatedAt, &k.RetiredAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan signing key: %w", err)
	}
	k.PublicKey = ed25519.PublicKey(pub)
	return &k, nil
}

// pgUniqueViolation is the SQLSTATE for 23505.
const pgUniqueViolation = "23505"

// KeyStoreResolver adapts a *KeyStore to the KeyResolver interface used
// by *Verifier. Lets the IdP verify its OWN access tokens without going
// through its public JWKS endpoint — no HTTP round-trip, no cache
// staleness concerns, keys come straight from Postgres.
//
// Downstream services (docs-api) will implement KeyResolver differently,
// with an HTTP-fetched JWKS cache.
type KeyStoreResolver struct {
	store *KeyStore
}

// NewKeyStoreResolver wraps a KeyStore so it satisfies KeyResolver.
func NewKeyStoreResolver(store *KeyStore) *KeyStoreResolver {
	return &KeyStoreResolver{store: store}
}

// Resolve looks up the public key for kid directly in the DB. Returns
// the public key regardless of the key's current state (PENDING / ACTIVE /
// RETIRED) because access tokens signed by a key that has since been
// retired must still verify during the overlap window.
func (r *KeyStoreResolver) Resolve(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	k, err := r.store.GetByID(ctx, kid)
	if err != nil {
		return nil, err
	}
	return k.PublicKey, nil
}
