package tokens

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Refresh tokens are opaque (not JWTs). They're 32 random bytes
// base64url-encoded (~43 chars). Unlike access tokens — which are
// self-validating and live ~15 min — refresh tokens live 30 days and
// are looked up in Postgres on every /token refresh exchange.
//
// Storage: we store a SHA-256 hash of the token, not plaintext. Reason:
// a DB snapshot shouldn't hand an attacker a 30-day bearer credential
// per row. Hash is enough here (not argon2) because the input is already
// 256 bits of entropy — brute-force resistance isn't meaningful. The
// primary threat we defend against is "attacker reads a DB dump."
//
// Rotation (Level 2 per README §6): every refresh CONSUMES the old row
// and issues a new one with rotated_from = old.id. Single linear chain.
// Reuse detection (Level 3, family invalidation) is a tracked stretch,
// not implemented.

// Sentinel errors.
var (
	ErrRefreshNotFound = errors.New("refresh token not found")
	ErrRefreshExpired  = errors.New("refresh token expired")
	ErrRefreshRevoked  = errors.New("refresh token revoked")
)

// RefreshToken is the in-memory row view. The plaintext token value
// is NOT stored here — only the hash. The plaintext only ever exists
// in the network response to the client (one time, in the /token
// response JSON).
type RefreshToken struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	ClientID    string
	Scopes      []string
	ExpiresAt   time.Time
	RevokedAt   *time.Time
	RotatedFrom *uuid.UUID
	CreatedAt   time.Time
}

// RefreshTokenStore manages opaque refresh tokens.
type RefreshTokenStore interface {
	// Issue mints a new token, stores its hash + metadata, and returns
	// BOTH the plaintext token (to include in the /token response) and
	// the row view. The plaintext cannot be recovered later.
	Issue(ctx context.Context, userID uuid.UUID, clientID string, scopes []string, ttl time.Duration) (plaintext string, row RefreshToken, err error)

	// Rotate consumes an existing refresh token + issues a replacement
	// atomically. Returns the NEW plaintext + row. The old row is marked
	// revoked_at. On mismatch (wrong client, expired, already revoked)
	// returns a typed sentinel WITHOUT advancing.
	//
	// Scopes on the new token must be a subset of the old token's
	// scopes (RFC 6749 §6 — refresh MAY return a subset of originally-
	// granted scopes, MUST NOT grant new ones). Pass nil or empty to
	// re-use the old scopes as-is.
	Rotate(ctx context.Context, presentedPlaintext, clientID string, newScopes []string, ttl time.Duration) (plaintext string, row RefreshToken, err error)
}

type PostgresRefreshTokenStore struct {
	pool *pgxpool.Pool
}

func NewPostgresRefreshTokenStore(pool *pgxpool.Pool) *PostgresRefreshTokenStore {
	return &PostgresRefreshTokenStore{pool: pool}
}

// refreshTokenLen is the random-bytes length. 32 bytes = 256 bits.
const refreshTokenLen = 32

// mintRefresh returns a fresh opaque token string.
func mintRefresh() (string, error) {
	b := make([]byte, refreshTokenLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashRefresh returns the SHA-256 hash used for DB storage.
// Hex-encoded so the stored column is TEXT (matches migration 0001).
func hashRefresh(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *PostgresRefreshTokenStore) Issue(ctx context.Context, userID uuid.UUID, clientID string, scopes []string, ttl time.Duration) (string, RefreshToken, error) {
	if ttl <= 0 {
		return "", RefreshToken{}, fmt.Errorf("refresh ttl must be > 0")
	}

	plaintext, err := mintRefresh()
	if err != nil {
		return "", RefreshToken{}, err
	}

	const q = `
        INSERT INTO refresh_tokens
            (token_hash, user_id, client_id, scopes, expires_at)
        VALUES ($1, $2, $3, $4, now() + $5::interval)
        RETURNING id, user_id, client_id, scopes, expires_at, revoked_at,
                  rotated_from, created_at`

	intervalSpec := fmt.Sprintf("%d milliseconds", ttl.Milliseconds())

	var row RefreshToken
	err = s.pool.QueryRow(ctx, q,
		hashRefresh(plaintext), userID, clientID, scopes, intervalSpec).Scan(
		&row.ID, &row.UserID, &row.ClientID, &row.Scopes,
		&row.ExpiresAt, &row.RevokedAt, &row.RotatedFrom, &row.CreatedAt)
	if err != nil {
		return "", RefreshToken{}, fmt.Errorf("insert refresh: %w", err)
	}
	return plaintext, row, nil
}

func (s *PostgresRefreshTokenStore) Rotate(ctx context.Context, presentedPlaintext, clientID string, newScopes []string, ttl time.Duration) (string, RefreshToken, error) {
	if ttl <= 0 {
		return "", RefreshToken{}, fmt.Errorf("refresh ttl must be > 0")
	}

	// Look up by hash. Constant-time compare is not needed on the hash
	// because an attacker who already has the plaintext has won; the
	// storage-side protection is defense against DB dumps.
	hash := hashRefresh(presentedPlaintext)

	// BEGIN tx: read the row, verify, mark revoked, insert new, return new.
	// SELECT FOR UPDATE locks the row so two concurrent rotate calls with
	// the same token can't both succeed — first wins, second sees revoked.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", RefreshToken{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const qOld = `
        SELECT id, user_id, client_id, scopes, expires_at, revoked_at
        FROM refresh_tokens
        WHERE token_hash = $1
        FOR UPDATE`

	var old struct {
		ID        uuid.UUID
		UserID    uuid.UUID
		ClientID  string
		Scopes    []string
		ExpiresAt time.Time
		RevokedAt *time.Time
	}
	err = tx.QueryRow(ctx, qOld, hash).Scan(
		&old.ID, &old.UserID, &old.ClientID, &old.Scopes, &old.ExpiresAt, &old.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", RefreshToken{}, ErrRefreshNotFound
		}
		return "", RefreshToken{}, fmt.Errorf("lookup refresh: %w", err)
	}

	if old.RevokedAt != nil {
		return "", RefreshToken{}, ErrRefreshRevoked
	}
	if time.Now().After(old.ExpiresAt) {
		return "", RefreshToken{}, ErrRefreshExpired
	}
	if old.ClientID != clientID {
		// A refresh token from client A cannot be redeemed by client B.
		// Same-bucket as "revoked" from the caller's POV.
		return "", RefreshToken{}, ErrRefreshRevoked
	}

	// Scope downgrade check: new scopes must be a subset of the old
	// token's scopes. Empty means "reuse old scopes as-is."
	scopesToStore := old.Scopes
	if len(newScopes) > 0 {
		for _, ns := range newScopes {
			if !containsExact(old.Scopes, ns) {
				return "", RefreshToken{}, fmt.Errorf("requested scope %q not in original grant", ns)
			}
		}
		scopesToStore = newScopes
	}

	// Mark old revoked.
	_, err = tx.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, old.ID)
	if err != nil {
		return "", RefreshToken{}, fmt.Errorf("revoke old refresh: %w", err)
	}

	// Mint and insert new.
	plaintext, err := mintRefresh()
	if err != nil {
		return "", RefreshToken{}, err
	}
	const qNew = `
        INSERT INTO refresh_tokens
            (token_hash, user_id, client_id, scopes, expires_at, rotated_from)
        VALUES ($1, $2, $3, $4, now() + $5::interval, $6)
        RETURNING id, user_id, client_id, scopes, expires_at, revoked_at,
                  rotated_from, created_at`

	intervalSpec := fmt.Sprintf("%d milliseconds", ttl.Milliseconds())

	var row RefreshToken
	err = tx.QueryRow(ctx, qNew,
		hashRefresh(plaintext), old.UserID, old.ClientID, scopesToStore, intervalSpec, old.ID).Scan(
		&row.ID, &row.UserID, &row.ClientID, &row.Scopes,
		&row.ExpiresAt, &row.RevokedAt, &row.RotatedFrom, &row.CreatedAt)
	if err != nil {
		return "", RefreshToken{}, fmt.Errorf("insert new refresh: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", RefreshToken{}, fmt.Errorf("commit rotate: %w", err)
	}
	return plaintext, row, nil
}

// containsExact reports exact equality membership — same helper as
// clients.Client.CheckRedirectURI uses internally.
func containsExact(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
