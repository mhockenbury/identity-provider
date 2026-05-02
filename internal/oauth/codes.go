package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Authorization codes are issued at /authorize and redeemed at /token.
// Per RFC 6749 §4.1.2:
//   - short-lived (<=60s recommended)
//   - single-use (we enforce via UPDATE ... WHERE used_at IS NULL)
//   - bound to one client + one redirect_uri
//   - carry the PKCE challenge (RFC 7636 §4.4) for /token to verify
//
// The "code" string is high-entropy random, base64url-encoded. We store
// it plaintext: losing a DB dump of pending auth codes is equivalent to
// losing the signing key (you can redeem each one once); hashing adds
// no meaningful security here because the codes have brutally short
// TTLs and single-use semantics. For refresh tokens — long-lived — we
// WILL hash.

// Sentinel errors handlers map to OAuth error responses.
var (
	ErrCodeNotFound      = errors.New("authorization code not found")
	ErrCodeExpired       = errors.New("authorization code expired")
	ErrCodeAlreadyUsed   = errors.New("authorization code already used")
	ErrCodeClientMismatch = errors.New("authorization code client mismatch")
)

// DefaultCodeTTL matches RFC 6749 §4.1.2 recommendation.
const DefaultCodeTTL = 60 * time.Second

// AuthCode is the in-memory row view.
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              uuid.UUID
	RedirectURI         string
	CodeChallenge       string // PKCE S256 hash, base64url
	CodeChallengeMethod string // "S256" — we only accept this
	Scopes              []string
	Resource            string // RFC 8707; access token's `aud` is set from this at /token
	Nonce               string
	ExpiresAt           time.Time
	UsedAt              *time.Time
	CreatedAt           time.Time
}

// NewAuthCodeInput groups the fields /authorize supplies when issuing
// a code. The store fills in Code, ExpiresAt, CreatedAt.
type NewAuthCodeInput struct {
	ClientID            string
	UserID              uuid.UUID
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scopes              []string
	Resource            string
	Nonce               string
}

// AuthCodeStore is the persistence surface for auth codes.
type AuthCodeStore interface {
	// Issue mints a new code, persists it, and returns the code string
	// (the caller redirects the user back to the client with this
	// string as ?code=...).
	Issue(ctx context.Context, in NewAuthCodeInput, ttl time.Duration) (string, error)

	// Consume looks up a code, verifies it matches clientID + redirectURI,
	// and atomically marks it used. Returns the full row so /token can
	// read code_challenge for PKCE verification.
	//
	// On any mismatch or prior-use, returns a typed sentinel and the row
	// is NOT marked used (so the legitimate holder can still try — though
	// in practice they won't succeed either, because the mismatched
	// client/redirect_uri probably means they got the wrong code).
	//
	// Concurrency: two simultaneous Consume calls for the same code —
	// exactly one succeeds. The other sees ErrCodeAlreadyUsed. Enforced
	// by the UPDATE ... WHERE used_at IS NULL ... RETURNING pattern.
	Consume(ctx context.Context, code, clientID, redirectURI string) (AuthCode, error)
}

type PostgresAuthCodeStore struct {
	pool *pgxpool.Pool
}

func NewPostgresAuthCodeStore(pool *pgxpool.Pool) *PostgresAuthCodeStore {
	return &PostgresAuthCodeStore{pool: pool}
}

// codeLen is the number of random bytes per code. 32 bytes of entropy,
// base64url'd to ~43 chars. Comfortably over RFC 6749 §10.10's 128-bit
// recommendation.
const codeLen = 32

// mintCode generates a cryptographically-random base64url code.
func mintCode() (string, error) {
	b := make([]byte, codeLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Issue inserts a new authorization_codes row.
func (s *PostgresAuthCodeStore) Issue(ctx context.Context, in NewAuthCodeInput, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}
	code, err := mintCode()
	if err != nil {
		return "", err
	}

	const q = `
        INSERT INTO authorization_codes
            (code, client_id, user_id, redirect_uri, code_challenge,
             code_challenge_method, scopes, resource, nonce, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), now() + $10::interval)`

	intervalSpec := fmt.Sprintf("%d milliseconds", ttl.Milliseconds())

	_, err = s.pool.Exec(ctx, q,
		code, in.ClientID, in.UserID, in.RedirectURI,
		in.CodeChallenge, in.CodeChallengeMethod,
		in.Scopes, in.Resource, in.Nonce, intervalSpec)
	if err != nil {
		return "", fmt.Errorf("insert auth code: %w", err)
	}
	return code, nil
}

// Consume atomically claims the code IFF it's unused and not expired.
// The client_id + redirect_uri checks are inside the UPDATE predicate
// so a mismatch can't accidentally burn the code.
//
// Flow:
//   1. Load the row to read fields (we need them for /token) and to
//      distinguish "not found" from "mismatch" for error messages.
//   2. UPDATE ... SET used_at=now() WHERE code=$1 AND used_at IS NULL
//      AND expires_at > now() — atomic claim.
//   3. If the UPDATE affected zero rows, the row was either already
//      used, already expired, or disappeared. We check step 1's data
//      to surface the right sentinel.
func (s *PostgresAuthCodeStore) Consume(ctx context.Context, code, clientID, redirectURI string) (AuthCode, error) {
	row, err := s.get(ctx, code)
	if err != nil {
		return AuthCode{}, err
	}

	if row.ClientID != clientID || row.RedirectURI != redirectURI {
		return AuthCode{}, ErrCodeClientMismatch
	}
	if row.UsedAt != nil {
		return AuthCode{}, ErrCodeAlreadyUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return AuthCode{}, ErrCodeExpired
	}

	// Atomic claim. Predicate repeats the used_at/expires_at checks so
	// a racing Consume can't double-redeem.
	const claim = `
        UPDATE authorization_codes
        SET used_at = now()
        WHERE code = $1
          AND used_at IS NULL
          AND expires_at > now()
        RETURNING used_at`

	var usedAt time.Time
	err = s.pool.QueryRow(ctx, claim, code).Scan(&usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Race: a concurrent Consume claimed it between our get and our UPDATE.
			return AuthCode{}, ErrCodeAlreadyUsed
		}
		return AuthCode{}, fmt.Errorf("claim auth code: %w", err)
	}
	row.UsedAt = &usedAt
	return row, nil
}

// get reads the row including used_at so Consume can surface the right
// sentinel. Unexported; callers should use Consume.
func (s *PostgresAuthCodeStore) get(ctx context.Context, code string) (AuthCode, error) {
	const q = `
        SELECT code, client_id, user_id, redirect_uri, code_challenge,
               code_challenge_method, scopes, resource, COALESCE(nonce, ''),
               expires_at, used_at, created_at
        FROM authorization_codes
        WHERE code = $1`

	var row AuthCode
	err := s.pool.QueryRow(ctx, q, code).Scan(
		&row.Code, &row.ClientID, &row.UserID, &row.RedirectURI,
		&row.CodeChallenge, &row.CodeChallengeMethod, &row.Scopes,
		&row.Resource, &row.Nonce, &row.ExpiresAt, &row.UsedAt, &row.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthCode{}, ErrCodeNotFound
		}
		return AuthCode{}, fmt.Errorf("get auth code: %w", err)
	}
	return row, nil
}
