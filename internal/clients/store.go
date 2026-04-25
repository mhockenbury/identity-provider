// Package clients holds the OAuth client registry.
//
// Two kinds of clients:
//   - Confidential: has a client_secret; authenticates at /token via basic
//     auth or client_secret_post. Examples: server-side apps.
//   - Public: no secret; relies on PKCE for security. Examples: SPAs, mobile.
//
// RFC 6749 §2.1 defines the distinction. The `is_public` flag on the clients
// table mirrors whether secret_hash is NULL; enforced by CHECK or by code.
package clients

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// Sentinel errors. Handlers map these to OAuth error codes.
var (
	ErrNotFound              = errors.New("client not found")
	ErrInvalidClientAuth     = errors.New("client authentication failed")
	ErrRedirectURINotAllowed = errors.New("redirect_uri not registered for this client")
	ErrGrantNotAllowed       = errors.New("grant_type not allowed for this client")
	ErrScopeNotAllowed       = errors.New("requested scope exceeds client's allowed scopes")
	ErrIDTaken               = errors.New("client id already in use")
	ErrInvalidClientShape    = errors.New("public clients must not have a secret; confidential must")
)

// Postgres unique-violation SQLSTATE.
const pgUniqueViolation = "23505"

// Client mirrors the `clients` row. Public clients have no SecretHash;
// confidential clients always do.
type Client struct {
	ID            string
	SecretHash    string    // empty for public clients
	RedirectURIs  []string
	AllowedGrants []string
	AllowedScopes []string
	IsPublic      bool
	CreatedAt     time.Time
}

// Store is the clients package's persistence + policy surface. Handlers
// depend on this, not on pgxpool.
type Store interface {
	GetByID(ctx context.Context, id string) (Client, error)

	// Authenticate returns a Client on successful client authentication:
	//   - Public client (no secret): presentedSecret must be empty.
	//   - Confidential: presentedSecret must match the stored hash.
	// Returns ErrInvalidClientAuth on mismatch/missing-secret-on-confidential.
	// Returns ErrNotFound if the client doesn't exist. Both should map to
	// the OAuth `invalid_client` error for the caller.
	Authenticate(ctx context.Context, clientID, presentedSecret string) (Client, error)

	// List returns all clients ordered by created_at. The admin API + UI
	// use it; the OAuth handlers don't need it.
	List(ctx context.Context) ([]Client, error)

	// Create inserts a new client. For confidential clients (isPublic=false),
	// a fresh secret is generated and returned in PLAINTEXT — this is the
	// ONLY time the plaintext is ever exposed. The DB stores only the
	// argon2id hash. For public clients, the returned plaintext is "".
	// Returns ErrIDTaken on unique-constraint conflict.
	Create(ctx context.Context, c Client) (Client, string, error)

	// Update replaces redirect_uris, allowed_grants, and allowed_scopes.
	// The id, is_public, and secret_hash are NOT updatable — those have
	// dedicated paths (RotateSecret, Delete + Create for the others).
	// Returns ErrNotFound if the client doesn't exist.
	Update(ctx context.Context, id string, redirectURIs, allowedGrants, allowedScopes []string) (Client, error)

	// RotateSecret generates a new secret for a confidential client,
	// hashes + persists it, and returns the plaintext (ONLY time exposed).
	// Errors with ErrInvalidClientShape if called on a public client.
	RotateSecret(ctx context.Context, id string) (Client, string, error)

	// Delete removes a client. Cascades via FK to authorization_codes,
	// consents — sessions are user-scoped, not client-scoped, so they
	// survive. Returns ErrNotFound if not present.
	Delete(ctx context.Context, id string) error
}

// PostgresStore is the Postgres-backed implementation.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) GetByID(ctx context.Context, id string) (Client, error) {
	const q = `
        SELECT id, COALESCE(secret_hash, ''), redirect_uris, allowed_grants,
               allowed_scopes, is_public, created_at
        FROM clients
        WHERE id = $1`

	var c Client
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&c.ID, &c.SecretHash, &c.RedirectURIs, &c.AllowedGrants,
		&c.AllowedScopes, &c.IsPublic, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Client{}, ErrNotFound
		}
		return Client{}, fmt.Errorf("get client by id: %w", err)
	}
	return c, nil
}

// Authenticate combines lookup + secret verify. Returns the Client on success.
//
// Security note: presentedSecret is hashed with argon2id during VerifyPassword
// (same primitive as user passwords). Comparison is constant-time.
func (s *PostgresStore) Authenticate(ctx context.Context, clientID, presentedSecret string) (Client, error) {
	c, err := s.GetByID(ctx, clientID)
	if err != nil {
		return Client{}, err
	}

	if c.IsPublic {
		// Public clients must not present a secret. If one is sent, treat as
		// mis-configuration rather than silently ignoring — belt-and-braces.
		if presentedSecret != "" {
			return Client{}, ErrInvalidClientAuth
		}
		return c, nil
	}

	// Confidential client: secret required, must verify against stored hash.
	if presentedSecret == "" {
		return Client{}, ErrInvalidClientAuth
	}
	if err := users.VerifyPassword(presentedSecret, c.SecretHash); err != nil {
		// Don't leak whether the client existed vs. the secret was wrong.
		return Client{}, ErrInvalidClientAuth
	}
	return c, nil
}

// List returns all clients in created_at ascending order.
func (s *PostgresStore) List(ctx context.Context) ([]Client, error) {
	const q = `
        SELECT id, COALESCE(secret_hash, ''), redirect_uris, allowed_grants,
               allowed_scopes, is_public, created_at
        FROM clients
        ORDER BY created_at`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	var out []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ID, &c.SecretHash, &c.RedirectURIs, &c.AllowedGrants,
			&c.AllowedScopes, &c.IsPublic, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan client: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Create inserts a new client and (for confidential clients) generates +
// returns a fresh plaintext secret. The plaintext is shown to the caller
// ONCE and never persisted in plaintext anywhere — only the argon2id
// hash lands in the DB.
func (s *PostgresStore) Create(ctx context.Context, c Client) (Client, string, error) {
	if c.ID == "" {
		return Client{}, "", fmt.Errorf("client id required")
	}
	// Sanity check: public + secret_hash mutually exclusive at the API,
	// regardless of caller intent.
	if c.IsPublic && c.SecretHash != "" {
		return Client{}, "", ErrInvalidClientShape
	}

	var plaintext string
	var hash string
	if !c.IsPublic {
		var err error
		plaintext, err = generateClientSecret()
		if err != nil {
			return Client{}, "", fmt.Errorf("generate secret: %w", err)
		}
		hash, err = users.HashPassword(plaintext, users.DefaultArgon2Params)
		if err != nil {
			return Client{}, "", fmt.Errorf("hash secret: %w", err)
		}
	}

	const q = `
        INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants,
                             allowed_scopes, is_public)
        VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6)
        RETURNING id, COALESCE(secret_hash, ''), redirect_uris, allowed_grants,
                  allowed_scopes, is_public, created_at`

	var saved Client
	err := s.pool.QueryRow(ctx, q,
		c.ID, hash, c.RedirectURIs, c.AllowedGrants, c.AllowedScopes, c.IsPublic,
	).Scan(&saved.ID, &saved.SecretHash, &saved.RedirectURIs, &saved.AllowedGrants,
		&saved.AllowedScopes, &saved.IsPublic, &saved.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return Client{}, "", ErrIDTaken
		}
		return Client{}, "", fmt.Errorf("insert client: %w", err)
	}
	return saved, plaintext, nil
}

// Update replaces the editable arrays. id / is_public / secret_hash are
// out of scope (separate paths or recreate-from-scratch).
func (s *PostgresStore) Update(ctx context.Context, id string, redirectURIs, allowedGrants, allowedScopes []string) (Client, error) {
	const q = `
        UPDATE clients
        SET redirect_uris = $2,
            allowed_grants = $3,
            allowed_scopes = $4
        WHERE id = $1
        RETURNING id, COALESCE(secret_hash, ''), redirect_uris, allowed_grants,
                  allowed_scopes, is_public, created_at`

	var c Client
	err := s.pool.QueryRow(ctx, q, id, redirectURIs, allowedGrants, allowedScopes).Scan(
		&c.ID, &c.SecretHash, &c.RedirectURIs, &c.AllowedGrants,
		&c.AllowedScopes, &c.IsPublic, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Client{}, ErrNotFound
		}
		return Client{}, fmt.Errorf("update client: %w", err)
	}
	return c, nil
}

// RotateSecret generates a fresh secret for a confidential client. The
// existing hash is replaced; old tokens issued under the previous secret
// are unaffected (JWTs aren't tied to client secrets — secrets gate
// /token, not the access tokens themselves). Any currently-running
// confidential client using the old secret will start failing on
// /token until it picks up the new one.
func (s *PostgresStore) RotateSecret(ctx context.Context, id string) (Client, string, error) {
	c, err := s.GetByID(ctx, id)
	if err != nil {
		return Client{}, "", err
	}
	if c.IsPublic {
		return Client{}, "", ErrInvalidClientShape
	}

	plaintext, err := generateClientSecret()
	if err != nil {
		return Client{}, "", fmt.Errorf("generate secret: %w", err)
	}
	hash, err := users.HashPassword(plaintext, users.DefaultArgon2Params)
	if err != nil {
		return Client{}, "", fmt.Errorf("hash secret: %w", err)
	}

	const q = `
        UPDATE clients
        SET secret_hash = $2
        WHERE id = $1
        RETURNING id, COALESCE(secret_hash, ''), redirect_uris, allowed_grants,
                  allowed_scopes, is_public, created_at`

	var saved Client
	err = s.pool.QueryRow(ctx, q, id, hash).Scan(
		&saved.ID, &saved.SecretHash, &saved.RedirectURIs, &saved.AllowedGrants,
		&saved.AllowedScopes, &saved.IsPublic, &saved.CreatedAt)
	if err != nil {
		return Client{}, "", fmt.Errorf("rotate secret: %w", err)
	}
	return saved, plaintext, nil
}

// Delete removes a client. FK-cascading rows (authorization_codes,
// consents) go with it.
func (s *PostgresStore) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM clients WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// generateClientSecret returns a 32-byte random string base64url-encoded
// (43 chars, no padding). 256 bits of entropy; comparable to OAuth
// client secrets at major IdPs.
func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --- Policy helpers that don't touch the DB. Exposed as free functions so
// they're trivially testable without a store. ---

// CheckRedirectURI enforces exact-match between a requested redirect_uri and
// one of the client's registered URIs. RFC 6749 §3.1.2.2 requires this for
// confidential clients and strongly recommends it for public. We require it
// for all.
func (c Client) CheckRedirectURI(requested string) error {
	if slices.Contains(c.RedirectURIs, requested) {
		return nil
	}
	return ErrRedirectURINotAllowed
}

// CheckGrant enforces that the requested grant_type is in the client's allow list.
func (c Client) CheckGrant(grant string) error {
	if slices.Contains(c.AllowedGrants, grant) {
		return nil
	}
	return ErrGrantNotAllowed
}

// CheckScopes verifies every requested scope is a subset of AllowedScopes.
// An empty requested list is allowed — scopes are optional per RFC 6749.
func (c Client) CheckScopes(requested []string) error {
	for _, r := range requested {
		if !slices.Contains(c.AllowedScopes, r) {
			return fmt.Errorf("%w: %q", ErrScopeNotAllowed, r)
		}
	}
	return nil
}
