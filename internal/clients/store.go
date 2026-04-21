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
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// Sentinel errors. Handlers map these to OAuth error codes.
var (
	ErrNotFound               = errors.New("client not found")
	ErrInvalidClientAuth      = errors.New("client authentication failed")
	ErrRedirectURINotAllowed  = errors.New("redirect_uri not registered for this client")
	ErrGrantNotAllowed        = errors.New("grant_type not allowed for this client")
	ErrScopeNotAllowed        = errors.New("requested scope exceeds client's allowed scopes")
)

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
