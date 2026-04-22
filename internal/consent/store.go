// Package consent tracks user consent per (user, client) keyed by scope
// set. Re-prompts on scope-set change.
//
// Design: one row per (user_id, client_id). Overwritten on new consent.
// Scope comparison is order-independent; we sort scopes before storing +
// comparing so "openid read:docs" and "read:docs openid" count as the
// same consent.
//
// Not in scope today: consent revocation UI (user can't revoke); per-
// scope granularity (consent is all-or-nothing for the requested set).
package consent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNoConsent = errors.New("no consent recorded")
)

// Consent is the row shape.
type Consent struct {
	UserID    uuid.UUID
	ClientID  string
	Scopes    []string // stored sorted
	GrantedAt time.Time
}

// Store is the persistence surface.
type Store interface {
	// HasScopes returns true if the user has previously consented to ALL
	// of the requested scopes for this client. Set comparison — order
	// and duplicates don't matter.
	HasScopes(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) (bool, error)

	// Grant upserts a consent row, replacing any prior scopes for this
	// (user, client) pair. "Consented once, then a new scope was added
	// to the request" → the next HasScopes returns false → prompt again.
	Grant(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// HasScopes reads the row if any and checks that requested ⊆ stored.
func (s *PostgresStore) HasScopes(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) (bool, error) {
	if len(scopes) == 0 {
		// No scopes requested → no consent to check. Vacuously true.
		return true, nil
	}

	const q = `
        SELECT scopes FROM consents WHERE user_id = $1 AND client_id = $2`

	var stored []string
	err := s.pool.QueryRow(ctx, q, userID, clientID).Scan(&stored)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("read consent: %w", err)
	}

	// Requested must be a subset of stored.
	for _, want := range scopes {
		if !slices.Contains(stored, want) {
			return false, nil
		}
	}
	return true, nil
}

// Grant upserts. We sort + dedupe before storing so comparisons are
// deterministic.
func (s *PostgresStore) Grant(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) error {
	stored := normalizeScopes(scopes)

	const q = `
        INSERT INTO consents (user_id, client_id, scopes, granted_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (user_id, client_id)
        DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = now()`

	_, err := s.pool.Exec(ctx, q, userID, clientID, stored)
	if err != nil {
		return fmt.Errorf("upsert consent: %w", err)
	}
	return nil
}

// normalizeScopes sorts + dedupes. Uses a small O(n²) loop for dedupe;
// scope sets are tiny (rarely >10 entries).
func normalizeScopes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}
