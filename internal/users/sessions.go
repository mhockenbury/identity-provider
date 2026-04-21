package users

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session cookie design (lab scope):
//
//   - Cookie carries the session ID only (UUID). Server resolves it via
//     a Postgres lookup on every auth-gated request.
//
//   - UNSIGNED on purpose. A forged session ID fails the DB lookup, so
//     the security property ("unforgeable") holds without HMAC. In a real
//     IdP you'd HMAC-sign for defense in depth (so you can reject at the
//     middleware without a DB hit) and to detect tampering of any
//     additional data you put in the cookie. Keeping this simple so the
//     OAuth/OIDC protocol work stays center stage; revisit if the session
//     cookie ever carries anything beyond the ID.
//
//   - HttpOnly + SameSite=Lax. Secure=true only when ISSUER_URL is https
//     (handler layer sets that).
//
//   - 12-hour absolute lifetime. No sliding extension in this lab — when
//     it expires, the user re-logs-in.

// Session is the in-memory view of a sessions row.
type Session struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
}

// DefaultSessionTTL is the absolute lifetime for a new session.
const DefaultSessionTTL = 12 * time.Hour

// Sentinel errors the middleware maps to responses.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

// SessionStore creates + resolves + deletes sessions. The session cookie
// carries Session.ID.String(); everything else lives in the DB.
type SessionStore interface {
	Create(ctx context.Context, userID uuid.UUID, ttl time.Duration) (Session, error)
	Get(ctx context.Context, id uuid.UUID) (Session, error)
	Delete(ctx context.Context, id uuid.UUID) error
	// DeleteExpired is a housekeeping helper; a cron or startup hook can
	// call it. Not wired up in the lab's serve loop.
	DeleteExpired(ctx context.Context) (int64, error)
}

// PostgresSessionStore is the Postgres-backed implementation.
type PostgresSessionStore struct {
	pool *pgxpool.Pool
}

func NewPostgresSessionStore(pool *pgxpool.Pool) *PostgresSessionStore {
	return &PostgresSessionStore{pool: pool}
}

// Create inserts a new session for userID with the given TTL. TTL must
// be positive; zero or negative falls back to DefaultSessionTTL.
func (s *PostgresSessionStore) Create(ctx context.Context, userID uuid.UUID, ttl time.Duration) (Session, error) {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	const q = `
        INSERT INTO sessions (user_id, expires_at)
        VALUES ($1, now() + $2::interval)
        RETURNING id, user_id, created_at, expires_at`

	// pgx passes Go durations cleanly if cast to the INTERVAL-compatible
	// form. "XXXms" is safe; anything bigger is fine too.
	intervalSpec := fmt.Sprintf("%d milliseconds", ttl.Milliseconds())

	var sess Session
	err := s.pool.QueryRow(ctx, q, userID, intervalSpec).Scan(
		&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("insert session: %w", err)
	}
	return sess, nil
}

// Get resolves a session ID. Returns ErrSessionNotFound if no row; returns
// ErrSessionExpired (AND deletes the row as a cheap GC) if expired.
func (s *PostgresSessionStore) Get(ctx context.Context, id uuid.UUID) (Session, error) {
	const q = `
        SELECT id, user_id, created_at, expires_at
        FROM sessions
        WHERE id = $1`

	var sess Session
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, fmt.Errorf("get session: %w", err)
	}

	if time.Now().After(sess.ExpiresAt) {
		// Best-effort cleanup. Don't block the caller on it; don't error
		// either — the expired sentinel is the thing the caller needs.
		_, _ = s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
		return Session{}, ErrSessionExpired
	}
	return sess, nil
}

// Delete removes a session (logout). No-error-on-not-found — idempotent.
func (s *PostgresSessionStore) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteExpired removes all expired sessions. Returns row count deleted.
// Safe to run periodically.
func (s *PostgresSessionStore) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()`)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
