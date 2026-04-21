// Package users holds the user + group stores, password hashing
// (argon2id), and the `group_memberships` CRUD that drives FGA tuple sync.
package users

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors returned by Store. Callers match on these to map to HTTP
// responses without coupling to pgx error types.
var (
	ErrNotFound       = errors.New("user not found")
	ErrEmailTaken     = errors.New("email already in use")
	ErrInvalidEmail   = errors.New("invalid email")
	ErrWeakPassword   = errors.New("password does not meet minimum requirements")
)

// Postgres unique-violation SQLSTATE.
const pgUniqueViolation = "23505"

// User mirrors the `users` row 1:1.
type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	CreatedAt    time.Time
}

// Store is the users package's persistence surface. Tests + handlers depend
// on this interface, not on *pgxpool.Pool directly.
type Store interface {
	Create(ctx context.Context, email, password string) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
	// Authenticate is a convenience that GetByEmail + VerifyPassword; returns
	// ErrNotFound or ErrPasswordMismatch on failure. Callers should treat both
	// as "invalid credentials" to avoid leaking user enumeration.
	Authenticate(ctx context.Context, email, password string) (User, error)
}

// PostgresStore is the Postgres-backed implementation. It writes the users
// table directly; group memberships are separate (see groups.go when that
// file exists).
type PostgresStore struct {
	pool   *pgxpool.Pool
	params Argon2Params
}

// NewPostgresStore wraps a pool with the default argon2 params.
// Use NewPostgresStoreWithParams if you need to tune them (tests do).
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return NewPostgresStoreWithParams(pool, DefaultArgon2Params)
}

func NewPostgresStoreWithParams(pool *pgxpool.Pool, params Argon2Params) *PostgresStore {
	return &PostgresStore{pool: pool, params: params}
}

// Minimum password requirements for lab use. Conservative — an 8-char min is
// the OWASP floor; longer is better but we're not in the business of
// password policy complexity here.
const minPasswordLen = 8

// Create inserts a new user. Email is lower-cased and whitespace-trimmed
// before storage. Returns ErrEmailTaken on unique-constraint conflict.
func (s *PostgresStore) Create(ctx context.Context, email, password string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !looksLikeEmail(email) {
		return User{}, ErrInvalidEmail
	}
	if len(password) < minPasswordLen {
		return User{}, ErrWeakPassword
	}

	hash, err := HashPassword(password, s.params)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}

	const q = `
        INSERT INTO users (email, password_hash)
        VALUES ($1, $2)
        RETURNING id, email, password_hash, created_at`

	var u User
	err = s.pool.QueryRow(ctx, q, email, hash).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

// GetByEmail returns the user row for an exact email match (after lower-case).
func (s *PostgresStore) GetByEmail(ctx context.Context, email string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	const q = `
        SELECT id, email, password_hash, created_at
        FROM users
        WHERE email = $1`

	var u User
	err := s.pool.QueryRow(ctx, q, email).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// GetByID returns the user row for a UUID. Used by session resolution.
func (s *PostgresStore) GetByID(ctx context.Context, id uuid.UUID) (User, error) {
	const q = `
        SELECT id, email, password_hash, created_at
        FROM users
        WHERE id = $1`

	var u User
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// Authenticate combines lookup + password verify. Returns a populated User
// on success; ErrNotFound if no user with that email; ErrPasswordMismatch
// if password doesn't verify. Handler code should map both to the same
// "invalid credentials" response to avoid user enumeration.
func (s *PostgresStore) Authenticate(ctx context.Context, email, password string) (User, error) {
	u, err := s.GetByEmail(ctx, email)
	if err != nil {
		return User{}, err
	}
	if err := VerifyPassword(password, u.PasswordHash); err != nil {
		return User{}, err
	}
	return u, nil
}

// looksLikeEmail is a deliberately cheap sanity check — we don't try to
// RFC-5322 parse. Presence of "@", a non-empty local + domain part, and
// a dot in the domain is enough to reject obvious garbage.
func looksLikeEmail(s string) bool {
	at := strings.Index(s, "@")
	if at <= 0 || at == len(s)-1 {
		return false
	}
	domain := s[at+1:]
	if !strings.Contains(domain, ".") {
		return false
	}
	return true
}
