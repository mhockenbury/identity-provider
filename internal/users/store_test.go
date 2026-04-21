package users_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// Integration tests against docker compose Postgres. Skipped if unreachable.
//
// Run locally:
//   make up
//   make migrate
//   DATABASE_URL=postgres://idp:idp@localhost:5434/idp?sslmode=disable \
//       go test ./internal/users/

const defaultDSN = "postgres://idp:idp@localhost:5434/idp?sslmode=disable"

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDSN
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres not reachable (dsn=%s): %v", dsn, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("postgres ping failed: %v", err)
	}
	return pool
}

// uniqueEmail generates a nanosecond-stamped address so parallel runs
// don't trample each other.
func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s+%d@example.com", prefix, time.Now().UnixNano())
}

func cleanup(t *testing.T, pool *pgxpool.Pool, email string) {
	t.Helper()
	_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE email=$1`, email)
}

// testStore returns a store with weak argon2 params so tests run fast.
func testStore(pool *pgxpool.Pool) *users.PostgresStore {
	return users.NewPostgresStoreWithParams(pool, users.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1,
		SaltLength: 16, KeyLength: 32,
	})
}

func TestCreate_HappyPath(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	email := uniqueEmail("alice")
	defer cleanup(t, pool, email)

	u, err := s.Create(context.Background(), email, "password-ok")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID.String() == "" {
		t.Errorf("ID not populated")
	}
	if u.Email != email {
		t.Errorf("Email = %q, want %q", u.Email, email)
	}
	if u.PasswordHash == "" || u.PasswordHash == "password-ok" {
		t.Errorf("PasswordHash should be hashed, got %q", u.PasswordHash)
	}
	if u.CreatedAt.IsZero() {
		t.Errorf("CreatedAt not populated")
	}
}

func TestCreate_DuplicateEmailReturnsErrEmailTaken(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	email := uniqueEmail("dup")
	defer cleanup(t, pool, email)

	if _, err := s.Create(context.Background(), email, "password-ok"); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := s.Create(context.Background(), email, "password-ok-2")
	if !errors.Is(err, users.ErrEmailTaken) {
		t.Errorf("err = %v, want ErrEmailTaken", err)
	}
}

func TestCreate_EmailLowerCased(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	upper := fmt.Sprintf("ALICE+%d@EXAMPLE.COM", time.Now().UnixNano())
	lower := strings.ToLower(upper)
	defer cleanup(t, pool, lower)

	u, err := s.Create(context.Background(), upper, "password-ok")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.Email != lower {
		t.Errorf("stored email = %q, want lower-cased %q", u.Email, lower)
	}

	// Lookup with original uppercase input must also find the row — confirms
	// GetByEmail applies the same normalization.
	looked, err := s.GetByEmail(context.Background(), upper)
	if err != nil {
		t.Fatalf("GetByEmail with uppercase input: %v", err)
	}
	if looked.ID != u.ID {
		t.Errorf("lookups with different casings returned different users")
	}
}

func TestCreate_RejectsInvalidEmail(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	cases := []string{"", "no-at-sign", "@nodomain", "missing-dot@localhost", "@"}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := s.Create(context.Background(), c, "password-ok")
			if !errors.Is(err, users.ErrInvalidEmail) {
				t.Errorf("err = %v, want ErrInvalidEmail", err)
			}
		})
	}
}

func TestCreate_RejectsWeakPassword(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	email := uniqueEmail("weak")
	_, err := s.Create(context.Background(), email, "short")
	if !errors.Is(err, users.ErrWeakPassword) {
		t.Errorf("err = %v, want ErrWeakPassword", err)
	}
}

func TestGetByEmail_NotFoundReturnsErrNotFound(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	_, err := s.GetByEmail(context.Background(), uniqueEmail("missing"))
	if !errors.Is(err, users.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestAuthenticate_CorrectPasswordSucceeds(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	email := uniqueEmail("auth")
	defer cleanup(t, pool, email)

	if _, err := s.Create(context.Background(), email, "right-password"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	u, err := s.Authenticate(context.Background(), email, "right-password")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u.Email != email {
		t.Errorf("Email = %q, want %q", u.Email, email)
	}
}

func TestAuthenticate_WrongPasswordReturnsMismatch(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	email := uniqueEmail("auth-wrong")
	defer cleanup(t, pool, email)

	if _, err := s.Create(context.Background(), email, "right-password"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := s.Authenticate(context.Background(), email, "wrong-password")
	if !errors.Is(err, users.ErrPasswordMismatch) {
		t.Errorf("err = %v, want ErrPasswordMismatch", err)
	}
}

func TestAuthenticate_NoSuchUserReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	_, err := s.Authenticate(context.Background(), uniqueEmail("noone"), "whatever")
	if !errors.Is(err, users.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestGetByID_RoundTrip(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := testStore(pool)

	email := uniqueEmail("byid")
	defer cleanup(t, pool, email)

	created, err := s.Create(context.Background(), email, "password-ok")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	looked, err := s.GetByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if looked.ID != created.ID || looked.Email != created.Email {
		t.Errorf("mismatch: got %+v, want %+v", looked, created)
	}
}
