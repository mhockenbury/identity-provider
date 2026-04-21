package clients_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/clients"
	"github.com/mhockenbury/identity-provider/internal/users"
)

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
	if err != nil || pool.Ping(ctx) != nil {
		if pool != nil {
			pool.Close()
		}
		t.Skipf("postgres not reachable: %v", err)
	}
	return pool
}

// cleanClient deletes a seeded test client. t.Cleanup is used so mid-test
// t.Fatal still removes the row.
func cleanClient(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM clients WHERE id=$1`, id)
	})
}

// seedConfidential inserts a confidential client with secret = "the-secret"
// (hashed with argon2id). Returns the client id for cleanup.
func seedConfidential(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	id := fmt.Sprintf("test-conf-%d", time.Now().UnixNano())
	hash, err := users.HashPassword("the-secret", users.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants,
		                     allowed_scopes, is_public)
		 VALUES ($1, $2, $3, $4, $5, FALSE)`,
		id, hash,
		[]string{"https://app.example.com/callback"},
		[]string{"authorization_code", "refresh_token"},
		[]string{"openid", "profile", "read:docs"})
	if err != nil {
		t.Fatalf("seed confidential client: %v", err)
	}
	cleanClient(t, pool, id)
	return id
}

// seedPublic inserts a public client with no secret.
func seedPublic(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	id := fmt.Sprintf("test-pub-%d", time.Now().UnixNano())
	_, err := pool.Exec(context.Background(),
		`INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants,
		                     allowed_scopes, is_public)
		 VALUES ($1, NULL, $2, $3, $4, TRUE)`,
		id,
		[]string{"http://localhost:5173/callback"},
		[]string{"authorization_code", "refresh_token"},
		[]string{"openid", "read:docs"})
	if err != nil {
		t.Fatalf("seed public client: %v", err)
	}
	cleanClient(t, pool, id)
	return id
}

func TestGetByID_HappyPath(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)
	id := seedConfidential(t, pool)

	c, err := s.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if c.ID != id {
		t.Errorf("ID mismatch")
	}
	if c.IsPublic {
		t.Errorf("expected confidential")
	}
	if c.SecretHash == "" {
		t.Errorf("confidential client should have SecretHash populated")
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Errorf("RedirectURIs = %v", c.RedirectURIs)
	}
}

func TestGetByID_NotFoundReturnsErrNotFound(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)

	_, err := s.GetByID(context.Background(), fmt.Sprintf("does-not-exist-%d", time.Now().UnixNano()))
	if !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestAuthenticate_Confidential_CorrectSecret(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)
	id := seedConfidential(t, pool)

	c, err := s.Authenticate(context.Background(), id, "the-secret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if c.ID != id {
		t.Errorf("ID mismatch")
	}
}

func TestAuthenticate_Confidential_WrongSecret(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)
	id := seedConfidential(t, pool)

	_, err := s.Authenticate(context.Background(), id, "wrong-secret")
	if !errors.Is(err, clients.ErrInvalidClientAuth) {
		t.Errorf("err = %v, want ErrInvalidClientAuth", err)
	}
}

func TestAuthenticate_Confidential_MissingSecret(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)
	id := seedConfidential(t, pool)

	_, err := s.Authenticate(context.Background(), id, "")
	if !errors.Is(err, clients.ErrInvalidClientAuth) {
		t.Errorf("err = %v, want ErrInvalidClientAuth", err)
	}
}

func TestAuthenticate_Public_NoSecretOK(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)
	id := seedPublic(t, pool)

	c, err := s.Authenticate(context.Background(), id, "")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !c.IsPublic {
		t.Errorf("expected IsPublic")
	}
}

// A public client sending a secret is a misconfig; we reject rather than
// silently allow — "strict even on the easy path" matches OAuth BCP norms.
func TestAuthenticate_Public_WithSecretRejected(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)
	id := seedPublic(t, pool)

	_, err := s.Authenticate(context.Background(), id, "accidental-secret")
	if !errors.Is(err, clients.ErrInvalidClientAuth) {
		t.Errorf("err = %v, want ErrInvalidClientAuth", err)
	}
}

func TestAuthenticate_UnknownClient(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := clients.NewPostgresStore(pool)

	_, err := s.Authenticate(context.Background(), fmt.Sprintf("unknown-%d", time.Now().UnixNano()), "")
	if !errors.Is(err, clients.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

// --- Policy helpers (no DB) ---

func TestCheckRedirectURI_ExactMatchRequired(t *testing.T) {
	c := clients.Client{
		RedirectURIs: []string{
			"https://app.example.com/callback",
			"http://localhost:5173/callback",
		},
	}

	ok := []string{
		"https://app.example.com/callback",
		"http://localhost:5173/callback",
	}
	bad := []string{
		"",
		"https://app.example.com/callback/",   // trailing slash
		"https://app.example.com/CALLBACK",    // wrong case
		"https://evil.example.com/callback",
		"https://app.example.com/callback?x=1",
	}

	for _, u := range ok {
		if err := c.CheckRedirectURI(u); err != nil {
			t.Errorf("CheckRedirectURI(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range bad {
		if err := c.CheckRedirectURI(u); !errors.Is(err, clients.ErrRedirectURINotAllowed) {
			t.Errorf("CheckRedirectURI(%q) = %v, want ErrRedirectURINotAllowed", u, err)
		}
	}
}

func TestCheckGrant(t *testing.T) {
	c := clients.Client{AllowedGrants: []string{"authorization_code", "refresh_token"}}

	if err := c.CheckGrant("authorization_code"); err != nil {
		t.Errorf("allowed grant rejected: %v", err)
	}
	if err := c.CheckGrant("client_credentials"); !errors.Is(err, clients.ErrGrantNotAllowed) {
		t.Errorf("err = %v, want ErrGrantNotAllowed", err)
	}
}

func TestCheckScopes(t *testing.T) {
	c := clients.Client{AllowedScopes: []string{"openid", "profile", "read:docs"}}

	// Subset: all good.
	if err := c.CheckScopes([]string{"openid", "read:docs"}); err != nil {
		t.Errorf("subset rejected: %v", err)
	}
	// Empty: allowed (OAuth lets scope be optional).
	if err := c.CheckScopes(nil); err != nil {
		t.Errorf("empty scopes rejected: %v", err)
	}
	// Superset: rejected, reporting which scope offended.
	err := c.CheckScopes([]string{"openid", "admin:users"})
	if !errors.Is(err, clients.ErrScopeNotAllowed) {
		t.Errorf("err = %v, want ErrScopeNotAllowed", err)
	}
}
