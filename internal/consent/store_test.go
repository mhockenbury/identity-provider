package consent_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/consent"
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
	t.Cleanup(func() { pool.Close() })
	return pool
}

func seedUserAndClient(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()

	us := users.NewPostgresStoreWithParams(pool, users.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	email := fmt.Sprintf("consent-%d@example.com", time.Now().UnixNano())
	u, err := us.Create(ctx, email, "password-ok")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	clientID := fmt.Sprintf("test-consent-%d", time.Now().UnixNano())
	_, err = pool.Exec(ctx,
		`INSERT INTO clients (id, redirect_uris, allowed_grants, allowed_scopes, is_public)
		 VALUES ($1, $2, $3, $4, TRUE)`,
		clientID,
		[]string{"http://localhost/cb"},
		[]string{"authorization_code"},
		[]string{"openid", "read:docs", "write:docs"})
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM clients WHERE id=$1`, clientID) })

	return u.ID, clientID
}

func TestConsent_HasScopes_NoRowReturnsFalse(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	got, err := store.HasScopes(context.Background(), uid, cid, []string{"openid"})
	if err != nil {
		t.Fatalf("HasScopes: %v", err)
	}
	if got {
		t.Error("expected false when no consent row exists")
	}
}

func TestConsent_HasScopes_EmptyRequestVacuouslyTrue(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	got, err := store.HasScopes(context.Background(), uid, cid, nil)
	if err != nil {
		t.Fatalf("HasScopes: %v", err)
	}
	if !got {
		t.Error("empty scope list should be vacuously true")
	}
}

func TestConsent_GrantAndReadBack(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	if err := store.Grant(context.Background(), uid, cid, []string{"openid", "read:docs"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	got, err := store.HasScopes(context.Background(), uid, cid, []string{"openid", "read:docs"})
	if err != nil {
		t.Fatalf("HasScopes: %v", err)
	}
	if !got {
		t.Error("expected true after Grant")
	}
}

// Order-independent: Grant([a,b]) → HasScopes([b,a]) = true.
func TestConsent_OrderIndependent(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	_ = store.Grant(context.Background(), uid, cid, []string{"openid", "read:docs"})
	got, _ := store.HasScopes(context.Background(), uid, cid, []string{"read:docs", "openid"})
	if !got {
		t.Error("HasScopes must be order-independent")
	}
}

// Subset: Grant([a,b,c]) → HasScopes([a]) = true. Requesting LESS than
// previously consented is fine.
func TestConsent_SubsetRequestSucceeds(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	_ = store.Grant(context.Background(), uid, cid, []string{"openid", "read:docs", "write:docs"})
	got, _ := store.HasScopes(context.Background(), uid, cid, []string{"openid"})
	if !got {
		t.Error("requesting a subset of consented scopes should pass")
	}
}

// Superset: Grant([a]) → HasScopes([a,b]) = false. Re-prompts user.
func TestConsent_SupersetRequestFails(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	_ = store.Grant(context.Background(), uid, cid, []string{"openid"})
	got, _ := store.HasScopes(context.Background(), uid, cid, []string{"openid", "write:docs"})
	if got {
		t.Error("requesting a superset of consented scopes should require re-prompt")
	}
}

// Upsert: Grant([a]) then Grant([a,b]) — second overrides the first.
func TestConsent_GrantOverwrites(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	_ = store.Grant(context.Background(), uid, cid, []string{"openid"})
	_ = store.Grant(context.Background(), uid, cid, []string{"openid", "write:docs"})
	got, _ := store.HasScopes(context.Background(), uid, cid, []string{"openid", "write:docs"})
	if !got {
		t.Error("second Grant should have overwritten the first")
	}
}

// Duplicate scopes in input deduplicated before storage.
func TestConsent_GrantDedupesInput(t *testing.T) {
	pool := testPool(t)
	store := consent.NewPostgresStore(pool)
	uid, cid := seedUserAndClient(t, pool)

	_ = store.Grant(context.Background(), uid, cid, []string{"openid", "openid", "read:docs"})
	got, _ := store.HasScopes(context.Background(), uid, cid, []string{"openid", "read:docs"})
	if !got {
		t.Error("duplicates in input should be normalized away, still satisfy HasScopes")
	}
}
