package tokens_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/tokens"
	"github.com/mhockenbury/identity-provider/internal/users"
)

func seedUserAndClient(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()

	userStore := users.NewPostgresStoreWithParams(pool, users.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	email := fmt.Sprintf("refresh-%d@example.com", time.Now().UnixNano())
	u, err := userStore.Create(ctx, email, "password-ok")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	clientID := fmt.Sprintf("refresh-client-%d", time.Now().UnixNano())
	_, err = pool.Exec(ctx,
		`INSERT INTO clients (id, redirect_uris, allowed_grants, allowed_scopes, is_public)
		 VALUES ($1, $2, $3, $4, TRUE)`,
		clientID,
		[]string{"http://localhost/cb"},
		[]string{"authorization_code", "refresh_token"},
		[]string{"openid", "read:docs", "write:docs"})
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM clients WHERE id=$1`, clientID) })

	return u.ID, clientID
}

func TestRefresh_IssueAndInspect(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	plaintext, row, err := store.Issue(context.Background(), userID, clientID, []string{"openid", "read:docs"}, "docs-api", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if plaintext == "" {
		t.Error("plaintext empty")
	}
	if len(plaintext) < 40 {
		t.Errorf("plaintext suspiciously short: %d chars", len(plaintext))
	}
	if row.UserID != userID || row.ClientID != clientID {
		t.Errorf("row fields mismatch: %+v", row)
	}
	if row.RevokedAt != nil {
		t.Errorf("new row should not be revoked")
	}
	if row.ExpiresAt.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("expires_at too early: %v", row.ExpiresAt)
	}

	// Plaintext must not appear in DB.
	var count int
	_ = pool.QueryRow(context.Background(),
		`SELECT count(*) FROM refresh_tokens WHERE token_hash = $1`, plaintext).Scan(&count)
	if count != 0 {
		t.Errorf("plaintext appears in DB as token_hash; must be hashed")
	}
}

func TestRefresh_Rotate_HappyPath(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	orig, _, err := store.Issue(context.Background(), userID, clientID, []string{"openid"}, "docs-api", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	newPlain, newRow, err := store.Rotate(context.Background(), orig, clientID, nil, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newPlain == orig {
		t.Error("new plaintext must differ from old")
	}
	if newRow.RotatedFrom == nil {
		t.Error("rotated_from must point at old row id")
	}
	if newRow.UserID != userID || newRow.ClientID != clientID {
		t.Errorf("row mismatch: %+v", newRow)
	}
}

func TestRefresh_Rotate_OldTokenRevoked(t *testing.T) {
	// After a successful rotate, the ORIGINAL plaintext must not be
	// redeemable. This is Level 2 rotation.
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	orig, _, _ := store.Issue(context.Background(), userID, clientID, []string{"openid"}, "docs-api", 30*24*time.Hour)
	_, _, err := store.Rotate(context.Background(), orig, clientID, nil, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	_, _, err = store.Rotate(context.Background(), orig, clientID, nil, 30*24*time.Hour)
	if !errors.Is(err, tokens.ErrRefreshRevoked) {
		t.Errorf("second Rotate with old token: err = %v, want ErrRefreshRevoked", err)
	}
}

func TestRefresh_Rotate_UnknownTokenReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)

	_, _, err := store.Rotate(context.Background(), "nonexistent-token-value", "anyclient", nil, time.Hour)
	if !errors.Is(err, tokens.ErrRefreshNotFound) {
		t.Errorf("err = %v, want ErrRefreshNotFound", err)
	}
}

// Client mismatch: token issued to client A cannot be rotated by client B.
// Same bucket as "revoked" from the caller's POV to avoid leaking whether
// the token belongs to someone else.
func TestRefresh_Rotate_WrongClientRejected(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	orig, _, _ := store.Issue(context.Background(), userID, clientID, []string{"openid"}, "docs-api", 30*24*time.Hour)

	_, _, err := store.Rotate(context.Background(), orig, "some-other-client", nil, 30*24*time.Hour)
	if !errors.Is(err, tokens.ErrRefreshRevoked) {
		t.Errorf("err = %v, want ErrRefreshRevoked", err)
	}
}

func TestRefresh_Rotate_ExpiredRejected(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	orig, _, _ := store.Issue(context.Background(), userID, clientID, []string{"openid"}, "docs-api", time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	_, _, err := store.Rotate(context.Background(), orig, clientID, nil, 30*24*time.Hour)
	if !errors.Is(err, tokens.ErrRefreshExpired) {
		t.Errorf("err = %v, want ErrRefreshExpired", err)
	}
}

// Scope downgrade: can rotate with SUBSET of original scopes.
// Scope upgrade: must be rejected — refresh MUST NOT grant new scopes
// (RFC 6749 §6).
func TestRefresh_Rotate_ScopeSubsetAllowed(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	orig, _, _ := store.Issue(context.Background(), userID, clientID,
		[]string{"openid", "read:docs", "write:docs"}, "docs-api", 30*24*time.Hour)

	_, row, err := store.Rotate(context.Background(), orig, clientID,
		[]string{"openid", "read:docs"}, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("Rotate with subset: %v", err)
	}
	if len(row.Scopes) != 2 {
		t.Errorf("new scopes = %v, want 2", row.Scopes)
	}
}

func TestRefresh_Rotate_ScopeUpgradeRejected(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	orig, _, _ := store.Issue(context.Background(), userID, clientID,
		[]string{"openid"}, "docs-api", 30*24*time.Hour)

	// Try to upgrade to include write:docs — not in the original grant.
	_, _, err := store.Rotate(context.Background(), orig, clientID,
		[]string{"openid", "write:docs"}, 30*24*time.Hour)
	if err == nil {
		t.Error("Rotate with scope upgrade should fail")
	}
}

// Concurrent Rotate calls: exactly one must succeed, others see revoked.
// The SELECT FOR UPDATE serializes access to the row.
func TestRefresh_Rotate_ConcurrentSerializes(t *testing.T) {
	pool := testPool(t)
	store := tokens.NewPostgresRefreshTokenStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	orig, _, _ := store.Issue(context.Background(), userID, clientID, []string{"openid"}, "docs-api", 30*24*time.Hour)

	const N = 8
	results := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			_, _, err := store.Rotate(context.Background(), orig, clientID, nil, 30*24*time.Hour)
			results <- err
		}()
	}

	successCount, revokedCount := 0, 0
	for i := 0; i < N; i++ {
		err := <-results
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, tokens.ErrRefreshRevoked):
			revokedCount++
		default:
			t.Errorf("unexpected err: %v", err)
		}
	}
	if successCount != 1 {
		t.Errorf("successCount = %d, want 1", successCount)
	}
	if revokedCount != N-1 {
		t.Errorf("revokedCount = %d, want %d", revokedCount, N-1)
	}
}
