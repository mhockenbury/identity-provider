package users_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// seed a user via the user store so session FK constraints hold.
func seedUser(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	s := testStore(pool) // from store_test.go — same package _test
	email := uniqueEmail("sess")
	u, err := s.Create(context.Background(), email, "password-ok")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID)
	})
	return u.ID
}

func TestSession_CreateAndGet(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewPostgresSessionStore(pool)
	userID := seedUser(t, pool)

	sess, err := store.Create(context.Background(), userID, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.ID == uuid.Nil {
		t.Error("ID not populated")
	}
	if sess.UserID != userID {
		t.Errorf("UserID = %v, want %v", sess.UserID, userID)
	}
	if sess.ExpiresAt.Before(time.Now().Add(50*time.Minute)) {
		t.Errorf("ExpiresAt too early: %v", sess.ExpiresAt)
	}

	got, err := store.Get(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("round-trip ID mismatch")
	}
}

func TestSession_GetUnknownReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewPostgresSessionStore(pool)

	_, err := store.Get(context.Background(), uuid.New())
	if !errors.Is(err, users.ErrSessionNotFound) {
		t.Errorf("err = %v, want ErrSessionNotFound", err)
	}
}

// Expired sessions return ErrSessionExpired AND get cleaned up on the
// Get call. Second Get of the same ID should return NotFound.
func TestSession_ExpiredReturnsExpiredAndCleansUp(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewPostgresSessionStore(pool)
	userID := seedUser(t, pool)

	// 1ms TTL — effectively already expired.
	sess, err := store.Create(context.Background(), userID, time.Millisecond)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	_, err = store.Get(context.Background(), sess.ID)
	if !errors.Is(err, users.ErrSessionExpired) {
		t.Errorf("err = %v, want ErrSessionExpired", err)
	}

	// Second Get should see NotFound — the first Get removed the row.
	_, err = store.Get(context.Background(), sess.ID)
	if !errors.Is(err, users.ErrSessionNotFound) {
		t.Errorf("after cleanup err = %v, want ErrSessionNotFound", err)
	}
}

// Delete is idempotent: unknown ID doesn't error.
func TestSession_DeleteIdempotent(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewPostgresSessionStore(pool)

	if err := store.Delete(context.Background(), uuid.New()); err != nil {
		t.Errorf("Delete unknown id: %v", err)
	}
}

// DeleteExpired clears only expired rows, not live ones.
func TestSession_DeleteExpiredOnlyRemovesExpired(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewPostgresSessionStore(pool)
	userID := seedUser(t, pool)

	live, err := store.Create(context.Background(), userID, time.Hour)
	if err != nil {
		t.Fatalf("create live: %v", err)
	}
	expired, err := store.Create(context.Background(), userID, time.Millisecond)
	if err != nil {
		t.Fatalf("create expired: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	_, err = store.DeleteExpired(context.Background())
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	// Live session still readable.
	if _, err := store.Get(context.Background(), live.ID); err != nil {
		t.Errorf("live session gone: %v", err)
	}
	// Expired session gone.
	if _, err := store.Get(context.Background(), expired.ID); !errors.Is(err, users.ErrSessionNotFound) {
		t.Errorf("expired session err = %v, want ErrSessionNotFound", err)
	}

	// Clean up the live row.
	t.Cleanup(func() { _ = store.Delete(context.Background(), live.ID) })
}
