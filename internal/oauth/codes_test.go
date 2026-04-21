package oauth_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/oauth"
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

// seedUserAndClient creates a user + OAuth client and returns their IDs,
// because authorization_codes rows have FKs to both. Returns the ids and
// registers cleanup that removes everything touched.
func seedUserAndClient(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()

	// User
	userStore := users.NewPostgresStoreWithParams(pool, users.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	email := fmt.Sprintf("code-%d@example.com", time.Now().UnixNano())
	u, err := userStore.Create(ctx, email, "password-ok")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })

	// Client
	clientID := fmt.Sprintf("test-code-%d", time.Now().UnixNano())
	_, err = pool.Exec(ctx,
		`INSERT INTO clients (id, secret_hash, redirect_uris, allowed_grants,
		                     allowed_scopes, is_public)
		 VALUES ($1, NULL, $2, $3, $4, TRUE)`,
		clientID,
		[]string{"http://localhost:5173/callback"},
		[]string{"authorization_code", "refresh_token"},
		[]string{"openid", "read:docs"})
	if err != nil {
		t.Fatalf("insert client: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM clients WHERE id=$1`, clientID) })

	return u.ID, clientID
}

func TestCodes_IssueAndConsumeRoundTrip(t *testing.T) {
	pool := testPool(t)
	store := oauth.NewPostgresAuthCodeStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	code, err := store.Issue(context.Background(), oauth.NewAuthCodeInput{
		ClientID:            clientID,
		UserID:              userID,
		RedirectURI:         "http://localhost:5173/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Scopes:              []string{"openid", "read:docs"},
		Nonce:               "n-0S6_WzA2Mj",
	}, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if code == "" {
		t.Fatal("got empty code")
	}

	row, err := store.Consume(context.Background(), code, clientID, "http://localhost:5173/callback")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if row.UserID != userID {
		t.Errorf("UserID = %v", row.UserID)
	}
	if row.CodeChallenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("CodeChallenge = %q", row.CodeChallenge)
	}
	if len(row.Scopes) != 2 || row.Scopes[0] != "openid" || row.Scopes[1] != "read:docs" {
		t.Errorf("Scopes = %v", row.Scopes)
	}
	if row.Nonce != "n-0S6_WzA2Mj" {
		t.Errorf("Nonce = %q", row.Nonce)
	}
	if row.UsedAt == nil {
		t.Error("UsedAt not set after Consume")
	}
}

// Single-use: first Consume succeeds, second returns ErrCodeAlreadyUsed.
// This is the core RFC 6749 §4.1.2 property the store exists to enforce.
func TestCodes_ConsumeTwiceRejectsSecondAttempt(t *testing.T) {
	pool := testPool(t)
	store := oauth.NewPostgresAuthCodeStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	code, err := store.Issue(context.Background(), oauth.NewAuthCodeInput{
		ClientID: clientID, UserID: userID,
		RedirectURI:         "http://localhost:5173/callback",
		CodeChallenge:       "x", CodeChallengeMethod: "S256",
		Scopes: []string{"openid"},
	}, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := store.Consume(context.Background(), code, clientID, "http://localhost:5173/callback"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	_, err = store.Consume(context.Background(), code, clientID, "http://localhost:5173/callback")
	if !errors.Is(err, oauth.ErrCodeAlreadyUsed) {
		t.Errorf("second Consume err = %v, want ErrCodeAlreadyUsed", err)
	}
}

// Client mismatch: code was issued to client A, client B tries to redeem.
// Rejected BEFORE we burn the code — the legitimate holder can still try.
func TestCodes_ConsumeWrongClientRejected(t *testing.T) {
	pool := testPool(t)
	store := oauth.NewPostgresAuthCodeStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	code, _ := store.Issue(context.Background(), oauth.NewAuthCodeInput{
		ClientID: clientID, UserID: userID,
		RedirectURI:         "http://localhost:5173/callback",
		CodeChallenge:       "x", CodeChallengeMethod: "S256",
		Scopes: []string{"openid"},
	}, time.Minute)

	_, err := store.Consume(context.Background(), code, "some-other-client", "http://localhost:5173/callback")
	if !errors.Is(err, oauth.ErrCodeClientMismatch) {
		t.Errorf("err = %v, want ErrCodeClientMismatch", err)
	}

	// Code should still be redeemable by the legitimate client.
	if _, err := store.Consume(context.Background(), code, clientID, "http://localhost:5173/callback"); err != nil {
		t.Errorf("legitimate Consume after mismatch: %v", err)
	}
}

// Redirect URI mismatch: same handling as client mismatch.
func TestCodes_ConsumeWrongRedirectURIRejected(t *testing.T) {
	pool := testPool(t)
	store := oauth.NewPostgresAuthCodeStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	code, _ := store.Issue(context.Background(), oauth.NewAuthCodeInput{
		ClientID: clientID, UserID: userID,
		RedirectURI:         "http://localhost:5173/callback",
		CodeChallenge:       "x", CodeChallengeMethod: "S256",
		Scopes: []string{"openid"},
	}, time.Minute)

	_, err := store.Consume(context.Background(), code, clientID, "http://evil.example/callback")
	if !errors.Is(err, oauth.ErrCodeClientMismatch) {
		t.Errorf("err = %v, want ErrCodeClientMismatch", err)
	}
}

// Expired code: Consume returns ErrCodeExpired without marking it used.
func TestCodes_ExpiredRejected(t *testing.T) {
	pool := testPool(t)
	store := oauth.NewPostgresAuthCodeStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	code, _ := store.Issue(context.Background(), oauth.NewAuthCodeInput{
		ClientID: clientID, UserID: userID,
		RedirectURI:         "http://localhost:5173/callback",
		CodeChallenge:       "x", CodeChallengeMethod: "S256",
		Scopes: []string{"openid"},
	}, time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	_, err := store.Consume(context.Background(), code, clientID, "http://localhost:5173/callback")
	if !errors.Is(err, oauth.ErrCodeExpired) {
		t.Errorf("err = %v, want ErrCodeExpired", err)
	}
}

func TestCodes_UnknownCodeReturnsNotFound(t *testing.T) {
	pool := testPool(t)
	store := oauth.NewPostgresAuthCodeStore(pool)

	_, err := store.Consume(context.Background(), "not-a-real-code", "any", "any")
	if !errors.Is(err, oauth.ErrCodeNotFound) {
		t.Errorf("err = %v, want ErrCodeNotFound", err)
	}
}

// Concurrent Consume: N goroutines race to redeem the same code. Exactly
// one must succeed; all others get ErrCodeAlreadyUsed. This is the
// property the UPDATE ... WHERE used_at IS NULL RETURNING pattern enforces.
func TestCodes_ConsumeIsAtomic(t *testing.T) {
	pool := testPool(t)
	store := oauth.NewPostgresAuthCodeStore(pool)
	userID, clientID := seedUserAndClient(t, pool)

	code, err := store.Issue(context.Background(), oauth.NewAuthCodeInput{
		ClientID: clientID, UserID: userID,
		RedirectURI:         "http://localhost:5173/callback",
		CodeChallenge:       "x", CodeChallengeMethod: "S256",
		Scopes: []string{"openid"},
	}, time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	const N = 8
	results := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			_, err := store.Consume(context.Background(), code, clientID, "http://localhost:5173/callback")
			results <- err
		}()
	}

	successCount := 0
	usedCount := 0
	for i := 0; i < N; i++ {
		err := <-results
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, oauth.ErrCodeAlreadyUsed):
			usedCount++
		default:
			t.Errorf("unexpected err: %v", err)
		}
	}
	if successCount != 1 {
		t.Errorf("successCount = %d, want exactly 1", successCount)
	}
	if usedCount != N-1 {
		t.Errorf("usedCount = %d, want %d", usedCount, N-1)
	}
}
