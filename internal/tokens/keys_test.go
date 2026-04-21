package tokens_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/tokens"
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
	// Register the close via t.Cleanup so LIFO ordering runs row-deletion
	// cleanups BEFORE the pool is closed. A `defer pool.Close()` in the
	// caller runs first and nukes the pool, which breaks any t.Cleanup
	// DELETEs registered after — silent failure because the error was
	// ignored. This is the fix.
	t.Cleanup(func() { pool.Close() })
	return pool
}

// testKEK generates a random 32-byte KEK per test.
func testKEK(t *testing.T) *tokens.EnvKEK {
	t.Helper()
	key := make([]byte, tokens.KEKKeyLength)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	kek, err := tokens.NewEnvKEK(key)
	if err != nil {
		t.Fatalf("NewEnvKEK: %v", err)
	}
	return kek
}

// cleanKey registers a cleanup that deletes a specific kid after the test.
// t.Cleanup runs even if the test fails mid-way, keeping the table tidy.
func cleanKey(t *testing.T, pool *pgxpool.Pool, kid string) {
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM signing_keys WHERE kid=$1`, kid)
	})
}

func TestGenerate_CreatesPendingKey(t *testing.T) {
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))

	k, err := s.Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cleanKey(t, pool, k.KID)

	if k.Status() != tokens.StatusPending {
		t.Errorf("Status = %q, want pending", k.Status())
	}
	if k.Alg != tokens.AlgEdDSA {
		t.Errorf("Alg = %q, want EdDSA", k.Alg)
	}
	if len(k.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey size = %d, want %d", len(k.PublicKey), ed25519.PublicKeySize)
	}
	if k.ActivatedAt != nil {
		t.Errorf("ActivatedAt = %v, want nil", *k.ActivatedAt)
	}
	if k.CreatedAt.IsZero() {
		t.Errorf("CreatedAt not set")
	}
}

func TestGenerate_PrivateKeyRoundTripsThroughKEK(t *testing.T) {
	// The key we get back from Generate already has the private half
	// loaded. Persist the row, reload via GetByID, Unwrap, and confirm
	// we can sign with it — proves wrap → store → fetch → unwrap round
	// trips without corruption.
	pool := testPool(t)
	kek := testKEK(t)
	s := tokens.NewKeyStore(pool, kek)
	ctx := context.Background()

	k1, err := s.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cleanKey(t, pool, k1.KID)

	k2, err := s.GetByID(ctx, k1.KID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if err := k2.Unwrap(kek); err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	// Sign + verify the same message with both loaded private keys;
	// they must produce the same signature (Ed25519 is deterministic).
	msg := []byte("hello, signing world")
	sig1 := ed25519.Sign(k1.PrivateKey(), msg)
	sig2 := ed25519.Sign(k2.PrivateKey(), msg)

	if string(sig1) != string(sig2) {
		t.Errorf("reloaded private key produced a different signature (wrap/unwrap corrupted bits)")
	}
}

func TestActivate_Happy(t *testing.T) {
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))
	ctx := context.Background()

	k, err := s.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cleanKey(t, pool, k.KID)

	if err := s.Activate(ctx, k.KID); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	k2, err := s.GetByID(ctx, k.KID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if k2.Status() != tokens.StatusActive {
		t.Errorf("Status = %q, want active", k2.Status())
	}
	if k2.ActivatedAt == nil {
		t.Errorf("ActivatedAt not set after activate")
	}
}

// The partial unique index "signing_keys_one_active_idx" must prevent a
// second key from being activated while another is already active.
func TestActivate_SecondConcurrentActivationBlocked(t *testing.T) {
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))
	ctx := context.Background()

	a, err := s.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate a: %v", err)
	}
	cleanKey(t, pool, a.KID)

	b, err := s.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate b: %v", err)
	}
	cleanKey(t, pool, b.KID)

	if err := s.Activate(ctx, a.KID); err != nil {
		t.Fatalf("Activate a: %v", err)
	}
	err = s.Activate(ctx, b.KID)
	if !errors.Is(err, tokens.ErrKeyAlreadyActive) {
		t.Fatalf("Activate b: err = %v, want ErrKeyAlreadyActive", err)
	}
}

// Full rotation cycle: A active → generate B pending → activate B fails
// (DB constraint) → retire A → activate B succeeds → B is the only active.
func TestRotationCycle_RequiresRetireBeforeActivatingReplacement(t *testing.T) {
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))
	ctx := context.Background()

	a, _ := s.Generate(ctx)
	cleanKey(t, pool, a.KID)
	if err := s.Activate(ctx, a.KID); err != nil {
		t.Fatalf("Activate a: %v", err)
	}

	b, _ := s.Generate(ctx)
	cleanKey(t, pool, b.KID)

	// Can't activate B while A is still active.
	if err := s.Activate(ctx, b.KID); !errors.Is(err, tokens.ErrKeyAlreadyActive) {
		t.Fatalf("premature activate b: err = %v, want ErrKeyAlreadyActive", err)
	}

	// Retire A first, then B activates cleanly.
	if err := s.Retire(ctx, a.KID); err != nil {
		t.Fatalf("Retire a: %v", err)
	}
	if err := s.Activate(ctx, b.KID); err != nil {
		t.Fatalf("Activate b after retire: %v", err)
	}

	// GetActive returns B (only active row).
	active, err := s.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.KID != b.KID {
		t.Errorf("GetActive = %q, want %q", active.KID, b.KID)
	}
}

func TestActivate_AlreadyRetiredRejected(t *testing.T) {
	// You can't "re-activate" a retired key. The state machine is one-way.
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))
	ctx := context.Background()

	k, _ := s.Generate(ctx)
	cleanKey(t, pool, k.KID)
	if err := s.Activate(ctx, k.KID); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if err := s.Retire(ctx, k.KID); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	err := s.Activate(ctx, k.KID)
	if !errors.Is(err, tokens.ErrInvalidKeyState) {
		t.Errorf("err = %v, want ErrInvalidKeyState", err)
	}
}

func TestRetire_PendingKeyRejected(t *testing.T) {
	// Retire only works on ACTIVE keys; a PENDING key must be activated first.
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))
	ctx := context.Background()

	k, _ := s.Generate(ctx)
	cleanKey(t, pool, k.KID)

	err := s.Retire(ctx, k.KID)
	if !errors.Is(err, tokens.ErrInvalidKeyState) {
		t.Errorf("err = %v, want ErrInvalidKeyState", err)
	}
}

func TestGetActive_NoActiveReturnsSentinel(t *testing.T) {
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))
	ctx := context.Background()

	// Baseline: the database may already contain keys from other tests.
	// We can't assume "empty table," so we need a distinguishing strategy:
	// generate a pending key (doesn't become active), then verify the query
	// either finds an existing active key (fine; someone else activated) or
	// returns the sentinel. If there's already an active key we skip — this
	// test is about the sentinel path specifically.
	if _, err := s.GetActive(ctx); err == nil {
		t.Skip("another key is active in this DB; can't test no-active sentinel path")
	} else if !errors.Is(err, tokens.ErrNoActiveKey) {
		t.Errorf("err = %v, want ErrNoActiveKey", err)
	}
}

func TestGetByID_NotFoundReturnsSentinel(t *testing.T) {
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))

	_, err := s.GetByID(context.Background(), "k_does-not-exist")
	if !errors.Is(err, tokens.ErrKeyNotFound) {
		t.Errorf("err = %v, want ErrKeyNotFound", err)
	}
}

// ForJWKS should include ACTIVE and PENDING but exclude RETIRED. The lab
// design has retired keys drop from JWKS immediately on Retire (the overlap
// window is enforced by the operator waiting before calling Retire).
func TestForJWKS_IncludesActiveAndPendingExcludesRetired(t *testing.T) {
	pool := testPool(t)
	s := tokens.NewKeyStore(pool, testKEK(t))
	ctx := context.Background()

	// Create three keys: one we'll activate, one we'll leave pending,
	// one we'll activate + retire. The retired one should be absent from
	// ForJWKS output.
	activeKey, _ := s.Generate(ctx)
	cleanKey(t, pool, activeKey.KID)
	if err := s.Activate(ctx, activeKey.KID); err != nil {
		t.Fatalf("Activate active: %v", err)
	}
	defer func() {
		// Retire active at test end so subsequent runs of
		// "second-concurrent-activation-blocked" don't fail because this
		// test left an active key behind. (cleanKey deletes the row,
		// but deletion happens AFTER Retire's status check runs in other
		// tests. Safer to just retire.)
		_ = s.Retire(ctx, activeKey.KID)
	}()

	pendingKey, _ := s.Generate(ctx)
	cleanKey(t, pool, pendingKey.KID)

	retiredKey, _ := s.Generate(ctx)
	cleanKey(t, pool, retiredKey.KID)
	// Can't activate while activeKey is active — so retire activeKey
	// first, flip retiredKey active, retire retiredKey, then re-activate
	// activeKey... too much test gymnastics. Simpler: touch the DB
	// directly to put retiredKey into a RETIRED state.
	_, err := pool.Exec(ctx,
		`UPDATE signing_keys SET activated_at=now()-interval '1 hour',
		 retired_at=now() WHERE kid=$1`, retiredKey.KID)
	if err != nil {
		t.Fatalf("force-retire: %v", err)
	}

	keys, err := s.ForJWKS(ctx)
	if err != nil {
		t.Fatalf("ForJWKS: %v", err)
	}

	got := map[string]bool{}
	for _, k := range keys {
		got[k.KID] = true
	}
	if !got[activeKey.KID] {
		t.Errorf("active key missing from ForJWKS output")
	}
	if !got[pendingKey.KID] {
		t.Errorf("pending key missing from ForJWKS output")
	}
	if got[retiredKey.KID] {
		t.Errorf("retired key should not appear in ForJWKS output")
	}
}

func TestSigningKey_Status(t *testing.T) {
	// Pure test of the Status() helper. No DB.
	now := time.Now()

	cases := []struct {
		name    string
		act     *time.Time
		ret     *time.Time
		want    tokens.KeyStatus
	}{
		{"pending", nil, nil, tokens.StatusPending},
		{"active", &now, nil, tokens.StatusActive},
		{"retired", &now, &now, tokens.StatusRetired},
	}
	for _, c := range cases {
		k := &tokens.SigningKey{ActivatedAt: c.act, RetiredAt: c.ret}
		if got := k.Status(); got != c.want {
			t.Errorf("%s: Status = %q, want %q", c.name, got, c.want)
		}
	}
}
