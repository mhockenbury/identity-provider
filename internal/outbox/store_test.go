package outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/outbox"
)

// Integration tests exercise the atomic-transaction property: either
// both identity + outbox rows land, or neither does. Skipped if
// postgres-idp isn't reachable.

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

func TestEnqueue_InsertsRowWithCorrectShape(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	uid := uuid.New()
	gid := uuid.New()
	event := outbox.GroupMembershipAdded{UserID: uid, GroupID: gid}

	// Run inside a tx and commit.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback(ctx) // no-op after Commit

	if err := outbox.Enqueue(ctx, tx, event); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Read the row back. Use the most recent matching event.
	var id int64
	var eventType string
	var payload []byte
	var processedAt *time.Time
	err = pool.QueryRow(ctx,
		`SELECT id, event_type, payload, processed_at
         FROM fga_outbox
         WHERE event_type = $1 AND payload->>'user_id' = $2
         ORDER BY id DESC LIMIT 1`,
		string(outbox.EventTypeGroupMembershipAdded), uid.String()).Scan(
		&id, &eventType, &payload, &processedAt)
	if err != nil {
		t.Fatalf("read back outbox row: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM fga_outbox WHERE id=$1`, id) })

	if processedAt != nil {
		t.Errorf("processed_at should be NULL on a fresh row; got %v", *processedAt)
	}

	// Payload round-trip: FromPayload should produce the identical event.
	back, err := outbox.FromPayload(outbox.EventType(eventType), payload)
	if err != nil {
		t.Fatalf("FromPayload: %v", err)
	}
	if got, ok := back.(outbox.GroupMembershipAdded); !ok || got != event {
		t.Errorf("round-tripped event = %+v (%T), want %+v", got, back, event)
	}

	// Also parse the raw JSON manually to check the column is valid JSONB.
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Errorf("payload is not valid JSON: %v", err)
	}
}

// The critical property: Enqueue runs inside a transaction, and if the
// transaction rolls back, the outbox row is NOT visible. This is what
// makes the outbox pattern safe — no ghost events referencing identity
// state that never committed.
func TestEnqueue_RollbackLeavesNoRow(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// Use a unique UUID so we can reliably query for this specific event.
	uid := uuid.New()
	gid := uuid.New()
	event := outbox.GroupMembershipAdded{UserID: uid, GroupID: gid}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}

	if err := outbox.Enqueue(ctx, tx, event); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	// Rollback — simulating a later handler step failing.
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	// Row must not be visible.
	var count int
	err = pool.QueryRow(ctx,
		`SELECT count(*) FROM fga_outbox WHERE payload->>'user_id' = $1`,
		uid.String()).Scan(&count)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows for rolled-back event, got %d", count)
	}
}

// Symmetric test with GroupMembershipRemoved — different event type
// but identical atomicity contract.
func TestEnqueue_GroupMembershipRemovedCommitsAndReadsBack(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	uid := uuid.New()
	gid := uuid.New()
	event := outbox.GroupMembershipRemoved{UserID: uid, GroupID: gid}

	tx, _ := pool.Begin(ctx)
	defer tx.Rollback(ctx)

	if err := outbox.Enqueue(ctx, tx, event); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var id int64
	err := pool.QueryRow(ctx,
		`SELECT id FROM fga_outbox
         WHERE event_type = $1 AND payload->>'user_id' = $2
         ORDER BY id DESC LIMIT 1`,
		string(outbox.EventTypeGroupMembershipRemoved), uid.String()).Scan(&id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM fga_outbox WHERE id=$1`, id) })
}

// Enqueue accepts context cancellation. If the caller's ctx is already
// cancelled the INSERT should fail rather than block. This matters
// because handlers pass r.Context() through and a client disconnect
// should abort the operation cleanly.
func TestEnqueue_RespectsContextCancellation(t *testing.T) {
	pool := testPool(t)
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback(context.Background())

	cancelled, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err = outbox.Enqueue(cancelled, tx, outbox.GroupMembershipAdded{
		UserID: uuid.New(), GroupID: uuid.New(),
	})
	if err == nil {
		t.Error("expected error on cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Logf("err is not ctx.Canceled but that's ok — pgx wraps it. err=%v", err)
	}
}

// Also covers the "pg_outbox table must exist" sanity case: an Enqueue
// against a fresh pool should work (the migration was applied). If the
// schema is missing this test fails loudly, which is what we want.
func TestEnqueue_FreshConnectionWorks(t *testing.T) {
	pool := testPool(t)

	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback(context.Background())

	event := outbox.GroupMembershipAdded{UserID: uuid.New(), GroupID: uuid.New()}
	if err := outbox.Enqueue(context.Background(), tx, event); err != nil {
		t.Fatalf("Enqueue on fresh pool: %v", err)
	}
	// Rollback is fine; we only care that the statement executed without
	// a schema error.
}

// Compile-time check that pgx.Tx is what Enqueue takes. Guards against
// a refactor that accidentally broadens the parameter to "anything with
// Exec" — which would let callers Enqueue with a raw *pgxpool.Pool and
// break the atomic property.
var _ func(context.Context, pgx.Tx, outbox.Event) error = outbox.Enqueue
