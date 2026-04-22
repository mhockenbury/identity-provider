package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Enqueue inserts a pending outbox row inside the caller's transaction.
// This is THE critical function of the outbox pattern: it MUST run in
// the same Postgres transaction as the identity-state change it's
// mirroring. If the tx commits, both the identity row and the outbox
// row become visible atomically. If it rolls back, neither persists —
// no ghost events pointing at state that never existed.
//
// Signature takes pgx.Tx rather than *pgxpool.Pool intentionally: you
// cannot enqueue outside a transaction. Trying would be a bug.
//
// Payload is marshaled to JSON using the event's Payload() method.
// event_type and payload are stored as TEXT and JSONB respectively
// per migrations/0001_init.sql.
func Enqueue(ctx context.Context, tx pgx.Tx, event Event) error {
	payload, err := json.Marshal(event.Payload())
	if err != nil {
		return fmt.Errorf("marshal event payload: %w", err)
	}

	const q = `
        INSERT INTO fga_outbox (event_type, payload)
        VALUES ($1, $2)`

	if _, err := tx.Exec(ctx, q, string(event.Type()), payload); err != nil {
		return fmt.Errorf("insert outbox row: %w", err)
	}
	return nil
}
