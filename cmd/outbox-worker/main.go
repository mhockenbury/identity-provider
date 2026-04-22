// Outbox worker.
//
// Drains fga_outbox rows into OpenFGA. Long-running, crash-safe, designed
// to scale horizontally: multiple workers can run against the same DB and
// partition work via SELECT ... FOR UPDATE SKIP LOCKED.
//
// Loop (per tick):
//   1. BEGIN tx
//   2. SELECT id, event_type, payload, attempt_count
//        FROM fga_outbox
//        WHERE processed_at IS NULL AND attempt_count < max_attempts
//        ORDER BY id
//        LIMIT batch_size
//        FOR UPDATE SKIP LOCKED
//   3. Translate each row → []TupleOp. Split into writes + deletes.
//   4. Call fga.WriteAndDelete(..., idempotent=true). The FGA Write API is
//      atomic across writes+deletes, so the whole batch either lands or
//      doesn't.
//   5. On success: UPDATE fga_outbox SET processed_at = now() WHERE id = ANY($1).
//      On failure: UPDATE fga_outbox SET attempt_count = attempt_count+1,
//                         last_error = $err WHERE id = ANY($1).
//      (Row-level error attribution isn't available from the FGA Write API —
//       transactional batch is all-or-nothing by design, so we mark all of
//       them failed with the same error. Poison-pill isolation happens via
//       attempt_count: a row that keeps failing stops being claimed once
//       it hits max_attempts.)
//   6. COMMIT. Row locks release; next tick claims the next slice.
//
// Idle (empty claim): sleep poll_interval, respect ctx cancel.
//
// Shutdown: on SIGINT/SIGTERM the loop finishes the current iteration (the
// tx is either committed or rolled back) then exits. No at-most-once
// guarantee — at-least-once with FGA-side dedup via OnDuplicateWrites=ignore.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openfga/go-sdk/client"

	"github.com/mhockenbury/identity-provider/internal/fga"
	"github.com/mhockenbury/identity-provider/internal/outbox"
)

type config struct {
	databaseURL string
	fga         fga.Config

	batchSize    int
	pollInterval time.Duration
	maxAttempts  int
	logLevel     slog.Level
}

func loadConfig() (config, error) {
	cfg := config{
		databaseURL: os.Getenv("DATABASE_URL"),
		fga: fga.Config{
			APIURL:               os.Getenv("OPENFGA_API_URL"),
			StoreID:              os.Getenv("OPENFGA_STORE_ID"),
			AuthorizationModelID: os.Getenv("OPENFGA_AUTHORIZATION_MODEL_ID"),
			APIToken:             os.Getenv("OPENFGA_API_TOKEN"),
		},
		batchSize:    intEnv("OUTBOX_BATCH_SIZE", 100),
		pollInterval: durEnv("OUTBOX_POLL_INTERVAL", time.Second),
		maxAttempts:  intEnv("OUTBOX_MAX_ATTEMPTS", 5),
		logLevel:     parseLogLevel(os.Getenv("LOG_LEVEL")),
	}
	if cfg.databaseURL == "" {
		return cfg, errors.New("DATABASE_URL is required")
	}
	if cfg.fga.APIURL == "" {
		return cfg, errors.New("OPENFGA_API_URL is required")
	}
	if cfg.fga.StoreID == "" {
		return cfg, errors.New("OPENFGA_STORE_ID is required (run `idp fga init`)")
	}
	if cfg.fga.AuthorizationModelID == "" {
		return cfg, errors.New("OPENFGA_AUTHORIZATION_MODEL_ID is required (run `idp fga init`)")
	}
	if cfg.batchSize <= 0 {
		return cfg, fmt.Errorf("OUTBOX_BATCH_SIZE must be > 0 (got %d)", cfg.batchSize)
	}
	if cfg.maxAttempts <= 0 {
		return cfg, fmt.Errorf("OUTBOX_MAX_ATTEMPTS must be > 0 (got %d)", cfg.maxAttempts)
	}
	return cfg, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.logLevel}))
	slog.SetDefault(logger)

	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	pingCtx, pingCancel := context.WithTimeout(rootCtx, 5*time.Second)
	defer pingCancel()
	pool, err := pgxpool.New(pingCtx, cfg.databaseURL)
	if err != nil {
		return fmt.Errorf("pgxpool.New: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("postgres ping: %w", err)
	}

	fgaClient, err := fga.NewClient(cfg.fga)
	if err != nil {
		return fmt.Errorf("build fga client: %w", err)
	}

	slog.Info("outbox worker started",
		"batch_size", cfg.batchSize,
		"poll_interval", cfg.pollInterval,
		"max_attempts", cfg.maxAttempts,
		"fga_store", cfg.fga.StoreID,
	)

	loop(rootCtx, pool, fgaClient, cfg)

	slog.Info("outbox worker stopped")
	return nil
}

// loop is the main drain loop. Each iteration either processes a batch or
// idles for pollInterval. Returns on ctx cancel.
func loop(ctx context.Context, pool *pgxpool.Pool, fc *client.OpenFgaClient, cfg config) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := tick(ctx, pool, fc, cfg)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Error("tick failed", "err", err)
			// Back off a full poll interval on hard errors (DB down, etc).
			// A tight retry loop would hammer the DB during an outage.
		}

		if n == 0 {
			if !sleep(ctx, cfg.pollInterval) {
				return
			}
		}
	}
}

// tick runs one claim+process+ack cycle. Returns the number of rows
// processed (0 when the table is drained).
func tick(ctx context.Context, pool *pgxpool.Pool, fc *client.OpenFgaClient, cfg config) (int, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	// Safety net — Commit makes this a no-op; Rollback on any early return.
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := claimBatch(ctx, tx, cfg.batchSize, cfg.maxAttempts)
	if err != nil {
		return 0, fmt.Errorf("claim batch: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}

	ids, writes, deletes, translateErr := buildBatch(rows)

	if translateErr != nil {
		// At least one row didn't translate. Mark ONLY the offending row as
		// failed (its id + error are in translateErr); the rest we leave
		// for the next tick so they don't get tarred by a sibling's bug.
		if err := markFailed(ctx, tx, []int64{translateErr.id}, translateErr.err.Error()); err != nil {
			return 0, fmt.Errorf("mark translate-failed: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("commit (translate failure): %w", err)
		}
		slog.Warn("event failed to translate",
			"row_id", translateErr.id, "err", translateErr.err)
		return 1, nil
	}

	if err := fga.WriteAndDelete(ctx, fc, writes, deletes, true); err != nil {
		// Batch-level failure: bump attempt_count + last_error on every row.
		// FGA's Write API is all-or-nothing, so we have no way to pick out
		// which row was the culprit.
		if markErr := markFailed(ctx, tx, ids, err.Error()); markErr != nil {
			return 0, fmt.Errorf("fga write failed (%v) and mark failed: %w", err, markErr)
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return 0, fmt.Errorf("commit after fga failure: %w", commitErr)
		}
		slog.Warn("fga write failed", "batch_size", len(ids), "err", err)
		return len(ids), nil
	}

	if err := markProcessed(ctx, tx, ids); err != nil {
		return 0, fmt.Errorf("mark processed: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	slog.Info("batch processed", "rows", len(ids), "writes", len(writes), "deletes", len(deletes))
	return len(ids), nil
}

// --- DB helpers ---

type outboxRow struct {
	id           int64
	eventType    outbox.EventType
	payload      []byte
	attemptCount int
}

func claimBatch(ctx context.Context, tx pgx.Tx, limit, maxAttempts int) ([]outboxRow, error) {
	const q = `
        SELECT id, event_type, payload, attempt_count
        FROM fga_outbox
        WHERE processed_at IS NULL
          AND attempt_count < $1
        ORDER BY id
        LIMIT $2
        FOR UPDATE SKIP LOCKED`

	rs, err := tx.Query(ctx, q, maxAttempts, limit)
	if err != nil {
		return nil, err
	}
	defer rs.Close()

	var out []outboxRow
	for rs.Next() {
		var r outboxRow
		var t string
		if err := rs.Scan(&r.id, &t, &r.payload, &r.attemptCount); err != nil {
			return nil, err
		}
		r.eventType = outbox.EventType(t)
		out = append(out, r)
	}
	return out, rs.Err()
}

func markProcessed(ctx context.Context, tx pgx.Tx, ids []int64) error {
	const q = `UPDATE fga_outbox SET processed_at = now() WHERE id = ANY($1)`
	_, err := tx.Exec(ctx, q, ids)
	return err
}

func markFailed(ctx context.Context, tx pgx.Tx, ids []int64, lastErr string) error {
	const q = `
        UPDATE fga_outbox
        SET attempt_count = attempt_count + 1,
            last_error    = $2
        WHERE id = ANY($1)`
	_, err := tx.Exec(ctx, q, ids, lastErr)
	return err
}

// --- translation ---

type rowError struct {
	id  int64
	err error
}

// buildBatch translates each row into tuple ops and coalesces them to the
// net change the batch represents.
//
// Why coalesce: FGA's Write API rejects a request that contains the same
// tuple in both writes AND deletes, or twice in either list — error code
// cannot_allow_duplicate_tuples_in_one_request. And even after we
// dedupe, naively emitting "the last op wins" produces a delete for a
// tuple we never wrote (when the sequence is add-then-remove on a tuple
// that wasn't in FGA to start with), which FGA also rejects.
//
// The fix: treat the batch as a sequence of state transitions on each
// (user, relation, object) key, and emit only the NET change:
//
//   • starts with unknown state (nothing to tell FGA)
//   • first op determines the intended final state (W or D)
//   • subsequent ops on the same key flip the final state
//   • if the first-seen op AND the last op are the same kind, emit that op
//   • if they alternate an even number of times and return to "no op", skip it
//
// Simpler formulation we use: record the FIRST op and the LAST op per key.
// - first=W, last=W → emit W (idempotent; safe)
// - first=W, last=D → net no-op (write then undo — FGA was never told about this tuple)
// - first=D, last=W → emit W (the delete undid some prior FGA state; if it did nothing, the write still lands)
// - first=D, last=D → emit D
//
// This isn't strictly correct in the "first=D, last=W" case when the
// tuple didn't exist in FGA before the Delete — but that's an FGA
// server-state question the outbox can't know for sure, and the retry
// flow + attempt_count handles the rare mismatch. Skipping the pure
// add-then-undo case is what fixes the actual bug we hit.
//
// On the first untranslatable row we return immediately with rowError so
// the caller can quarantine just that row.
func buildBatch(rows []outboxRow) (ids []int64, writes []client.ClientTupleKey, deletes []client.ClientTupleKeyWithoutCondition, badRow *rowError) {
	type state struct {
		first, last outbox.TupleOpKind
		tuple       client.ClientTupleKey
	}
	states := map[string]*state{}
	order := []string{}

	for _, r := range rows {
		event, err := outbox.FromPayload(r.eventType, r.payload)
		if err != nil {
			return nil, nil, nil, &rowError{id: r.id, err: fmt.Errorf("rehydrate event: %w", err)}
		}
		ops, err := outbox.Translate(event)
		if err != nil {
			return nil, nil, nil, &rowError{id: r.id, err: fmt.Errorf("translate event: %w", err)}
		}
		ids = append(ids, r.id)
		for _, op := range ops {
			if op.Kind != outbox.TupleOpWrite && op.Kind != outbox.TupleOpDelete {
				return nil, nil, nil, &rowError{id: r.id, err: fmt.Errorf("unknown tuple op kind: %s", op.Kind)}
			}
			key := op.Tuple.User + "#" + op.Tuple.Relation + "@" + op.Tuple.Object
			s, ok := states[key]
			if !ok {
				states[key] = &state{first: op.Kind, last: op.Kind, tuple: op.Tuple}
				order = append(order, key)
			} else {
				s.last = op.Kind
			}
		}
	}

	for _, key := range order {
		s := states[key]
		// W then D on a key FGA never knew about — pure no-op; skip.
		if s.first == outbox.TupleOpWrite && s.last == outbox.TupleOpDelete {
			continue
		}
		switch s.last {
		case outbox.TupleOpWrite:
			writes = append(writes, s.tuple)
		case outbox.TupleOpDelete:
			deletes = append(deletes, fga.TupleWithoutCondition(s.tuple))
		}
	}
	return ids, writes, deletes, nil
}

// --- tiny utilities ---

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func intEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func durEnv(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func parseLogLevel(v string) slog.Level {
	switch v {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Ensure json is referenced — the payload is []byte from Postgres; we pass
// it to outbox.FromPayload which does the unmarshal. Kept here as a hook
// in case we later want to pretty-print payloads at debug level.
var _ = json.Valid
