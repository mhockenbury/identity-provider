package users

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Group-related sentinel errors. Mirrors the User sentinels pattern.
var (
	ErrGroupNotFound      = errors.New("group not found")
	ErrGroupNameTaken     = errors.New("group name already in use")
	ErrMembershipExists   = errors.New("user is already a member of this group")
	ErrMembershipNotFound = errors.New("user is not a member of this group")
)

// Group is the in-memory row shape.
type Group struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
}

// GroupStore wraps the `groups` and `group_memberships` tables. Methods
// accept an optional pgx.Tx param for the AddMember / RemoveMember calls
// because those need to be transactional with outbox.Enqueue — same
// transaction, atomic commit.
//
// Create doesn't emit an outbox event (groups themselves aren't FGA
// subjects; only their membership matters), so it's a plain pool op.
type GroupStore struct {
	pool *pgxpool.Pool
}

func NewGroupStore(pool *pgxpool.Pool) *GroupStore {
	return &GroupStore{pool: pool}
}

// Create inserts a new group with the given name. No outbox event —
// group existence alone doesn't imply an FGA tuple; tuples are only
// written when users are added as members.
func (s *GroupStore) Create(ctx context.Context, name string) (Group, error) {
	if name == "" {
		return Group{}, fmt.Errorf("group name is empty")
	}
	const q = `
        INSERT INTO groups (name)
        VALUES ($1)
        RETURNING id, name, created_at`

	var g Group
	err := s.pool.QueryRow(ctx, q, name).Scan(&g.ID, &g.Name, &g.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return Group{}, ErrGroupNameTaken
		}
		return Group{}, fmt.Errorf("insert group: %w", err)
	}
	return g, nil
}

// GetByID returns a group by its UUID.
func (s *GroupStore) GetByID(ctx context.Context, id uuid.UUID) (Group, error) {
	const q = `SELECT id, name, created_at FROM groups WHERE id = $1`
	var g Group
	err := s.pool.QueryRow(ctx, q, id).Scan(&g.ID, &g.Name, &g.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Group{}, ErrGroupNotFound
		}
		return Group{}, fmt.Errorf("get group: %w", err)
	}
	return g, nil
}

// GetByName returns a group by its unique name. Convenience for CLI:
// operator says `idp groups add-member editors alice@example.com` and
// we look up both by human-readable key.
func (s *GroupStore) GetByName(ctx context.Context, name string) (Group, error) {
	const q = `SELECT id, name, created_at FROM groups WHERE name = $1`
	var g Group
	err := s.pool.QueryRow(ctx, q, name).Scan(&g.ID, &g.Name, &g.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Group{}, ErrGroupNotFound
		}
		return Group{}, fmt.Errorf("get group by name: %w", err)
	}
	return g, nil
}

// List returns all groups ordered by creation time. Used by the CLI.
func (s *GroupStore) List(ctx context.Context) ([]Group, error) {
	const q = `SELECT id, name, created_at FROM groups ORDER BY created_at`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// AddMemberTx adds a user to a group INSIDE the caller's transaction.
// The caller is expected to call outbox.Enqueue in the same tx so
// the membership row and the outbox event commit atomically.
//
// Signature takes pgx.Tx for the same reason outbox.Enqueue does:
// prevents an accidental call with a pool that would break atomicity.
func (s *GroupStore) AddMemberTx(ctx context.Context, tx pgx.Tx, userID, groupID uuid.UUID) error {
	const q = `
        INSERT INTO group_memberships (user_id, group_id)
        VALUES ($1, $2)`

	_, err := tx.Exec(ctx, q, userID, groupID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case pgUniqueViolation:
				// PK is (user_id, group_id), so this means the user is
				// already a member. Not an outright error from the user's
				// perspective — idempotency is nice — but surfacing the
				// sentinel lets the caller decide whether to skip the
				// outbox enqueue too.
				return ErrMembershipExists
			case pgForeignKeyViolation:
				// Either the user or the group doesn't exist. We can't
				// tell which from the constraint name without more work;
				// ErrGroupNotFound is the more likely case for a CLI
				// user who just typed a bad group name, so surface that.
				return ErrGroupNotFound
			}
		}
		return fmt.Errorf("insert membership: %w", err)
	}
	return nil
}

// RemoveMemberTx removes a user from a group INSIDE the caller's
// transaction, same contract as AddMemberTx.
func (s *GroupStore) RemoveMemberTx(ctx context.Context, tx pgx.Tx, userID, groupID uuid.UUID) error {
	const q = `
        DELETE FROM group_memberships
        WHERE user_id = $1 AND group_id = $2`

	tag, err := tx.Exec(ctx, q, userID, groupID)
	if err != nil {
		return fmt.Errorf("delete membership: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMembershipNotFound
	}
	return nil
}

// ListMembers returns all users currently in the given group.
// Emitted by the CLI for debugging; used by tests.
func (s *GroupStore) ListMembers(ctx context.Context, groupID uuid.UUID) ([]User, error) {
	const q = `
        SELECT u.id, u.email, u.password_hash, u.created_at
        FROM users u
        JOIN group_memberships m ON m.user_id = u.id
        WHERE m.group_id = $1
        ORDER BY u.email`

	rows, err := s.pool.Query(ctx, q, groupID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// pgForeignKeyViolation is the SQLSTATE for 23503 (FK constraint).
const pgForeignKeyViolation = "23503"
