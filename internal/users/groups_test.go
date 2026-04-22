package users_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/users"
)

// uniqueGroupName guarantees per-test isolation on the shared DB.
func uniqueGroupName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func cleanGroup(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, id)
	})
}

// --- Create / GetByID / GetByName / List ---

func TestGroup_CreateAndLookup(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewGroupStore(pool)

	name := uniqueGroupName("editors")
	g, err := store.Create(context.Background(), name)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanGroup(t, pool, g.ID)

	if g.Name != name {
		t.Errorf("Name = %q, want %q", g.Name, name)
	}
	if g.ID == uuid.Nil {
		t.Error("ID is nil")
	}
	if g.CreatedAt.IsZero() {
		t.Error("CreatedAt not populated")
	}

	// Read back by ID.
	got, err := store.GetByID(context.Background(), g.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != g.ID {
		t.Errorf("GetByID round-trip mismatch")
	}

	// Read back by name.
	byName, err := store.GetByName(context.Background(), name)
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if byName.ID != g.ID {
		t.Errorf("GetByName round-trip mismatch")
	}
}

func TestGroup_CreateDuplicateNameRejected(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewGroupStore(pool)

	name := uniqueGroupName("dupes")
	g, _ := store.Create(context.Background(), name)
	cleanGroup(t, pool, g.ID)

	_, err := store.Create(context.Background(), name)
	if !errors.Is(err, users.ErrGroupNameTaken) {
		t.Errorf("err = %v, want ErrGroupNameTaken", err)
	}
}

func TestGroup_CreateEmptyNameRejected(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewGroupStore(pool)

	_, err := store.Create(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty group name")
	}
}

func TestGroup_GetByID_NotFound(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewGroupStore(pool)

	_, err := store.GetByID(context.Background(), uuid.New())
	if !errors.Is(err, users.ErrGroupNotFound) {
		t.Errorf("err = %v, want ErrGroupNotFound", err)
	}
}

func TestGroup_GetByName_NotFound(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	store := users.NewGroupStore(pool)

	_, err := store.GetByName(context.Background(), uniqueGroupName("nonexistent"))
	if !errors.Is(err, users.ErrGroupNotFound) {
		t.Errorf("err = %v, want ErrGroupNotFound", err)
	}
}

// --- Membership operations ---

// seedUserForGroup creates a user for membership tests and registers
// cleanup.
func seedUserForGroup(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	s := testStore(pool)
	email := uniqueEmail("gm")
	u, err := s.Create(context.Background(), email, "password-ok")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID)
	})
	return u.ID
}

func TestGroup_AddAndRemoveMember(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	groups := users.NewGroupStore(pool)

	userID := seedUserForGroup(t, pool)
	g, _ := groups.Create(context.Background(), uniqueGroupName("add-rem"))
	cleanGroup(t, pool, g.ID)

	// Add member in a tx.
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := groups.AddMemberTx(context.Background(), tx, userID, g.ID); err != nil {
		t.Fatalf("AddMemberTx: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	members, err := groups.ListMembers(context.Background(), g.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].ID != userID {
		t.Errorf("members = %+v, want [%s]", members, userID)
	}

	// Remove in another tx.
	tx, _ = pool.Begin(context.Background())
	if err := groups.RemoveMemberTx(context.Background(), tx, userID, g.ID); err != nil {
		t.Fatalf("RemoveMemberTx: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	members, _ = groups.ListMembers(context.Background(), g.ID)
	if len(members) != 0 {
		t.Errorf("after remove, members = %+v, want empty", members)
	}
}

func TestGroup_AddMemberDuplicateRejected(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	groups := users.NewGroupStore(pool)

	userID := seedUserForGroup(t, pool)
	g, _ := groups.Create(context.Background(), uniqueGroupName("dup-member"))
	cleanGroup(t, pool, g.ID)

	tx, _ := pool.Begin(context.Background())
	if err := groups.AddMemberTx(context.Background(), tx, userID, g.ID); err != nil {
		t.Fatalf("first AddMemberTx: %v", err)
	}
	// Second add in the SAME tx should also fail (uniqueness constraint).
	err := groups.AddMemberTx(context.Background(), tx, userID, g.ID)
	if !errors.Is(err, users.ErrMembershipExists) {
		t.Errorf("err = %v, want ErrMembershipExists", err)
	}
	_ = tx.Rollback(context.Background())
}

func TestGroup_RemoveNonexistentMember(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	groups := users.NewGroupStore(pool)

	g, _ := groups.Create(context.Background(), uniqueGroupName("empty"))
	cleanGroup(t, pool, g.ID)

	tx, _ := pool.Begin(context.Background())
	defer tx.Rollback(context.Background())
	err := groups.RemoveMemberTx(context.Background(), tx, uuid.New(), g.ID)
	if !errors.Is(err, users.ErrMembershipNotFound) {
		t.Errorf("err = %v, want ErrMembershipNotFound", err)
	}
}

func TestGroup_AddMemberUnknownGroup(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	groups := users.NewGroupStore(pool)

	userID := seedUserForGroup(t, pool)

	tx, _ := pool.Begin(context.Background())
	defer tx.Rollback(context.Background())
	err := groups.AddMemberTx(context.Background(), tx, userID, uuid.New())
	if !errors.Is(err, users.ErrGroupNotFound) {
		t.Errorf("err = %v, want ErrGroupNotFound (FK violation)", err)
	}
}

func TestGroup_List(t *testing.T) {
	pool := testPool(t)
	t.Cleanup(func() { pool.Close() })
	groups := users.NewGroupStore(pool)

	// Seed two groups. We don't assert exact count because other tests
	// may have leftover rows; we just assert our two are in the result.
	a, _ := groups.Create(context.Background(), uniqueGroupName("list-a"))
	cleanGroup(t, pool, a.ID)
	b, _ := groups.Create(context.Background(), uniqueGroupName("list-b"))
	cleanGroup(t, pool, b.ID)

	all, err := groups.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	seen := map[uuid.UUID]bool{}
	for _, g := range all {
		seen[g.ID] = true
	}
	if !seen[a.ID] || !seen[b.ID] {
		t.Errorf("List missing seeded groups; seen: %v", seen)
	}
}
