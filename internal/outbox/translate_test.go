package outbox_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/outbox"
)

// fakeEvent is an Event with no matching Translate case. Used to prove
// Translate errors (rather than silently no-ops) on unknown event types.
type fakeEvent struct{}

func (fakeEvent) Type() outbox.EventType      { return "fake_event" }
func (fakeEvent) Payload() map[string]any     { return nil }

// --- GroupMembershipAdded translation ---

func TestTranslate_GroupMembershipAdded(t *testing.T) {
	uid := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	gid := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	ops, err := outbox.Translate(outbox.GroupMembershipAdded{UserID: uid, GroupID: gid})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}

	if len(ops) != 1 {
		t.Fatalf("got %d ops, want 1", len(ops))
	}
	op := ops[0]

	if op.Kind != outbox.TupleOpWrite {
		t.Errorf("kind = %s, want write", op.Kind)
	}
	wantUser := fmt.Sprintf("user:%s", uid)
	if op.Tuple.User != wantUser {
		t.Errorf("tuple.User = %q, want %q", op.Tuple.User, wantUser)
	}
	if op.Tuple.Relation != "member" {
		t.Errorf("tuple.Relation = %q, want %q", op.Tuple.Relation, "member")
	}
	wantObject := fmt.Sprintf("group:%s", gid)
	if op.Tuple.Object != wantObject {
		t.Errorf("tuple.Object = %q, want %q", op.Tuple.Object, wantObject)
	}
}

// --- GroupMembershipRemoved translation ---

func TestTranslate_GroupMembershipRemoved(t *testing.T) {
	uid := uuid.New()
	gid := uuid.New()

	ops, err := outbox.Translate(outbox.GroupMembershipRemoved{UserID: uid, GroupID: gid})
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("got %d ops, want 1", len(ops))
	}
	op := ops[0]
	if op.Kind != outbox.TupleOpDelete {
		t.Errorf("kind = %s, want delete", op.Kind)
	}
	if op.Tuple.Relation != "member" {
		t.Errorf("tuple.Relation = %q", op.Tuple.Relation)
	}
	if !strings.HasPrefix(op.Tuple.User, "user:") {
		t.Errorf("tuple.User must have user: prefix, got %q", op.Tuple.User)
	}
	if !strings.HasPrefix(op.Tuple.Object, "group:") {
		t.Errorf("tuple.Object must have group: prefix, got %q", op.Tuple.Object)
	}
}

// --- Symmetry ---

// Add and Remove for the same (user, group) pair should produce
// identical tuples — only the op kind differs. If translation ever
// drifted and added a subtle difference, downstream delete wouldn't
// match the earlier write.
func TestTranslate_AddAndRemoveProduceIdenticalTuples(t *testing.T) {
	uid := uuid.New()
	gid := uuid.New()

	addOps, _ := outbox.Translate(outbox.GroupMembershipAdded{UserID: uid, GroupID: gid})
	remOps, _ := outbox.Translate(outbox.GroupMembershipRemoved{UserID: uid, GroupID: gid})

	if addOps[0].Tuple != remOps[0].Tuple {
		t.Errorf("add and remove tuples differ:\n  add: %+v\n  rem: %+v",
			addOps[0].Tuple, remOps[0].Tuple)
	}
	if addOps[0].Kind == remOps[0].Kind {
		t.Error("add and remove produced the same op kind — should differ")
	}
}

// --- Unknown event ---

func TestTranslate_UnknownEventReturnsError(t *testing.T) {
	_, err := outbox.Translate(fakeEvent{})
	if err == nil {
		t.Error("expected error for unknown event type")
	}
	if !strings.Contains(err.Error(), "fake_event") {
		t.Errorf("error should name the offending type: %v", err)
	}
}

// --- Format stability ---

// Subject format is load-bearing — a change here breaks every existing
// FGA tuple. Pin the exact format so the test breaks visibly if someone
// "improves" it.
func TestTranslate_TupleFormatPinned(t *testing.T) {
	uid := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	gid := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	ops, _ := outbox.Translate(outbox.GroupMembershipAdded{UserID: uid, GroupID: gid})

	want := "user:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	if ops[0].Tuple.User != want {
		t.Errorf("User format changed — breaking change for stored tuples.\n  got:  %q\n  want: %q",
			ops[0].Tuple.User, want)
	}
	want = "group:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	if ops[0].Tuple.Object != want {
		t.Errorf("Object format changed — breaking change for stored tuples.\n  got:  %q\n  want: %q",
			ops[0].Tuple.Object, want)
	}
}
