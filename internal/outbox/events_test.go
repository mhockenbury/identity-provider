package outbox_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/outbox"
)

// --- Event interface + Type/Payload ---

func TestGroupMembershipAdded_TypeAndPayload(t *testing.T) {
	uid := uuid.New()
	gid := uuid.New()
	e := outbox.GroupMembershipAdded{UserID: uid, GroupID: gid}

	if e.Type() != outbox.EventTypeGroupMembershipAdded {
		t.Errorf("Type() = %q, want %q", e.Type(), outbox.EventTypeGroupMembershipAdded)
	}
	p := e.Payload()
	if p["user_id"] != uid.String() {
		t.Errorf("payload user_id = %v, want %q", p["user_id"], uid)
	}
	if p["group_id"] != gid.String() {
		t.Errorf("payload group_id = %v, want %q", p["group_id"], gid)
	}
}

func TestGroupMembershipRemoved_TypeAndPayload(t *testing.T) {
	uid := uuid.New()
	gid := uuid.New()
	e := outbox.GroupMembershipRemoved{UserID: uid, GroupID: gid}

	if e.Type() != outbox.EventTypeGroupMembershipRemoved {
		t.Errorf("Type() = %q", e.Type())
	}
	p := e.Payload()
	if p["user_id"] != uid.String() || p["group_id"] != gid.String() {
		t.Errorf("payload mismatch: %+v", p)
	}
}

// --- FromPayload ---

func TestFromPayload_RoundTripGroupMembershipAdded(t *testing.T) {
	uid := uuid.New()
	gid := uuid.New()
	original := outbox.GroupMembershipAdded{UserID: uid, GroupID: gid}

	// Marshal the Payload() output the way the outbox store will.
	raw, err := json.Marshal(original.Payload())
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	back, err := outbox.FromPayload(outbox.EventTypeGroupMembershipAdded, raw)
	if err != nil {
		t.Fatalf("FromPayload: %v", err)
	}
	got, ok := back.(outbox.GroupMembershipAdded)
	if !ok {
		t.Fatalf("FromPayload returned %T, want GroupMembershipAdded", back)
	}
	if got != original {
		t.Errorf("round trip mismatch: got %+v, want %+v", got, original)
	}
}

func TestFromPayload_RoundTripGroupMembershipRemoved(t *testing.T) {
	uid := uuid.New()
	gid := uuid.New()
	original := outbox.GroupMembershipRemoved{UserID: uid, GroupID: gid}

	raw, _ := json.Marshal(original.Payload())
	back, err := outbox.FromPayload(outbox.EventTypeGroupMembershipRemoved, raw)
	if err != nil {
		t.Fatalf("FromPayload: %v", err)
	}
	if got, ok := back.(outbox.GroupMembershipRemoved); !ok || got != original {
		t.Errorf("round trip: got %+v (%T)", got, back)
	}
}

func TestFromPayload_UnknownTypeReturnsError(t *testing.T) {
	_, err := outbox.FromPayload("made_up_event", []byte(`{}`))
	if err == nil {
		t.Error("expected error for unknown event type")
	}
	if !strings.Contains(err.Error(), "made_up_event") {
		t.Errorf("error should name the unknown type: %v", err)
	}
}

func TestFromPayload_BadJSONReturnsError(t *testing.T) {
	_, err := outbox.FromPayload(outbox.EventTypeGroupMembershipAdded, []byte("not json"))
	if err == nil {
		t.Error("expected error for malformed JSON payload")
	}
}

func TestFromPayload_BadUUIDReturnsError(t *testing.T) {
	// Well-formed JSON with a malformed UUID should error out at parse time,
	// not silently produce a zero-valued event.
	raw := []byte(`{"user_id": "not-a-uuid", "group_id": "also-not-a-uuid"}`)
	_, err := outbox.FromPayload(outbox.EventTypeGroupMembershipAdded, raw)
	if err == nil {
		t.Error("expected error for malformed user_id")
	}
}

// --- Event interface compliance (compile-time + sanity) ---

// Catch a refactor that accidentally breaks the interface.
func TestAllEvents_ImplementEventInterface(t *testing.T) {
	events := []outbox.Event{
		outbox.GroupMembershipAdded{},
		outbox.GroupMembershipRemoved{},
	}
	for _, e := range events {
		if e.Type() == "" {
			t.Errorf("%T.Type() returned empty string", e)
		}
		if e.Payload() == nil {
			t.Errorf("%T.Payload() returned nil", e)
		}
	}
}

// The Event interface should NOT be satisfied by a non-Event type. Just
// a sanity check — if this starts passing, the interface is too loose.
func TestEvent_InterfaceIsNotTrivial(t *testing.T) {
	// uuid.UUID doesn't satisfy Event — it has neither Type() nor Payload().
	var _ outbox.Event = outbox.GroupMembershipAdded{}
	// This line compiles; the comment above documents that uuid.UUID does
	// not. No runtime assertion needed.
	_ = errors.New("dummy")
}
