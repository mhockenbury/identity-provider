// Package outbox implements the transactional outbox pattern for
// syncing identity-side state (users, group memberships) into OpenFGA
// as authorization tuples.
//
// Design:
//   - Handlers that mutate identity state call Enqueue(ctx, tx, event)
//     inside their Postgres transaction. Both the identity row and the
//     outbox row commit atomically.
//   - A separate worker (cmd/outbox-worker) drains pending outbox rows,
//     translates events to FGA tuple operations, calls OpenFGA, and
//     marks rows processed.
//
// This file defines the event types. Translation to FGA tuples lives
// in translate.go; storage in store.go.
package outbox

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// EventType is the enum of identity-state transitions that need to
// reflect in FGA. Kept small deliberately; extend only when a new
// identity event has a well-defined tuple translation.
type EventType string

const (
	// EventTypeGroupMembershipAdded fires when a user is added to a group.
	// Translation: write tuple (user:<user_id>, member, group:<group_id>).
	EventTypeGroupMembershipAdded EventType = "group_membership_added"

	// EventTypeGroupMembershipRemoved fires when a user is removed from
	// a group. Translation: delete tuple (user:<id>, member, group:<id>).
	EventTypeGroupMembershipRemoved EventType = "group_membership_removed"
)

// Event is the interface every event type implements. Kept tiny on
// purpose — all the behavior lives on the translation function and
// the registry, not on the event values themselves.
type Event interface {
	// Type returns the EventType value used as the event_type column
	// in fga_outbox.
	Type() EventType

	// Payload returns the event-specific fields as a map ready for JSON
	// encoding. The outbox store marshals this into the payload column.
	// Deserialization happens via the registry (see FromPayload below).
	Payload() map[string]any
}

// --- GroupMembershipAdded ---

// GroupMembershipAdded is the event emitted when a user is added to a
// group. The outbox worker translates this into an FGA write tuple.
type GroupMembershipAdded struct {
	UserID  uuid.UUID
	GroupID uuid.UUID
}

func (GroupMembershipAdded) Type() EventType { return EventTypeGroupMembershipAdded }

func (e GroupMembershipAdded) Payload() map[string]any {
	return map[string]any{
		"user_id":  e.UserID.String(),
		"group_id": e.GroupID.String(),
	}
}

// --- GroupMembershipRemoved ---

// GroupMembershipRemoved is emitted when a user is removed from a group.
// The outbox worker translates this into an FGA delete tuple.
type GroupMembershipRemoved struct {
	UserID  uuid.UUID
	GroupID uuid.UUID
}

func (GroupMembershipRemoved) Type() EventType { return EventTypeGroupMembershipRemoved }

func (e GroupMembershipRemoved) Payload() map[string]any {
	return map[string]any{
		"user_id":  e.UserID.String(),
		"group_id": e.GroupID.String(),
	}
}

// --- Registry / deserialization ---
//
// The worker reads (event_type, payload_bytes) pairs from the outbox
// table. It needs to rehydrate them into typed Event values for the
// translation function. This lookup table maps event_type → decoder.
//
// When you add a new Event, add it here too. Kept as a small map rather
// than reflection-based auto-registration for clarity: adding a type
// without a translation is a compile-error-adjacent oversight, and
// forcing the registry line keeps it visible in reviews.

// FromPayload reconstructs an Event from the (event_type, payload_json)
// pair the worker reads from the outbox table. Returns an error for
// unknown event types — the worker should log and skip (or park with
// attempt_count exhaustion).
func FromPayload(t EventType, raw []byte) (Event, error) {
	switch t {
	case EventTypeGroupMembershipAdded:
		var p struct {
			UserID  string `json:"user_id"`
			GroupID string `json:"group_id"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("unmarshal group_membership_added: %w", err)
		}
		userID, err := uuid.Parse(p.UserID)
		if err != nil {
			return nil, fmt.Errorf("parse user_id: %w", err)
		}
		groupID, err := uuid.Parse(p.GroupID)
		if err != nil {
			return nil, fmt.Errorf("parse group_id: %w", err)
		}
		return GroupMembershipAdded{UserID: userID, GroupID: groupID}, nil

	case EventTypeGroupMembershipRemoved:
		var p struct {
			UserID  string `json:"user_id"`
			GroupID string `json:"group_id"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("unmarshal group_membership_removed: %w", err)
		}
		userID, err := uuid.Parse(p.UserID)
		if err != nil {
			return nil, fmt.Errorf("parse user_id: %w", err)
		}
		groupID, err := uuid.Parse(p.GroupID)
		if err != nil {
			return nil, fmt.Errorf("parse group_id: %w", err)
		}
		return GroupMembershipRemoved{UserID: userID, GroupID: groupID}, nil

	default:
		return nil, fmt.Errorf("unknown event type: %q", t)
	}
}
