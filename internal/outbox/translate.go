package outbox

import (
	"fmt"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"

	"github.com/mhockenbury/identity-provider/internal/fga"
)

// TupleOpKind distinguishes FGA operations the worker batches into a
// single Write API call. See OpenFGA Write docs: a single request can
// carry both Writes and Deletes, atomically.
type TupleOpKind int

const (
	TupleOpWrite TupleOpKind = iota
	TupleOpDelete
)

func (k TupleOpKind) String() string {
	switch k {
	case TupleOpWrite:
		return "write"
	case TupleOpDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// TupleOp is one atomic FGA operation. An event may translate to zero
// or more TupleOps; the worker batches them across events into a single
// Write call.
//
// Uses SDK types (client.ClientTupleKey = openfga.TupleKey) directly.
// The slight leak of the SDK into our domain package is intentional:
// keeps the translation layer thin and avoids a parallel tuple struct.
type TupleOp struct {
	Kind  TupleOpKind
	Tuple client.ClientTupleKey
}

// Translate turns an event into the zero-or-more tuple operations the
// worker should apply to FGA. Pure function — no DB, no HTTP, no
// logging. Every event type needs a case here; an unknown type is a
// programming error (we built the event, failed to teach the translator).
//
// The FGA model this targets lives in migrations/fga/model.fga:
//
//	type group
//	  relations
//	    define member: [user]
//
// Group membership is the only thing layer 8 syncs. Future events
// (documents, folders, etc.) would add cases here.
func Translate(e Event) ([]TupleOp, error) {
	switch ev := e.(type) {
	case GroupMembershipAdded:
		return []TupleOp{{
			Kind: TupleOpWrite,
			Tuple: client.ClientTupleKey{
				User:     fga.TypeUser + ev.UserID.String(),
				Relation: fga.RelMember,
				Object:   fga.TypeGroup + ev.GroupID.String(),
			},
		}}, nil

	case GroupMembershipRemoved:
		return []TupleOp{{
			Kind: TupleOpDelete,
			Tuple: client.ClientTupleKey{
				User:     fga.TypeUser + ev.UserID.String(),
				Relation: fga.RelMember,
				Object:   fga.TypeGroup + ev.GroupID.String(),
			},
		}}, nil

	default:
		// Exhaustive switch — if you get here, an Event type was added
		// without a matching Translate case. Treat as a bug.
		return nil, fmt.Errorf("translate: no rule for event type %T (%s)", e, e.Type())
	}
}

// Ensure the SDK package is referenced so the import isn't removed by
// goimports on a day where all tuples use only the client alias.
var _ = openfga.PtrString
