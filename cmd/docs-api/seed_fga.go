package main

// FGA tuple seeding for the in-memory doc corpus.
//
// docs-api doesn't participate in the transactional outbox — documents
// are in-memory, not identity-side rows, so there's nothing to
// atomically pair with an FGA write. We write tuples directly.
//
// Seeding is idempotent: we use OnDuplicateWrites=ignore when writing
// tuples so starting docs-api twice against the same OpenFGA store
// doesn't error. Handy for `make dev-all` reruns.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/openfga/go-sdk/client"

	"github.com/mhockenbury/identity-provider/internal/fga"
)

// SeedPeople is the set of human users referenced in the FGA seed. Keyed
// by a short nickname; values are the user's sub claim (== user UUID as
// assigned by the IdP).
//
// Populated at docs-api startup from env vars like DOCS_SEED_ALICE=<uuid>.
// If a nickname is missing from this map, that identity's seed tuples
// are simply skipped — the corpus still loads, just without that user's
// permissions wired up.
type SeedPeople struct {
	Alice string // "owns" engineering overview; editor on runbooks
	Bob   string // viewer on engineering (inherits viewer on runbooks)
	Carol string // viewer on public only
}

// SeedFGA writes the tuples that make the in-memory corpus actually
// authorizable. Mirrors SeedCorpus's structure.
//
// Permission layout (designed to exercise the FGA model):
//
//	folder:engineering
//	  owner: alice
//	  viewer: bob         ← bob gets viewer on /engineering/*
//
//	folder:runbooks  parent=folder:engineering
//	  editor: alice       ← explicit + inherited
//	  (bob is viewer via parent inheritance — no tuple needed)
//
//	folder:public
//	  viewer: carol
//
//	document:eng-overview     parent=folder:engineering
//	  (alice owner via folder; bob viewer via folder)
//
//	document:deploy-runbook   parent=folder:runbooks
//	  (alice editor via folder; bob viewer via grandparent)
//
//	document:oncall-runbook   parent=folder:runbooks
//	  (same as deploy-runbook)
//
//	document:public-readme    parent=folder:public
//	  (carol viewer via folder)
//
//	document:private-notes    (no parent)
//	  owner: alice
//	  (bob and carol have NO access)
//
// This gives us tests for:
//   - direct tuple → viewer (carol on public-readme via folder)
//   - inherited viewer (bob on deploy-runbook via grandparent)
//   - editor implies viewer (alice can view everything she edits)
//   - no access path (carol on private-notes — should 403)
func SeedFGA(ctx context.Context, c *client.OpenFgaClient, p SeedPeople) error {
	var writes []client.ClientTupleKey

	// Parent tuples (folders + docs need their parent linked for
	// inheritance to resolve). Always safe to write; idempotent.
	writes = append(writes,
		parentTuple(fga.TypeFolder+SeedIDs.FolderRunbooks, fga.TypeFolder+SeedIDs.FolderEngineering),
		parentTuple(fga.TypeDocument+SeedIDs.DocEngOverview, fga.TypeFolder+SeedIDs.FolderEngineering),
		parentTuple(fga.TypeDocument+SeedIDs.DocDeployRunbook, fga.TypeFolder+SeedIDs.FolderRunbooks),
		parentTuple(fga.TypeDocument+SeedIDs.DocOnCallRunbook, fga.TypeFolder+SeedIDs.FolderRunbooks),
		parentTuple(fga.TypeDocument+SeedIDs.DocPublicReadme, fga.TypeFolder+SeedIDs.FolderPublic),
	)

	if p.Alice != "" {
		writes = append(writes,
			ownerTuple(fga.TypeUser+p.Alice, fga.TypeFolder+SeedIDs.FolderEngineering),
			editorTuple(fga.TypeUser+p.Alice, fga.TypeFolder+SeedIDs.FolderRunbooks),
			ownerTuple(fga.TypeUser+p.Alice, fga.TypeDocument+SeedIDs.DocPrivateNotes),
		)
	}
	if p.Bob != "" {
		writes = append(writes,
			viewerTuple(fga.TypeUser+p.Bob, fga.TypeFolder+SeedIDs.FolderEngineering),
		)
	}
	if p.Carol != "" {
		writes = append(writes,
			viewerTuple(fga.TypeUser+p.Carol, fga.TypeFolder+SeedIDs.FolderPublic),
		)
	}

	if len(writes) == 0 {
		slog.Info("fga seed: no user nicknames configured; skipping user tuples (parent tuples only)")
	}

	if err := fga.WriteAndDelete(ctx, c, writes, nil, true /*idempotent*/); err != nil {
		return fmt.Errorf("seed fga tuples: %w", err)
	}

	slog.Info("fga seed complete", "tuples_written", len(writes))
	return nil
}

// --- tuple builders ---
// Thin helpers; keep the Write call sites readable.

func parentTuple(child, parent string) client.ClientTupleKey {
	return client.ClientTupleKey{User: parent, Relation: fga.RelParent, Object: child}
}

func ownerTuple(user, obj string) client.ClientTupleKey {
	return client.ClientTupleKey{User: user, Relation: fga.RelOwner, Object: obj}
}

func editorTuple(user, obj string) client.ClientTupleKey {
	return client.ClientTupleKey{User: user, Relation: fga.RelEditor, Object: obj}
}

func viewerTuple(user, obj string) client.ClientTupleKey {
	return client.ClientTupleKey{User: user, Relation: fga.RelViewer, Object: obj}
}
