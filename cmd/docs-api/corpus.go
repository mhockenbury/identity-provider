package main

// In-memory "docs product" corpus.
//
// docs-api doesn't have its own database — the whole point is to make
// the protocol the hero, not the persistence layer. A map behind a mutex
// is sufficient; restarts start fresh.
//
// The corpus is interesting enough that the SPA demo (stretch task) can
// render a list view, a detail view, and show permission tiers
// (owner/editor/viewer) in action. Each seed doc deliberately has a
// different owner or group-editor so the SPA can show "here's what
// alice sees vs bob sees" with no cheating.

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Document is the surface-facing shape returned from docs-api. Fields
// are wire-compatible with the eventual SPA — rename only at the cost
// of a frontend change.
type Document struct {
	ID        string    `json:"id"`
	FolderID  string    `json:"folder_id,omitempty"`
	Title     string    `json:"title"`
	Body      string    `json:"body,omitempty"`
	OwnerSub  string    `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Folder is a container for documents. Supports nesting via ParentID
// (empty = top-level). The FGA model inherits viewer/editor from
// parent → so a user who's viewer on "/engineering" can see docs in
// "/engineering/runbooks" without explicit tuples on the subfolder.
type Folder struct {
	ID       string `json:"id"`
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name"`
}

// Store holds the in-memory corpus. Safe for concurrent reads + writes.
// Writer locks are coarse (one big mutex); fine for a lab API at <1 RPS
// expected from a browser-driven SPA.
type Store struct {
	mu      sync.RWMutex
	docs    map[string]*Document
	folders map[string]*Folder
}

func NewStore() *Store {
	return &Store{
		docs:    map[string]*Document{},
		folders: map[string]*Folder{},
	}
}

// AddFolder inserts a folder at an explicit ID. Used by seeding — lets
// the FGA seed reference deterministic IDs across restarts. Runtime
// callers use CreateFolder which generates a UUID.
func (s *Store) AddFolder(f Folder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.folders[f.ID] = &f
}

// AddDocument inserts a document at an explicit ID. Seed-only (see
// AddFolder).
func (s *Store) AddDocument(d Document) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[d.ID] = &d
}

// GetDoc returns (doc, ok). Pointer is a copy — mutating it won't
// affect the store.
func (s *Store) GetDoc(id string) (Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.docs[id]
	if !ok {
		return Document{}, false
	}
	return *d, true
}

// GetFolder returns (folder, ok).
func (s *Store) GetFolder(id string) (Folder, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, ok := s.folders[id]
	if !ok {
		return Folder{}, false
	}
	return *f, true
}

// ListDocs returns all docs in insertion-agnostic order. Callers that
// need filtering by FGA do that themselves.
func (s *Store) ListDocs() []Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Document, 0, len(s.docs))
	for _, d := range s.docs {
		out = append(out, *d)
	}
	return out
}

// ListFolderDocs returns docs whose FolderID matches.
func (s *Store) ListFolderDocs(folderID string) []Document {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Document
	for _, d := range s.docs {
		if d.FolderID == folderID {
			out = append(out, *d)
		}
	}
	return out
}

// CreateDocument inserts a new doc with a fresh UUID. Returns the
// created doc so the caller can echo it back in the HTTP response.
func (s *Store) CreateDocument(folderID, title, body, ownerSub string) Document {
	now := time.Now().UTC()
	d := Document{
		ID:        uuid.New().String(),
		FolderID:  folderID,
		Title:     title,
		Body:      body,
		OwnerSub:  ownerSub,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[d.ID] = &d
	return d
}

// UpdateDocument applies title/body edits. Returns the updated doc or
// ErrNotFound.
func (s *Store) UpdateDocument(id, title, body string) (Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.docs[id]
	if !ok {
		return Document{}, ErrNotFound
	}
	if title != "" {
		d.Title = title
	}
	if body != "" {
		d.Body = body
	}
	d.UpdatedAt = time.Now().UTC()
	return *d, nil
}

// DeleteDocument removes a doc. Returns ErrNotFound if it wasn't there.
func (s *Store) DeleteDocument(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.docs[id]; !ok {
		return ErrNotFound
	}
	delete(s.docs, id)
	return nil
}

// ErrNotFound is the sentinel the HTTP layer maps to 404.
var ErrNotFound = fmt.Errorf("not found")

// --- seed ---
//
// SeedData is the baked-in corpus: deterministic IDs + owners so the
// FGA seed can reference them, and the SPA can link to a known doc at
// /docs/<UUID>. IDs are hardcoded UUIDs — easier to paste into curl
// and tests than runtime-generated ones.
//
// Users referenced here (alice, bob, carol) are expected to exist as
// real identity-provider users, created via `idp users create`. Their
// subject (sub) claim will be the UUID the IdP assigned them, not
// these names — the seed resolves that at startup via a map the
// operator provides (see SeedContext in seed.go's caller).

// SeedIDs groups the deterministic IDs the seed writes so other code
// (FGA seeder, tests) can reference them without restating the
// hardcoded values.
var SeedIDs = struct {
	FolderEngineering string
	FolderRunbooks    string // nested under Engineering
	FolderPublic      string

	DocEngOverview    string // in Engineering
	DocDeployRunbook  string // in Engineering/Runbooks
	DocOnCallRunbook  string // in Engineering/Runbooks
	DocPublicReadme   string // in Public
	DocPrivateNotes   string // top-level; only alice is owner
}{
	FolderEngineering: "11111111-1111-1111-1111-000000000001",
	FolderRunbooks:    "11111111-1111-1111-1111-000000000002",
	FolderPublic:      "11111111-1111-1111-1111-000000000003",

	DocEngOverview:   "22222222-2222-2222-2222-000000000001",
	DocDeployRunbook: "22222222-2222-2222-2222-000000000002",
	DocOnCallRunbook: "22222222-2222-2222-2222-000000000003",
	DocPublicReadme:  "22222222-2222-2222-2222-000000000004",
	DocPrivateNotes:  "22222222-2222-2222-2222-000000000005",
}

// SeedCorpus populates a fresh Store with the deterministic corpus.
// owner is the sub (user UUID) that will be recorded as the owner on
// every document. FGA tuples are seeded separately via SeedFGA.
//
// Choosing ONE owner for the whole seed simplifies: we're focused on
// the *viewer/editor* paths in the authz model, and ownership is just
// "you made it." Different viewers/editors per doc is what makes the
// authz checks interesting.
func SeedCorpus(s *Store, owner string) {
	s.AddFolder(Folder{
		ID:   SeedIDs.FolderEngineering,
		Name: "Engineering",
	})
	s.AddFolder(Folder{
		ID:       SeedIDs.FolderRunbooks,
		ParentID: SeedIDs.FolderEngineering,
		Name:     "Runbooks",
	})
	s.AddFolder(Folder{
		ID:   SeedIDs.FolderPublic,
		Name: "Public",
	})

	now := time.Now().UTC()
	s.AddDocument(Document{
		ID: SeedIDs.DocEngOverview, FolderID: SeedIDs.FolderEngineering,
		Title: "Engineering Overview",
		Body:  "What we work on, how we ship.",
		OwnerSub: owner, CreatedAt: now, UpdatedAt: now,
	})
	s.AddDocument(Document{
		ID: SeedIDs.DocDeployRunbook, FolderID: SeedIDs.FolderRunbooks,
		Title: "Deploy Runbook",
		Body:  "Step-by-step production deploy procedure.",
		OwnerSub: owner, CreatedAt: now, UpdatedAt: now,
	})
	s.AddDocument(Document{
		ID: SeedIDs.DocOnCallRunbook, FolderID: SeedIDs.FolderRunbooks,
		Title: "On-Call Runbook",
		Body:  "Paging, escalation, and runbook links.",
		OwnerSub: owner, CreatedAt: now, UpdatedAt: now,
	})
	s.AddDocument(Document{
		ID: SeedIDs.DocPublicReadme, FolderID: SeedIDs.FolderPublic,
		Title: "Public README",
		Body:  "Visible to anyone viewer-on-public.",
		OwnerSub: owner, CreatedAt: now, UpdatedAt: now,
	})
	s.AddDocument(Document{
		ID: SeedIDs.DocPrivateNotes,
		Title: "Private Notes",
		Body:  "Top-level doc, tightly held.",
		OwnerSub: owner, CreatedAt: now, UpdatedAt: now,
	})
}
