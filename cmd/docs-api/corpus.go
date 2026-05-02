package main

// Postgres-backed docs/folders store. Thin adapter over the sqlc-
// generated package in cmd/docs-api/db: handlers see the same
// Document / Folder shapes and the same Store method signatures they
// always have; the *implementation* is now SQL.
//
// Why an adapter instead of using the sqlc types directly:
//   - Wire-format stability: SPA already speaks our string-keyed JSON.
//     sqlc emits pgtype.UUID + pgtype.Timestamptz; we'd have to either
//     leak those (ugly) or write the same conversions in every handler.
//   - One place to translate "" / not-found semantics. sqlc returns
//     pgx.ErrNoRows; we map to ErrNotFound here, matching the old API.
//
// Handlers don't import package db.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/cmd/docs-api/db"
)

// Document is the wire shape returned to the SPA. Stable across
// implementation changes — see file-level comment.
type Document struct {
	ID        string    `json:"id"`
	FolderID  string    `json:"folder_id,omitempty"`
	Title     string    `json:"title"`
	Body      string    `json:"body,omitempty"`
	OwnerSub  string    `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Folder is the wire shape returned to the SPA.
type Folder struct {
	ID       string `json:"id"`
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name"`
}

// ErrNotFound is the sentinel handlers map to 404. Same semantics as
// the in-memory Store had.
var ErrNotFound = errors.New("not found")

// Store is the package-level persistence surface. Thin wrapper over a
// sqlc Queries instance plus the pgx pool (the pool is held so future
// transactional flows have a hook).
type Store struct {
	pool *pgxpool.Pool
	q    *db.Queries
}

// NewStore opens nothing — pool is the caller's. Cheap to construct.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, q: db.New(pool)}
}

func (s *Store) GetDoc(ctx context.Context, id string) (Document, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Document{}, ErrNotFound
	}
	row, err := s.q.GetDocument(ctx, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Document{}, ErrNotFound
		}
		return Document{}, fmt.Errorf("get doc: %w", err)
	}
	return docFromRow(row), nil
}

func (s *Store) GetFolder(ctx context.Context, id string) (Folder, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Folder{}, ErrNotFound
	}
	row, err := s.q.GetFolder(ctx, uid)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Folder{}, ErrNotFound
		}
		return Folder{}, fmt.Errorf("get folder: %w", err)
	}
	return folderFromRow(row), nil
}

func (s *Store) ListFolders(ctx context.Context) ([]Folder, error) {
	rows, err := s.q.ListFolders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	out := make([]Folder, 0, len(rows))
	for _, r := range rows {
		out = append(out, folderFromRow(r))
	}
	return out, nil
}

func (s *Store) ListDocs(ctx context.Context) ([]Document, error) {
	rows, err := s.q.ListDocuments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list docs: %w", err)
	}
	out := make([]Document, 0, len(rows))
	for _, r := range rows {
		out = append(out, docFromRow(r))
	}
	return out, nil
}

func (s *Store) ListFolderDocs(ctx context.Context, folderID string) ([]Document, error) {
	uid, err := parseUUID(folderID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.q.ListDocumentsInFolder(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("list folder docs: %w", err)
	}
	out := make([]Document, 0, len(rows))
	for _, r := range rows {
		out = append(out, docFromRow(r))
	}
	return out, nil
}

func (s *Store) CreateDocument(ctx context.Context, folderID, title, body, ownerSub string) (Document, error) {
	var folderUUID pgtype.UUID
	if folderID != "" {
		fid, err := parseUUID(folderID)
		if err != nil {
			return Document{}, fmt.Errorf("invalid folder_id: %w", err)
		}
		folderUUID = fid
	}
	row, err := s.q.CreateDocument(ctx, db.CreateDocumentParams{
		FolderID: folderUUID,
		Title:    title,
		Body:     body,
		OwnerSub: ownerSub,
	})
	if err != nil {
		return Document{}, fmt.Errorf("create doc: %w", err)
	}
	return docFromRow(row), nil
}

// UpdateDocument applies title/body edits. Empty strings are
// "no change" (sqlc query handles this via NULLIF). Returns
// ErrNotFound if no row matched.
func (s *Store) UpdateDocument(ctx context.Context, id, title, body string) (Document, error) {
	uid, err := parseUUID(id)
	if err != nil {
		return Document{}, ErrNotFound
	}
	row, err := s.q.UpdateDocument(ctx, db.UpdateDocumentParams{
		ID:    uid,
		Title: title,
		Body:  body,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Document{}, ErrNotFound
		}
		return Document{}, fmt.Errorf("update doc: %w", err)
	}
	return docFromRow(row), nil
}

func (s *Store) DeleteDocument(ctx context.Context, id string) error {
	uid, err := parseUUID(id)
	if err != nil {
		return ErrNotFound
	}
	rows, err := s.q.DeleteDocument(ctx, uid)
	if err != nil {
		return fmt.Errorf("delete doc: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// --- conversions ---

func parseUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return pgtype.UUID{}, err
	}
	return u, nil
}

func uuidString(u pgtype.UUID) string {
	if !u.Valid {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		u.Bytes[0:4], u.Bytes[4:6], u.Bytes[6:8], u.Bytes[8:10], u.Bytes[10:16])
}

func docFromRow(r db.Document) Document {
	return Document{
		ID:        uuidString(r.ID),
		FolderID:  uuidString(r.FolderID),
		Title:     r.Title,
		Body:      r.Body,
		OwnerSub:  r.OwnerSub,
		CreatedAt: r.CreatedAt.Time,
		UpdatedAt: r.UpdatedAt.Time,
	}
}

func folderFromRow(r db.Folder) Folder {
	return Folder{
		ID:       uuidString(r.ID),
		ParentID: uuidString(r.ParentID),
		Name:     r.Name,
	}
}
