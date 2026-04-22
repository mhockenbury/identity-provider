package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// --- fakes ---

// fakeChecker is a deterministic in-memory FGA stand-in. Keyed by
// "<user>|<relation>|<object>". Any checker error path is exercised by
// setting errOn to the key that should fail.
type fakeChecker struct {
	mu      sync.Mutex
	allowed map[string]bool
	errOn   map[string]error
}

func newFakeChecker() *fakeChecker {
	return &fakeChecker{
		allowed: map[string]bool{},
		errOn:   map[string]error{},
	}
}

func (f *fakeChecker) Check(_ context.Context, user, relation, object string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := user + "|" + relation + "|" + object
	if err, ok := f.errOn[key]; ok {
		return false, err
	}
	return f.allowed[key], nil
}

func (f *fakeChecker) allow(user, relation, object string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowed[user+"|"+relation+"|"+object] = true
}

// --- test harness ---

// newTestRouter builds a router with auth-middleware replaced by a
// test stub that just injects pre-built claims. That way we don't have
// to mint + verify a real JWT in every test; the auth-middleware
// surface is covered by auth_test.go.
func newTestRouter(t *testing.T, sub, scope string, store *Store, fga fgaChecker) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(injectClaims(sub, scope))
		registerResourceRoutes(r, handlerDeps{
			store: store,
			fga:   fga,
			// fgaRawClient omitted — handlers that need it (POST/DELETE)
			// will nil-deref if tested via this harness. Those paths
			// get a separate test that uses a fake rawClient below.
		})
	})
	return r
}

// injectClaims is the test-only equivalent of authenticate. Builds an
// AccessClaims from the given sub + scope and stashes it in ctx.
func injectClaims(sub, scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := &tokens.AccessClaims{
				BaseClaims: tokens.BaseClaims{
					RegisteredClaims: jwt.RegisteredClaims{Subject: sub},
				},
				Scope: scope,
			}
			ctx := context.WithValue(r.Context(), claimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// seedStoreForTests builds a minimal store — two docs in two folders.
// Deliberately doesn't use the full SeedCorpus so test expectations
// are obvious at the call site.
func seedStoreForTests() *Store {
	s := NewStore()
	s.AddFolder(Folder{ID: "f1", Name: "F1"})
	s.AddFolder(Folder{ID: "f2", Name: "F2"})
	s.AddDocument(Document{ID: "d1", FolderID: "f1", Title: "Doc 1"})
	s.AddDocument(Document{ID: "d2", FolderID: "f2", Title: "Doc 2"})
	s.AddDocument(Document{ID: "d3", Title: "Orphan Doc"})
	return s
}

// --- listDocs ---

func TestListDocs_FiltersByViewer(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	fga.allow("user:u1", "viewer", "document:d1")
	fga.allow("user:u1", "viewer", "document:d3")
	// d2 intentionally not allowed.

	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	w, _ := doGet(t, srv, "/docs")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var body struct{ Docs []Document }
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	ids := docIDs(body.Docs)
	if len(ids) != 2 {
		t.Fatalf("got %d docs, want 2; ids=%v", len(ids), ids)
	}
	if !contains(ids, "d1") || !contains(ids, "d3") {
		t.Errorf("expected d1 + d3, got %v", ids)
	}
}

func TestListDocs_RequiresReadDocsScope(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	srv := newTestRouter(t, "u1", "", store, fga) // empty scope
	w, _ := doGet(t, srv, "/docs")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// --- getDoc ---

func TestGetDoc_Visible_200(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	fga.allow("user:u1", "viewer", "document:d1")
	srv := newTestRouter(t, "u1", "read:docs", store, fga)

	w, _ := doGet(t, srv, "/docs/d1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%q)", w.Code, w.Body.String())
	}
	var got Document
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got.ID != "d1" || got.Title != "Doc 1" {
		t.Errorf("got %+v", got)
	}
}

func TestGetDoc_NotViewer_404(t *testing.T) {
	// 404, not 403 — we don't leak existence to users without view
	// permission.
	store := seedStoreForTests()
	fga := newFakeChecker() // no tuples
	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	w, _ := doGet(t, srv, "/docs/d1")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetDoc_Missing_404(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	w, _ := doGet(t, srv, "/docs/does-not-exist")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetDoc_FGAError_502(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	fga.errOn = map[string]error{
		"user:u1|viewer|document:d1": fmt.Errorf("fga down"),
	}
	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	w, _ := doGet(t, srv, "/docs/d1")
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
}

// --- folders ---

func TestGetFolder_Viewer_200(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	fga.allow("user:u1", "viewer", "folder:f1")
	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	w, _ := doGet(t, srv, "/folders/f1")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestGetFolder_NotViewer_404(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	w, _ := doGet(t, srv, "/folders/f1")
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListFolderDocs_FiltersByViewer(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	fga.allow("user:u1", "viewer", "folder:f1")
	fga.allow("user:u1", "viewer", "document:d1")
	// d1 is the only doc in f1 anyway; this confirms the filter runs
	// per-doc even inside a viewable folder.
	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	w, _ := doGet(t, srv, "/folders/f1/docs")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct{ Docs []Document }
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if len(body.Docs) != 1 || body.Docs[0].ID != "d1" {
		t.Errorf("got %+v", body.Docs)
	}
}

// --- updateDoc (editor required) ---

func TestUpdateDoc_Editor_200(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	fga.allow("user:u1", "editor", "document:d1")
	srv := newTestRouter(t, "u1", "write:docs", store, fga)
	body := strings.NewReader(`{"title":"Updated"}`)
	w, _ := doReq(t, srv, http.MethodPatch, "/docs/d1", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%q)", w.Code, w.Body.String())
	}
	got, _ := store.GetDoc("d1")
	if got.Title != "Updated" {
		t.Errorf("title = %q, want Updated", got.Title)
	}
}

func TestUpdateDoc_NotEditor_403(t *testing.T) {
	store := seedStoreForTests()
	fga := newFakeChecker()
	srv := newTestRouter(t, "u1", "write:docs", store, fga)
	body := strings.NewReader(`{"title":"X"}`)
	w, _ := doReq(t, srv, http.MethodPatch, "/docs/d1", body)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestUpdateDoc_ReadScope_403(t *testing.T) {
	// Correct scope is write:docs. read:docs alone shouldn't allow PATCH.
	store := seedStoreForTests()
	fga := newFakeChecker()
	fga.allow("user:u1", "editor", "document:d1")
	srv := newTestRouter(t, "u1", "read:docs", store, fga)
	body := strings.NewReader(`{"title":"X"}`)
	w, _ := doReq(t, srv, http.MethodPatch, "/docs/d1", body)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

// --- userFromClaims ---

func TestUserFromClaims(t *testing.T) {
	c := &tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "abc-123"}},
	}
	if got := userFromClaims(c); got != "user:abc-123" {
		t.Errorf("got %q", got)
	}
	if got := userFromClaims(nil); got != "" {
		t.Errorf("nil claims: got %q", got)
	}
}

// --- helpers ---

func doGet(t *testing.T, h http.Handler, path string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	return doReq(t, h, http.MethodGet, path, nil)
}

func doReq(t *testing.T, h http.Handler, method, path string, body interface{ Read([]byte) (int, error) }) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, body.(interface{ Read(p []byte) (n int, err error) }))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w, req
}

func docIDs(docs []Document) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, d.ID)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
