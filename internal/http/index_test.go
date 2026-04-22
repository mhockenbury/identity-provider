package http_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	myhttp "github.com/mhockenbury/identity-provider/internal/http"
	"github.com/mhockenbury/identity-provider/internal/users"
)

func TestIndex_AnonymousRendersNotSignedIn(t *testing.T) {
	tmpl, err := myhttp.ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}
	h := myhttp.Index(myhttp.IndexConfig{Templates: tmpl, Users: &fakeUserStore{}})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Not signed in") {
		t.Errorf("expected 'Not signed in' in body, got: %s", body[:min(400, len(body))])
	}
	if strings.Contains(body, "Signed in as") {
		t.Errorf("anonymous response should not say 'Signed in as'")
	}
}

func TestIndex_LoggedInShowsEmail(t *testing.T) {
	tmpl, err := myhttp.ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}

	uid := uuid.New()
	userStore := &fakeUserStore{users: map[string]users.User{
		"alice@example.com": {ID: uid, Email: "alice@example.com"},
	}}
	sess := &fakeSessionStore{
		sessions: map[uuid.UUID]users.Session{},
	}
	sessID := uuid.New()
	sess.sessions[sessID] = users.Session{
		ID: sessID, UserID: uid,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}

	h := myhttp.Index(myhttp.IndexConfig{Templates: tmpl, Users: userStore})

	// Route through WithSession to populate ctx with a Session.
	wrapped := myhttp.WithSession(sess)(h)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: myhttp.SessionCookieName, Value: sessID.String()})
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "Signed in as") {
		t.Errorf("expected 'Signed in as' in body")
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("expected email in body")
	}
}

func TestIndex_NonRootPath404s(t *testing.T) {
	tmpl, _ := myhttp.ParseTemplates()
	h := myhttp.Index(myhttp.IndexConfig{Templates: tmpl})

	// The Index handler explicitly checks r.URL.Path == "/" — hits to
	// /foo via this handler should 404 rather than render the landing page.
	req := httptest.NewRequest(http.MethodGet, "/foo", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for non-root path", rec.Code)
	}
}

func TestIndex_ResponseIsNoStore(t *testing.T) {
	tmpl, _ := myhttp.ParseTemplates()
	h := myhttp.Index(myhttp.IndexConfig{Templates: tmpl, Users: &fakeUserStore{}})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
