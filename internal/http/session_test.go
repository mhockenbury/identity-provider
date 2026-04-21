package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	myhttp "github.com/mhockenbury/identity-provider/internal/http"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// fakeSessionStore implements users.SessionStore without a DB.
type fakeSessionStore struct {
	sessions map[uuid.UUID]users.Session
	getErr   error
}

func (f *fakeSessionStore) Create(ctx context.Context, userID uuid.UUID, ttl time.Duration) (users.Session, error) {
	s := users.Session{
		ID: uuid.New(), UserID: userID,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(ttl),
	}
	if f.sessions == nil {
		f.sessions = map[uuid.UUID]users.Session{}
	}
	f.sessions[s.ID] = s
	return s, nil
}
func (f *fakeSessionStore) Get(ctx context.Context, id uuid.UUID) (users.Session, error) {
	if f.getErr != nil {
		return users.Session{}, f.getErr
	}
	s, ok := f.sessions[id]
	if !ok {
		return users.Session{}, users.ErrSessionNotFound
	}
	if time.Now().After(s.ExpiresAt) {
		delete(f.sessions, id)
		return users.Session{}, users.ErrSessionExpired
	}
	return s, nil
}
func (f *fakeSessionStore) Delete(ctx context.Context, id uuid.UUID) error {
	delete(f.sessions, id)
	return nil
}
func (f *fakeSessionStore) DeleteExpired(ctx context.Context) (int64, error) { return 0, nil }

func TestSetAndReadSessionCookie_RoundTrip(t *testing.T) {
	rec := httptest.NewRecorder()
	id := uuid.New()
	myhttp.SetSessionCookie(rec, id, false)

	// Echo the Set-Cookie back into a request Cookie header.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	got, err := myhttp.ReadSessionCookie(req)
	if err != nil {
		t.Fatalf("ReadSessionCookie: %v", err)
	}
	if got != id {
		t.Errorf("round-trip id = %v, want %v", got, id)
	}
}

func TestSetSessionCookie_HttpOnlyAndSameSite(t *testing.T) {
	rec := httptest.NewRecorder()
	myhttp.SetSessionCookie(rec, uuid.New(), false)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]

	if !c.HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Secure {
		t.Error("Secure should be false when secure=false")
	}
}

func TestSetSessionCookie_SecureWhenHTTPS(t *testing.T) {
	rec := httptest.NewRecorder()
	myhttp.SetSessionCookie(rec, uuid.New(), true)
	c := rec.Result().Cookies()[0]
	if !c.Secure {
		t.Error("Secure should be true when secure=true")
	}
}

func TestClearSessionCookie_MaxAgeNegative(t *testing.T) {
	rec := httptest.NewRecorder()
	myhttp.ClearSessionCookie(rec, false)
	c := rec.Result().Cookies()[0]
	if c.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative (delete)", c.MaxAge)
	}
}

func TestReadSessionCookie_MissingReturnsError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := myhttp.ReadSessionCookie(req)
	if err == nil {
		t.Error("expected error for missing cookie")
	}
}

func TestReadSessionCookie_MalformedReturnsError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: myhttp.SessionCookieName, Value: "not-a-uuid"})
	_, err := myhttp.ReadSessionCookie(req)
	if err == nil {
		t.Error("expected error for malformed cookie value")
	}
}

// Middleware integration: request with a valid session cookie exposes the
// session via SessionFromContext; request without a cookie passes through
// cleanly with a nil session.
func TestWithSession_AttachesSessionToContext(t *testing.T) {
	store := &fakeSessionStore{}
	userID := uuid.New()
	sess, _ := store.Create(context.Background(), userID, time.Hour)

	var observed *users.Session
	h := myhttp.WithSession(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = myhttp.SessionFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: myhttp.SessionCookieName, Value: sess.ID.String()})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if observed == nil {
		t.Fatal("handler saw nil session, want populated")
	}
	if observed.UserID != userID {
		t.Errorf("UserID = %v, want %v", observed.UserID, userID)
	}
}

func TestWithSession_NoCookiePassesThrough(t *testing.T) {
	store := &fakeSessionStore{}
	var observed *users.Session
	h := myhttp.WithSession(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = myhttp.SessionFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if observed != nil {
		t.Errorf("handler saw session %+v, want nil (no cookie)", observed)
	}
}

// Stale cookie (session deleted from store) becomes "no session" —
// handler runs with nil session, cookie is NOT cleared (intentional,
// see comment in WithSession).
func TestWithSession_ExpiredOrMissingTreatedAsAnonymous(t *testing.T) {
	store := &fakeSessionStore{}
	var observed *users.Session
	h := myhttp.WithSession(store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = myhttp.SessionFromContext(r.Context())
	}))

	// Cookie points at a session ID the store doesn't know about.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: myhttp.SessionCookieName, Value: uuid.New().String()})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if observed != nil {
		t.Errorf("handler saw session, want nil (store didn't know the id)")
	}
	// Middleware should NOT have cleared the cookie — verify no Set-Cookie.
	for _, c := range rec.Result().Cookies() {
		if c.Name == myhttp.SessionCookieName && c.MaxAge < 0 {
			t.Errorf("middleware cleared the cookie; it shouldn't")
		}
	}
}
