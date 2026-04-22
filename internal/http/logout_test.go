package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	myhttp "github.com/mhockenbury/identity-provider/internal/http"
	"github.com/mhockenbury/identity-provider/internal/users"
)

func TestLogout_RedirectsToRoot(t *testing.T) {
	sess := &fakeSessionStore{sessions: map[uuid.UUID]users.Session{}}
	h := myhttp.Logout(myhttp.LogoutConfig{Sessions: sess, Secure: false})

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
}

func TestLogout_DeletesSessionAndClearsCookie(t *testing.T) {
	userID := uuid.New()
	sessID := uuid.New()
	sess := &fakeSessionStore{sessions: map[uuid.UUID]users.Session{
		sessID: {
			ID: sessID, UserID: userID,
			CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		},
	}}

	h := myhttp.Logout(myhttp.LogoutConfig{Sessions: sess, Secure: false})
	wrapped := myhttp.WithSession(sess)(h)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: myhttp.SessionCookieName, Value: sessID.String()})
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// Session row is gone.
	if _, ok := sess.sessions[sessID]; ok {
		t.Errorf("session not deleted from store")
	}
	// Set-Cookie with MaxAge < 0 (ClearSessionCookie behavior).
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == myhttp.SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("expected cookie clear (MaxAge<0); cookies=%+v", rec.Result().Cookies())
	}
}

func TestLogout_NoSessionStillRedirects(t *testing.T) {
	sess := &fakeSessionStore{sessions: map[uuid.UUID]users.Session{}}
	h := myhttp.Logout(myhttp.LogoutConfig{Sessions: sess, Secure: false})

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302 (idempotent logout)", rec.Code)
	}
}

// Accept both GET and POST per the package doc.
func TestLogout_AcceptsPOSTToo(t *testing.T) {
	sess := &fakeSessionStore{sessions: map[uuid.UUID]users.Session{}}
	h := myhttp.Logout(myhttp.LogoutConfig{Sessions: sess, Secure: false})

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
}
