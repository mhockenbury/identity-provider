package http_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	myhttp "github.com/mhockenbury/identity-provider/internal/http"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// --- fakes for consent handler tests ---

type fakeConsentStore struct {
	scopes map[string][]string // key: userID.String()+"|"+clientID
}

func consentKey(u uuid.UUID, c string) string { return u.String() + "|" + c }

func (f *fakeConsentStore) HasScopes(ctx context.Context, u uuid.UUID, c string, scopes []string) (bool, error) {
	stored, ok := f.scopes[consentKey(u, c)]
	if !ok {
		return len(scopes) == 0, nil
	}
	for _, s := range scopes {
		if !slices.Contains(stored, s) {
			return false, nil
		}
	}
	return true, nil
}
func (f *fakeConsentStore) Grant(ctx context.Context, u uuid.UUID, c string, scopes []string) error {
	if f.scopes == nil {
		f.scopes = map[string][]string{}
	}
	cp := make([]string, len(scopes))
	copy(cp, scopes)
	f.scopes[consentKey(u, c)] = cp
	return nil
}

type fakeClientLookup struct {
	redirectURIs []string
	err          error
}

func (f *fakeClientLookup) GetByID(ctx context.Context, id string) (myhttp.ClientDisplay, error) {
	if f.err != nil {
		return myhttp.ClientDisplay{}, f.err
	}
	return myhttp.ClientDisplay{ID: id, RedirectURIs: f.redirectURIs}, nil
}

// newConsentFixture wires everything with a logged-in user.
func newConsentFixture(t *testing.T) (myhttp.ConsentConfig, *fakeUserStore, *fakeSessionStore, *fakeConsentStore, users.User, users.Session) {
	t.Helper()

	userID := uuid.New()
	u := users.User{ID: userID, Email: "alice@example.com"}
	userStore := &fakeUserStore{users: map[string]users.User{"alice@example.com": u}}
	sessStore := &fakeSessionStore{
		sessions: map[uuid.UUID]users.Session{},
	}
	sessionID := uuid.New()
	sess := users.Session{ID: sessionID, UserID: userID, ExpiresAt: time.Now().Add(time.Hour)}
	sessStore.sessions[sessionID] = sess

	consentStore := &fakeConsentStore{}

	tmpl, err := myhttp.ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}

	cfg := myhttp.ConsentConfig{
		Consent:   consentStore,
		Users:     userStore,
		Clients:   &fakeClientLookup{redirectURIs: []string{"http://localhost:5173/callback"}},
		Templates: tmpl,
		BaseURL:   "http://idp.test",
	}
	return cfg, userStore, sessStore, consentStore, u, sess
}

// attachSession runs the public WithSession middleware over r with a
// cookie pointing at `session`, captures the populated request (context
// now carries the session), and returns it so the test can invoke the
// handler under test directly with that request.
//
// Why not just test via a full chi router? Because the unit tests want
// to call the handler in isolation for clean assertions on responses,
// without the middleware stack coloring the output.
func attachSession(r *http.Request, store users.SessionStore, session users.Session) *http.Request {
	cookieReq := r.Clone(r.Context())
	cookieReq.AddCookie(&http.Cookie{Name: myhttp.SessionCookieName, Value: session.ID.String()})

	var populated *http.Request
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		populated = r
	})
	myhttp.WithSession(store)(capture).ServeHTTP(httptest.NewRecorder(), cookieReq)
	return populated
}

// --- GET /consent ---

func TestConsentGET_NoSessionRedirectsToLogin(t *testing.T) {
	cfg, _, _, _, _, _ := newConsentFixture(t)
	h := myhttp.ConsentGET(cfg)

	req := httptest.NewRequest(http.MethodGet, "/consent?client_id=localdev&redirect_uri=http://localhost:5173/callback&scope=openid", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect to /login)", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?return_to=") {
		t.Errorf("Location = %q, want /login?return_to=...", loc)
	}
}

func TestConsentGET_LoggedInRendersForm(t *testing.T) {
	cfg, _, sessStore, _, _, sess := newConsentFixture(t)
	h := myhttp.ConsentGET(cfg)

	base := httptest.NewRequest(http.MethodGet,
		"/consent?client_id=localdev&redirect_uri=http://localhost:5173/callback&scope=openid+read:docs&state=abc&return_to=/authorize?x=1", nil)
	req := attachSession(base, sessStore, sess)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "localdev") {
		t.Errorf("expected client_id in body")
	}
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("expected user email in body")
	}
	if !strings.Contains(body, "openid") || !strings.Contains(body, "read:docs") {
		t.Errorf("expected scopes in body")
	}
	if !strings.Contains(body, `<input type="hidden" name="state" value="abc">`) {
		t.Errorf("expected state in hidden field")
	}
}

func TestConsentGET_UnknownClientRejected(t *testing.T) {
	cfg, _, sessStore, _, _, sess := newConsentFixture(t)
	// Swap clients for an erroring one.
	cfg.Clients = &fakeClientLookup{err: errors.New("nope")}
	h := myhttp.ConsentGET(cfg)

	base := httptest.NewRequest(http.MethodGet,
		"/consent?client_id=nope&redirect_uri=x&scope=openid", nil)
	req := attachSession(base, sessStore, sess)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestConsentGET_UnregisteredRedirectURIRejected(t *testing.T) {
	cfg, _, sessStore, _, _, sess := newConsentFixture(t)
	h := myhttp.ConsentGET(cfg)

	// redirect_uri NOT in the fakeClientLookup's allow list.
	base := httptest.NewRequest(http.MethodGet,
		"/consent?client_id=localdev&redirect_uri=http://evil.example/cb&scope=openid", nil)
	req := attachSession(base, sessStore, sess)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// --- POST /consent ---

func TestConsentPOST_ApproveWritesRowAndRedirects(t *testing.T) {
	cfg, _, sessStore, consentStore, u, sess := newConsentFixture(t)
	h := myhttp.ConsentPOST(cfg)

	form := url.Values{
		"decision":     {"approve"},
		"client_id":    {"localdev"},
		"redirect_uri": {"http://localhost:5173/callback"},
		"state":        {"abc"},
		"return_to":    {"/authorize?x=1"},
		"scope":        {"openid", "read:docs"},
	}
	base := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	base.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req := attachSession(base, sessStore, sess)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/authorize?x=1" {
		t.Errorf("Location = %q", loc)
	}
	stored := consentStore.scopes[consentKey(u.ID, "localdev")]
	if len(stored) != 2 {
		t.Errorf("stored scopes = %v, want [openid read:docs]", stored)
	}
}

// Deny path: redirects back to the client's redirect_uri with
// error=access_denied (RFC 6749 §4.1.2.1), carries state through.
func TestConsentPOST_DenyRedirectsToClientWithError(t *testing.T) {
	cfg, _, sessStore, consentStore, _, sess := newConsentFixture(t)
	h := myhttp.ConsentPOST(cfg)

	form := url.Values{
		"decision":     {"deny"},
		"client_id":    {"localdev"},
		"redirect_uri": {"http://localhost:5173/callback"},
		"state":        {"xyz"},
		"scope":        {"openid"},
	}
	base := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	base.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req := attachSession(base, sessStore, sess)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if parsed.Host != "localhost:5173" || parsed.Path != "/callback" {
		t.Errorf("Location points away from client: %q", loc)
	}
	if parsed.Query().Get("error") != "access_denied" {
		t.Errorf("error = %q, want access_denied", parsed.Query().Get("error"))
	}
	if parsed.Query().Get("state") != "xyz" {
		t.Errorf("state not propagated: %q", parsed.Query().Get("state"))
	}
	if len(consentStore.scopes) != 0 {
		t.Error("deny should not grant any scopes")
	}
}

// Tampered redirect_uri in the form must be rejected even though the
// handler already checked at GET time. Defense in depth.
func TestConsentPOST_TamperedRedirectURIRejected(t *testing.T) {
	cfg, _, sessStore, _, _, sess := newConsentFixture(t)
	h := myhttp.ConsentPOST(cfg)

	form := url.Values{
		"decision":     {"approve"},
		"client_id":    {"localdev"},
		"redirect_uri": {"http://evil.example/cb"},
		"scope":        {"openid"},
	}
	base := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	base.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req := attachSession(base, sessStore, sess)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// Invalid decision value: reject rather than default to approve or deny.
func TestConsentPOST_InvalidDecisionRejected(t *testing.T) {
	cfg, _, sessStore, _, _, sess := newConsentFixture(t)
	h := myhttp.ConsentPOST(cfg)

	form := url.Values{
		"decision":     {"maybe"},
		"client_id":    {"localdev"},
		"redirect_uri": {"http://localhost:5173/callback"},
		"scope":        {"openid"},
	}
	base := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	base.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req := attachSession(base, sessStore, sess)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
