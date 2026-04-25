package http_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	myhttp "github.com/mhockenbury/identity-provider/internal/http"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// fakeUserStore for login tests — doesn't touch the DB.
type fakeUserStore struct {
	users map[string]users.User // email → user
	hash  string                // shared password hash across "users" for test brevity
}

func (f *fakeUserStore) Create(ctx context.Context, email, password string) (users.User, error) {
	return users.User{}, errors.New("not used in tests")
}
func (f *fakeUserStore) GetByEmail(ctx context.Context, email string) (users.User, error) {
	u, ok := f.users[email]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return u, nil
}
func (f *fakeUserStore) GetByID(ctx context.Context, id uuid.UUID) (users.User, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return users.User{}, users.ErrNotFound
}
func (f *fakeUserStore) Authenticate(ctx context.Context, email, password string) (users.User, error) {
	u, err := f.GetByEmail(ctx, email)
	if err != nil {
		return users.User{}, err
	}
	if err := users.VerifyPassword(password, u.PasswordHash); err != nil {
		return users.User{}, err
	}
	return u, nil
}
func (f *fakeUserStore) List(ctx context.Context) ([]users.User, error) {
	out := make([]users.User, 0, len(f.users))
	for _, u := range f.users {
		out = append(out, u)
	}
	return out, nil
}
func (f *fakeUserStore) SetAdmin(ctx context.Context, id uuid.UUID, isAdmin bool) error {
	for email, u := range f.users {
		if u.ID == id {
			u.IsAdmin = isAdmin
			f.users[email] = u
			return nil
		}
	}
	return users.ErrNotFound
}

func newLoginFixture(t *testing.T) (myhttp.LoginConfig, *fakeUserStore, *fakeSessionStore) {
	t.Helper()

	// Build a user with a known password.
	hash, err := users.HashPassword("correct-password", users.Argon2Params{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	uid := uuid.New()
	userStore := &fakeUserStore{
		users: map[string]users.User{
			"alice@example.com": {ID: uid, Email: "alice@example.com", PasswordHash: hash},
		},
	}
	sessStore := &fakeSessionStore{}

	tmpl, err := myhttp.ParseTemplates()
	if err != nil {
		t.Fatalf("ParseTemplates: %v", err)
	}

	cfg := myhttp.LoginConfig{
		Users:      userStore,
		Sessions:   sessStore,
		Templates:  tmpl,
		BaseURL:    "http://idp.test",
		SessionTTL: time.Hour,
		Secure:     false,
	}
	return cfg, userStore, sessStore
}

func TestLoginGET_RendersForm(t *testing.T) {
	cfg, _, _ := newLoginFixture(t)
	h := myhttp.LoginGET(cfg)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<form method=\"POST\" action=\"/login\">") {
		t.Errorf("expected form in body, got: %s", body[:min(200, len(body))])
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestLoginPOST_CorrectPasswordCreatesSession(t *testing.T) {
	cfg, _, sessStore := newLoginFixture(t)
	h := myhttp.LoginPOST(cfg)

	form := url.Values{
		"email":     {"alice@example.com"},
		"password":  {"correct-password"},
		"return_to": {"/authorize?client_id=localdev"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302. body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/authorize?client_id=localdev" {
		t.Errorf("Location = %q, want /authorize?client_id=localdev", loc)
	}

	// Session cookie set?
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == myhttp.SessionCookieName && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected Set-Cookie for session")
	}

	// Session row created.
	if len(sessStore.sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessStore.sessions))
	}
}

func TestLoginPOST_WrongPasswordGenericError(t *testing.T) {
	cfg, _, sessStore := newLoginFixture(t)
	h := myhttp.LoginPOST(cfg)

	form := url.Values{"email": {"alice@example.com"}, "password": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid email or password") {
		t.Errorf("expected generic error, got: %s", rec.Body.String())
	}
	if len(sessStore.sessions) != 0 {
		t.Error("no session should have been created on failed login")
	}
}

// User enumeration check: "no such user" produces IDENTICAL response
// bytes to "wrong password". An attacker probing for valid emails
// must not be able to tell.
func TestLoginPOST_NoSuchUserSameResponseAsWrongPassword(t *testing.T) {
	cfg, _, _ := newLoginFixture(t)
	h := myhttp.LoginPOST(cfg)

	// (a) wrong password for known user
	req1 := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(url.Values{"email": {"alice@example.com"}, "password": {"bad"}}.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	// (b) unknown email
	req2 := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(url.Values{"email": {"bob@example.com"}, "password": {"bad"}}.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec1.Code != rec2.Code {
		t.Errorf("status codes differ: %d vs %d (leaks user existence)", rec1.Code, rec2.Code)
	}
	// Bodies may differ on the email field value we echo back into the
	// form. That's intentional UX. The error message must be identical.
	getErr := func(s string) string {
		start := strings.Index(s, `class="error"`)
		if start < 0 {
			return ""
		}
		end := strings.Index(s[start:], "</div>")
		if end < 0 {
			return ""
		}
		return s[start : start+end]
	}
	if getErr(rec1.Body.String()) != getErr(rec2.Body.String()) {
		t.Errorf("error blocks differ between wrong-password and unknown-user cases")
	}
}

// return_to open-redirect defense: cross-origin return_to must be
// dropped so the post-login redirect goes to "/".
func TestLoginPOST_RejectsCrossOriginReturnTo(t *testing.T) {
	cfg, _, _ := newLoginFixture(t)
	h := myhttp.LoginPOST(cfg)

	form := url.Values{
		"email":     {"alice@example.com"},
		"password":  {"correct-password"},
		"return_to": {"https://evil.example.com/steal"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
}

// Absolute same-origin URL with matching scheme+host should be accepted
// (the path-and-query fragment is extracted).
func TestLoginPOST_AcceptsSameOriginAbsoluteReturnTo(t *testing.T) {
	cfg, _, _ := newLoginFixture(t)
	h := myhttp.LoginPOST(cfg)

	form := url.Values{
		"email":     {"alice@example.com"},
		"password":  {"correct-password"},
		"return_to": {"http://idp.test/authorize?x=1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/authorize?x=1" {
		t.Errorf("Location = %q, want /authorize?x=1", loc)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
