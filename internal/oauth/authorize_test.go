package oauth_test

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

	"github.com/mhockenbury/identity-provider/internal/clients"
	"github.com/mhockenbury/identity-provider/internal/consent"
	"github.com/mhockenbury/identity-provider/internal/oauth"
)

// --- fakes ---

type fakeClientStore struct {
	client clients.Client
	err    error
}

func (f *fakeClientStore) GetByID(ctx context.Context, id string) (clients.Client, error) {
	if f.err != nil {
		return clients.Client{}, f.err
	}
	if id != f.client.ID {
		return clients.Client{}, clients.ErrNotFound
	}
	return f.client, nil
}

type fakeConsentStore struct {
	has bool
}

func (f *fakeConsentStore) HasScopes(ctx context.Context, u uuid.UUID, c string, scopes []string) (bool, error) {
	return f.has, nil
}
func (f *fakeConsentStore) Grant(ctx context.Context, u uuid.UUID, c string, scopes []string) error {
	return nil
}

// Assert our fake actually satisfies the interface we import.
var _ consent.Store = (*fakeConsentStore)(nil)

type fakeCodeStore struct {
	lastIn oauth.NewAuthCodeInput
	code   string
	err    error
}

func (f *fakeCodeStore) Issue(ctx context.Context, in oauth.NewAuthCodeInput, ttl time.Duration) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.lastIn = in
	if f.code == "" {
		f.code = "test-code-123"
	}
	return f.code, nil
}
func (f *fakeCodeStore) Consume(ctx context.Context, code, clientID, redirectURI string) (oauth.AuthCode, error) {
	return oauth.AuthCode{}, errors.New("not used in tests")
}

// buildTestClient returns a client the happy-path test can use.
func buildTestClient() clients.Client {
	return clients.Client{
		ID:            "localdev",
		RedirectURIs:  []string{"http://localhost:5173/callback"},
		AllowedGrants: []string{"authorization_code", "refresh_token"},
		AllowedScopes: []string{"openid", "profile", "email", "read:docs"},
		IsPublic:      true,
	}
}

// newAuthorizeFixture returns a ready-to-use AuthorizeConfig plus handles
// to the fakes so tests can assert side effects.
func newAuthorizeFixture(loggedIn bool, hasConsent bool) (oauth.AuthorizeConfig, *fakeCodeStore) {
	userID := uuid.New()
	codes := &fakeCodeStore{}

	cfg := oauth.AuthorizeConfig{
		Clients:   &fakeClientStore{client: buildTestClient()},
		Consent:   &fakeConsentStore{has: hasConsent},
		AuthCodes: codes,
		CodeTTL:   time.Minute,
		CurrentSessionUser: func(r *http.Request) (uuid.UUID, bool) {
			if loggedIn {
				return userID, true
			}
			return uuid.Nil, false
		},
	}
	return cfg, codes
}

// A well-formed authorize URL every test can start from, then amend.
func goodAuthorizeURL() string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", "localdev")
	v.Set("redirect_uri", "http://localhost:5173/callback")
	v.Set("scope", "openid read:docs")
	v.Set("state", "xyz")
	v.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	v.Set("code_challenge_method", "S256")
	v.Set("nonce", "n-0S6_WzA2Mj")
	return "/authorize?" + v.Encode()
}

// --- happy path ---

func TestAuthorize_HappyPathIssuesCodeAndRedirects(t *testing.T) {
	cfg, codes := newAuthorizeFixture(true, true)
	h := oauth.Authorize(cfg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, goodAuthorizeURL(), nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302. body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Host != "localhost:5173" || loc.Path != "/callback" {
		t.Errorf("redirect target = %v", loc)
	}
	if loc.Query().Get("code") == "" {
		t.Errorf("no code in redirect: %v", loc.Query())
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("state not propagated: %q", loc.Query().Get("state"))
	}

	// Code store saw all the fields.
	if codes.lastIn.ClientID != "localdev" || codes.lastIn.RedirectURI != "http://localhost:5173/callback" {
		t.Errorf("bad code.Issue inputs: %+v", codes.lastIn)
	}
	if codes.lastIn.CodeChallenge != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("code_challenge not persisted")
	}
	if codes.lastIn.Nonce != "n-0S6_WzA2Mj" {
		t.Errorf("nonce not persisted: %q", codes.lastIn.Nonce)
	}
	if len(codes.lastIn.Scopes) != 2 {
		t.Errorf("scopes = %v", codes.lastIn.Scopes)
	}
}

// --- redirects that must NOT leak error info to a tampered redirect_uri ---

func TestAuthorize_MissingClientIDReturnsPlainError(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, true)
	h := oauth.Authorize(cfg)

	req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAuthorize_UnknownClientReturnsPlainError(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, true)
	// Swap in a client store that doesn't know "localdev".
	cfg.Clients = &fakeClientStore{err: clients.ErrNotFound}
	h := oauth.Authorize(cfg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, goodAuthorizeURL(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAuthorize_UnregisteredRedirectURIReturnsPlainError(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, true)
	h := oauth.Authorize(cfg)

	u := url.Values{}
	u.Set("response_type", "code")
	u.Set("client_id", "localdev")
	u.Set("redirect_uri", "http://evil.example/cb")
	u.Set("scope", "openid")
	u.Set("code_challenge", "x")
	u.Set("code_challenge_method", "S256")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+u.Encode(), nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// --- redirects with error=... to the (now-trusted) redirect_uri ---

// Once client + redirect_uri are validated, parameter errors redirect
// back with error=... so the client can display them.

func assertErrorRedirect(t *testing.T, rec *httptest.ResponseRecorder, wantErr string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302. body=%s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Host != "localhost:5173" {
		t.Errorf("redirect host = %q, want localhost:5173", loc.Host)
	}
	if got := loc.Query().Get("error"); got != wantErr {
		t.Errorf("error = %q, want %q", got, wantErr)
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("state not propagated")
	}
}

func TestAuthorize_WrongResponseTypeRedirectsUnsupportedResponseType(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, true)
	h := oauth.Authorize(cfg)

	bad := strings.Replace(goodAuthorizeURL(), "response_type=code", "response_type=token", 1)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, bad, nil))
	assertErrorRedirect(t, rec, "unsupported_response_type")
}

func TestAuthorize_MissingPKCERedirectsInvalidRequest(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, true)
	h := oauth.Authorize(cfg)

	u := url.Values{}
	u.Set("response_type", "code")
	u.Set("client_id", "localdev")
	u.Set("redirect_uri", "http://localhost:5173/callback")
	u.Set("scope", "openid")
	u.Set("state", "xyz")
	// no code_challenge / code_challenge_method

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+u.Encode(), nil))
	assertErrorRedirect(t, rec, "invalid_request")
}

func TestAuthorize_PlainChallengeMethodRejected(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, true)
	h := oauth.Authorize(cfg)

	bad := strings.Replace(goodAuthorizeURL(), "code_challenge_method=S256", "code_challenge_method=plain", 1)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, bad, nil))
	assertErrorRedirect(t, rec, "invalid_request")
}

func TestAuthorize_UnknownScopeRedirectsInvalidScope(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, true)
	h := oauth.Authorize(cfg)

	u := url.Values{}
	u.Set("response_type", "code")
	u.Set("client_id", "localdev")
	u.Set("redirect_uri", "http://localhost:5173/callback")
	u.Set("scope", "openid admin:users") // admin:users not in allowedScopes
	u.Set("state", "xyz")
	u.Set("code_challenge", "x")
	u.Set("code_challenge_method", "S256")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+u.Encode(), nil))
	assertErrorRedirect(t, rec, "invalid_scope")
}

// --- pivots ---

func TestAuthorize_NoSessionPivotsToLogin(t *testing.T) {
	cfg, _ := newAuthorizeFixture(false, false)
	h := oauth.Authorize(cfg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, goodAuthorizeURL(), nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?return_to=") {
		t.Errorf("Location = %q, want /login?return_to=...", loc)
	}
}

func TestAuthorize_NoConsentPivotsToConsent(t *testing.T) {
	cfg, _ := newAuthorizeFixture(true, false)
	h := oauth.Authorize(cfg)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, goodAuthorizeURL(), nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Path != "/consent" {
		t.Errorf("Location path = %q, want /consent", loc.Path)
	}
	// /consent needs everything to continue the flow.
	q := loc.Query()
	if q.Get("return_to") == "" || q.Get("client_id") != "localdev" ||
		q.Get("redirect_uri") == "" || q.Get("scope") == "" {
		t.Errorf("consent URL missing required params: %v", q)
	}
}
