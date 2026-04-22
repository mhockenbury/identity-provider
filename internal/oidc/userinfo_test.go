package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/oidc"
	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// --- fakes ---

// fakeVerifier is a tokens.Verifier stand-in. Returns either the canned
// claims or a canned error.
type fakeVerifier struct {
	claims *tokens.AccessClaims
	err    error
}

func (f *fakeVerifier) Verify(ctx context.Context, raw string) (*tokens.AccessClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

// fakeUserStore returns canned user data.
type fakeUserStore struct {
	data oidc.UserInfoData
	err  error
}

func (f *fakeUserStore) GetByID(ctx context.Context, id uuid.UUID) (oidc.UserInfoData, error) {
	if f.err != nil {
		return oidc.UserInfoData{}, f.err
	}
	return f.data, nil
}

// buildClaims is a convenience to construct valid-looking AccessClaims
// for tests. Only sub + scope are load-bearing; the verifier already
// validated exp/nbf/iss upstream.
func buildClaims(sub, scope string) *tokens.AccessClaims {
	return &tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: sub,
			},
		},
		Scope: scope,
	}
}

// --- tests ---

func TestUserInfo_HappyPath_OpenIDOnlyReturnsSubOnly(t *testing.T) {
	// Token has openid scope but not email — response must include sub
	// and nothing else. This is the OIDC Core §5.3.2 "filter by scope"
	// contract.
	uid := uuid.New()
	cfg := oidc.UserInfoConfig{
		Verifier: &fakeVerifier{claims: buildClaims(uid.String(), "openid")},
		UserStore: &fakeUserStore{data: oidc.UserInfoData{
			ID:            uid,
			Email:         "alice@example.com",
			EmailVerified: true,
		}},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body=%s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["sub"] != uid.String() {
		t.Errorf("sub = %v, want %q", body["sub"], uid)
	}
	if _, present := body["email"]; present {
		t.Error("email must NOT appear without email scope")
	}
	if _, present := body["email_verified"]; present {
		t.Error("email_verified must NOT appear without email scope")
	}
}

func TestUserInfo_EmailScopePopulatesEmailClaims(t *testing.T) {
	uid := uuid.New()
	cfg := oidc.UserInfoConfig{
		Verifier: &fakeVerifier{claims: buildClaims(uid.String(), "openid email")},
		UserStore: &fakeUserStore{data: oidc.UserInfoData{
			ID:            uid,
			Email:         "alice@example.com",
			EmailVerified: true,
		}},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body["email"] != "alice@example.com" {
		t.Errorf("email = %v", body["email"])
	}
	if body["email_verified"] != true {
		t.Errorf("email_verified = %v, want true", body["email_verified"])
	}
}

func TestUserInfo_MissingTokenReturns401WithChallenge(t *testing.T) {
	cfg := oidc.UserInfoConfig{
		Verifier:  &fakeVerifier{},
		UserStore: &fakeUserStore{},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	// no Authorization header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	ch := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(ch, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q, want Bearer challenge", ch)
	}
	// No error= field on the "missing token" case per RFC 6750.
	if strings.Contains(ch, "error=") {
		t.Errorf("missing-token challenge should not include error=; got %q", ch)
	}
}

func TestUserInfo_MalformedAuthHeaderReturns401(t *testing.T) {
	cfg := oidc.UserInfoConfig{
		Verifier:  &fakeVerifier{},
		UserStore: &fakeUserStore{},
	}
	h := oidc.UserInfoHandler(cfg)

	cases := []string{
		"",               // empty
		"Basic abc",      // wrong scheme
		"Bearer",         // no space, no token
		"Bearer  ",       // only whitespace after scheme
		"bearerabc",      // no space separator
	}
	for _, hdr := range cases {
		t.Run(hdr, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
			if hdr != "" {
				req.Header.Set("Authorization", hdr)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("header=%q: status = %d, want 401", hdr, rec.Code)
			}
		})
	}
}

func TestUserInfo_InvalidTokenReturns401WithErrorInvalidToken(t *testing.T) {
	cfg := oidc.UserInfoConfig{
		Verifier:  &fakeVerifier{err: tokens.ErrInvalidToken},
		UserStore: &fakeUserStore{},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer tampered")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	ch := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(ch, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want error=\"invalid_token\"", ch)
	}
}

// Case-insensitive scheme match per RFC 6750 §2.1 ("case insensitive
// matching of the scheme name"). "bearer foo" must work.
func TestUserInfo_LowercaseBearerAccepted(t *testing.T) {
	uid := uuid.New()
	cfg := oidc.UserInfoConfig{
		Verifier: &fakeVerifier{claims: buildClaims(uid.String(), "openid")},
		UserStore: &fakeUserStore{data: oidc.UserInfoData{ID: uid}},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("lowercase bearer: status = %d, want 200", rec.Code)
	}
}

// Missing openid scope: 403 + insufficient_scope. The access token was
// otherwise valid, but /userinfo requires openid per OIDC Core §5.3.
func TestUserInfo_MissingOpenIDScopeReturns403(t *testing.T) {
	uid := uuid.New()
	cfg := oidc.UserInfoConfig{
		Verifier:  &fakeVerifier{claims: buildClaims(uid.String(), "read:docs")},
		UserStore: &fakeUserStore{data: oidc.UserInfoData{ID: uid}},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	ch := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(ch, `error="insufficient_scope"`) {
		t.Errorf("WWW-Authenticate = %q, want error=\"insufficient_scope\"", ch)
	}
	if !strings.Contains(ch, `scope="openid"`) {
		t.Errorf("WWW-Authenticate must advertise required scope: %q", ch)
	}
}

func TestUserInfo_UnparseableSubReturnsInvalidToken(t *testing.T) {
	cfg := oidc.UserInfoConfig{
		Verifier:  &fakeVerifier{claims: buildClaims("not-a-uuid", "openid")},
		UserStore: &fakeUserStore{},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// User deleted between token issuance and /userinfo call: 401 invalid_token.
// We deliberately don't surface "user not found" — treats the token as no
// longer valid, doesn't leak existence.
func TestUserInfo_UserLookupFailureReturns401(t *testing.T) {
	uid := uuid.New()
	cfg := oidc.UserInfoConfig{
		Verifier:  &fakeVerifier{claims: buildClaims(uid.String(), "openid")},
		UserStore: &fakeUserStore{err: errors.New("not found")},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	ch := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(ch, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q, want error=\"invalid_token\"", ch)
	}
}

// Response must have no-store Cache-Control — user claims are sensitive.
func TestUserInfo_ResponseIsNoStore(t *testing.T) {
	uid := uuid.New()
	cfg := oidc.UserInfoConfig{
		Verifier:  &fakeVerifier{claims: buildClaims(uid.String(), "openid")},
		UserStore: &fakeUserStore{data: oidc.UserInfoData{ID: uid}},
	}
	h := oidc.UserInfoHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}
