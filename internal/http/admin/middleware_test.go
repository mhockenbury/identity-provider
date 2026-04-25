package admin

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/tokens"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// staticResolver is a tokens.KeyResolver with one key. Avoids JWKS HTTP.
type staticResolver struct {
	keys map[string]ed25519.PublicKey
}

func (s *staticResolver) Resolve(_ context.Context, kid string) (ed25519.PublicKey, error) {
	k, ok := s.keys[kid]
	if !ok {
		return nil, tokens.ErrUnknownKID
	}
	return k, nil
}

// memUserStore is a minimal users.Store for the auth tests. Only
// implements GetByID; other methods panic so a test that hits them
// fails loudly.
type memUserStore struct {
	users map[uuid.UUID]users.User
}

func (m *memUserStore) GetByID(_ context.Context, id uuid.UUID) (users.User, error) {
	u, ok := m.users[id]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return u, nil
}
func (m *memUserStore) Create(context.Context, string, string) (users.User, error) {
	panic("not used in tests")
}
func (m *memUserStore) GetByEmail(context.Context, string) (users.User, error) {
	panic("not used in tests")
}
func (m *memUserStore) List(context.Context) ([]users.User, error) {
	panic("not used in tests")
}
func (m *memUserStore) SetAdmin(context.Context, uuid.UUID, bool) error {
	panic("not used in tests")
}
func (m *memUserStore) Authenticate(context.Context, string, string) (users.User, error) {
	panic("not used in tests")
}

// signJWT mints an EdDSA JWT for testing without dragging in the IdP signer.
func signJWT(t *testing.T, priv ed25519.PrivateKey, kid, iss, aud, sub, scope string, exp time.Time) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}
	now := time.Now().Unix()
	payload := map[string]any{
		"iss":   iss,
		"aud":   aud,
		"sub":   sub,
		"scope": scope,
		"iat":   now,
		"nbf":   now,
		"exp":   exp.Unix(),
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	signing := h + "." + p
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// fixture builds a verifier + user store wired together for the tests.
// Returns (verifier, store, signing-priv, kid, admin-user-id).
func fixture(t *testing.T, isAdmin bool) (*tokens.Verifier, *memUserStore, ed25519.PrivateKey, string, uuid.UUID) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	kid := "k1"
	res := &staticResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	v := tokens.NewVerifier(map[string]tokens.KeyResolver{"http://idp": res}, "", nil)

	uid := uuid.New()
	store := &memUserStore{users: map[uuid.UUID]users.User{
		uid: {ID: uid, Email: "alice@example.com", IsAdmin: isAdmin},
	}}
	return v, store, priv, kid, uid
}

func okHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}
}

func TestAuthenticate_NoBearer_401(t *testing.T) {
	v, store, _, _, _ := fixture(t, true)
	h := Authenticate(v, store)(okHandler())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthenticate_NoAdminScope_403(t *testing.T) {
	v, store, priv, kid, uid := fixture(t, true)
	tok := signJWT(t, priv, kid, "http://idp", "anything", uid.String(),
		"openid email", time.Now().Add(5*time.Minute))
	h := Authenticate(v, store)(okHandler())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestAuthenticate_AdminScopeButNotIsAdmin_403(t *testing.T) {
	v, store, priv, kid, uid := fixture(t, false) // is_admin=false
	tok := signJWT(t, priv, kid, "http://idp", "anything", uid.String(),
		"openid admin", time.Now().Add(5*time.Minute))
	h := Authenticate(v, store)(okHandler())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (defense-in-depth: token has scope but DB says not admin)", w.Code)
	}
}

func TestAuthenticate_HappyPath_200(t *testing.T) {
	v, store, priv, kid, uid := fixture(t, true)
	tok := signJWT(t, priv, kid, "http://idp", "anything", uid.String(),
		"openid admin", time.Now().Add(5*time.Minute))
	h := Authenticate(v, store)(okHandler())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, body = %q", w.Code, w.Body.String())
	}
}

func TestHasScope_Boundary(t *testing.T) {
	cases := []struct {
		scope, want string
		expected    bool
	}{
		{"openid email admin", "admin", true},
		{"openid email", "admin", false},
		{"", "admin", false},
		{"admin", "", false},
		// Exact match required — no hierarchical "admin:users" → "admin".
		{"admin:users", "admin", false},
	}
	for _, tc := range cases {
		got := hasScope(tc.scope, tc.want)
		if got != tc.expected {
			t.Errorf("hasScope(%q, %q) = %v, want %v", tc.scope, tc.want, got, tc.expected)
		}
	}
}
