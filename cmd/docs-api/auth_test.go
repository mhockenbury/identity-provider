package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// --- test helpers ---

// staticResolver is a KeyResolver with a fixed map, no HTTP. Lets the
// auth tests focus on middleware behavior rather than JWKS fetch paths
// (those are covered in internal/jwks/cache_test.go).
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

// buildVerifier wires a tokens.Verifier with a single issuer backed by a
// static key resolver. Returns the verifier plus the signing key so the
// test can mint tokens.
func buildVerifier(t *testing.T, iss, aud string) (*tokens.Verifier, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kid := "k1"
	res := &staticResolver{keys: map[string]ed25519.PublicKey{kid: pub}}
	v := tokens.NewVerifier(map[string]tokens.KeyResolver{iss: res}, aud, nil)
	return v, priv, kid
}

// signJWT hand-crafts an EdDSA JWT. Keeps the test self-contained —
// no dependency on the internal signer/KeyStore which would pull in
// DB setup.
func signJWT(t *testing.T, priv ed25519.PrivateKey, kid, iss, aud, sub, scope string, exp time.Time) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}
	payload := map[string]any{
		"iss":   iss,
		"aud":   aud,
		"sub":   sub,
		"scope": scope,
		"iat":   time.Now().Unix(),
		"nbf":   time.Now().Unix(),
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

// okHandler is what sits at the end of the middleware chain in tests.
// It asserts claims were populated in ctx (proving authenticate ran)
// and echoes the subject so tests can verify the right token was used.
func okHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		claims := claimsFromCtx(r.Context())
		if claims == nil {
			t.Error("expected claims in ctx")
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(claims.Subject))
	}
}

// --- bearerFromRequest ---

func TestBearerFromRequest(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		errSub string
	}{
		{"happy", "Bearer abc.def.ghi", "abc.def.ghi", ""},
		{"missing", "", "", "missing"},
		{"wrong scheme", "Basic dXNlcjpwYXNz", "", "Bearer"},
		{"empty token", "Bearer ", "", "empty"},
		{"trailing space trimmed", "Bearer abc.def.ghi  ", "abc.def.ghi", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			got, err := bearerFromRequest(r)
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// --- hasScope ---

func TestHasScope(t *testing.T) {
	cases := []struct {
		scope, want string
		expected    bool
	}{
		{"read:docs write:docs", "read:docs", true},
		{"read:docs write:docs", "write:docs", true},
		{"read:docs", "write:docs", false},
		{"", "read:docs", false},
		{"read:docs", "", false},
		// No hierarchical matching — "read" is NOT a subset of "read:docs".
		{"read:docs", "read", false},
		// Whitespace splitting handles tabs/newlines too (RFC tolerant).
		{"read:docs\twrite:docs", "write:docs", true},
	}
	for _, tc := range cases {
		if got := hasScope(tc.scope, tc.want); got != tc.expected {
			t.Errorf("hasScope(%q, %q) = %v, want %v", tc.scope, tc.want, got, tc.expected)
		}
	}
}

// --- authenticate ---

func TestAuthenticate_MissingHeader_401(t *testing.T) {
	v, _, _ := buildVerifier(t, "http://iss", "docs-api")
	h := authenticate(v)(okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q, want Bearer", got)
	}
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", body["error"])
	}
}

func TestAuthenticate_WrongScheme_401(t *testing.T) {
	v, _, _ := buildVerifier(t, "http://iss", "docs-api")
	h := authenticate(v)(okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Basic abc")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthenticate_HappyPath_PopulatesClaims(t *testing.T) {
	v, priv, kid := buildVerifier(t, "http://iss", "docs-api")
	tok := signJWT(t, priv, kid, "http://iss", "docs-api", "u-123", "read:docs", time.Now().Add(5*time.Minute))
	h := authenticate(v)(okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if got := w.Body.String(); got != "u-123" {
		t.Errorf("sub = %q, want u-123", got)
	}
}

func TestAuthenticate_ExpiredToken_401(t *testing.T) {
	v, priv, kid := buildVerifier(t, "http://iss", "docs-api")
	tok := signJWT(t, priv, kid, "http://iss", "docs-api", "u", "", time.Now().Add(-1*time.Minute))
	h := authenticate(v)(okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", body["error"])
	}
}

func TestAuthenticate_UnknownIssuer_401(t *testing.T) {
	v, priv, kid := buildVerifier(t, "http://iss", "docs-api")
	// Sign a token from a DIFFERENT issuer than the verifier trusts.
	tok := signJWT(t, priv, kid, "http://other", "docs-api", "u", "", time.Now().Add(5*time.Minute))
	h := authenticate(v)(okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAuthenticate_WrongAudience_401(t *testing.T) {
	v, priv, kid := buildVerifier(t, "http://iss", "docs-api")
	tok := signJWT(t, priv, kid, "http://iss", "other-api", "u", "", time.Now().Add(5*time.Minute))
	h := authenticate(v)(okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// --- requireScope ---

func TestRequireScope_HasScope_200(t *testing.T) {
	v, priv, kid := buildVerifier(t, "http://iss", "docs-api")
	tok := signJWT(t, priv, kid, "http://iss", "docs-api", "u", "read:docs write:docs", time.Now().Add(5*time.Minute))

	// Chain: authenticate → requireScope → ok.
	h := authenticate(v)(requireScope("write:docs")(okHandler(t)))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (body=%q)", w.Code, w.Body.String())
	}
}

func TestRequireScope_MissingScope_403(t *testing.T) {
	v, priv, kid := buildVerifier(t, "http://iss", "docs-api")
	tok := signJWT(t, priv, kid, "http://iss", "docs-api", "u", "read:docs", time.Now().Add(5*time.Minute))

	h := authenticate(v)(requireScope("write:docs")(okHandler(t)))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["error"] != "insufficient_scope" {
		t.Errorf("error = %q, want insufficient_scope", body["error"])
	}
}

func TestRequireScope_NoAuthMiddleware_500(t *testing.T) {
	// requireScope without a prior authenticate is a wiring bug. Make
	// sure we fail loudly rather than silently serving the handler.
	h := requireScope("read:docs")(okHandler(t))

	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
