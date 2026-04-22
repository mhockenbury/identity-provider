package jwks_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhockenbury/identity-provider/internal/jwks"
	"github.com/mhockenbury/identity-provider/internal/oidc"
	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// --- test helpers ---

// fakeClock is a controllable time source — tests advance it to
// deterministically cross the RefreshInterval/StaleWindow boundaries.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeIdP is a minimal IdP stand-in serving /.well-known/openid-configuration
// and a JWKS endpoint. Tests swap the JWKS contents and count hits to
// assert cache behavior.
type fakeIdP struct {
	server       *httptest.Server
	mu           sync.Mutex
	jwks         tokens.JWKS
	discoveryHit int64
	jwksHit      int64
	failJWKS     bool // when true, JWKS endpoint returns 500
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.discoveryHit, 1)
		d := oidc.Discovery{
			Issuer:  f.server.URL,
			JWKSURI: f.server.URL + "/jwks.json",
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(d)
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.jwksHit, 1)
		f.mu.Lock()
		fail := f.failJWKS
		j := f.jwks
		f.mu.Unlock()
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(j)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIdP) setKeys(keys map[string]ed25519.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := tokens.JWKS{Keys: make([]tokens.JWK, 0, len(keys))}
	for kid, pub := range keys {
		out.Keys = append(out.Keys, tokens.JWK{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(pub),
			Kid: kid,
			Use: "sig",
			Alg: "EdDSA",
		})
	}
	f.jwks = out
}

func mustGenKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return pub
}

// --- tests ---

func TestResolve_FirstCall_FetchesAndReturns(t *testing.T) {
	idp := newFakeIdP(t)
	pub := mustGenKey(t)
	idp.setKeys(map[string]ed25519.PublicKey{"k1": pub})

	c := jwks.NewCache(jwks.Config{
		Issuer:          idp.server.URL,
		RefreshInterval: 10 * time.Minute,
		Clock:           &fakeClock{t: time.Now()},
	})

	got, err := c.Resolve(context.Background(), "k1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !pub.Equal(got) {
		t.Errorf("wrong key returned")
	}
	if atomic.LoadInt64(&idp.discoveryHit) != 1 {
		t.Errorf("expected 1 discovery hit, got %d", idp.discoveryHit)
	}
	if atomic.LoadInt64(&idp.jwksHit) != 1 {
		t.Errorf("expected 1 jwks hit, got %d", idp.jwksHit)
	}
}

func TestResolve_FreshCache_NoRefetch(t *testing.T) {
	idp := newFakeIdP(t)
	pub := mustGenKey(t)
	idp.setKeys(map[string]ed25519.PublicKey{"k1": pub})
	clk := &fakeClock{t: time.Now()}

	c := jwks.NewCache(jwks.Config{
		Issuer:          idp.server.URL,
		RefreshInterval: 10 * time.Minute,
		Clock:           clk,
	})

	// First resolve: fetches.
	if _, err := c.Resolve(context.Background(), "k1"); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	// Advance under the refresh interval.
	clk.advance(5 * time.Minute)
	// Second resolve: should NOT refetch.
	if _, err := c.Resolve(context.Background(), "k1"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := atomic.LoadInt64(&idp.jwksHit); got != 1 {
		t.Errorf("expected 1 jwks hit (cached), got %d", got)
	}
}

// Rotation scenario: the IdP has a new kid we've never seen. Cache miss
// on an unknown kid should trigger a refetch, and the new kid should
// resolve on retry. This is the core "downstream cache picks up rotation"
// learning objective.
func TestResolve_UnknownKid_TriggersRefetch(t *testing.T) {
	idp := newFakeIdP(t)
	oldPub := mustGenKey(t)
	idp.setKeys(map[string]ed25519.PublicKey{"old": oldPub})
	clk := &fakeClock{t: time.Now()}

	c := jwks.NewCache(jwks.Config{
		Issuer:          idp.server.URL,
		RefreshInterval: 10 * time.Minute,
		Clock:           clk,
	})

	// Prime cache with "old".
	if _, err := c.Resolve(context.Background(), "old"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	beforeHits := atomic.LoadInt64(&idp.jwksHit)

	// IdP rotates: "new" appears, "old" gone.
	newPub := mustGenKey(t)
	idp.setKeys(map[string]ed25519.PublicKey{"new": newPub})

	// Asking for "new" must trigger a refetch even though the cache is
	// still within RefreshInterval.
	got, err := c.Resolve(context.Background(), "new")
	if err != nil {
		t.Fatalf("post-rotation resolve: %v", err)
	}
	if !newPub.Equal(got) {
		t.Errorf("wrong key after rotation")
	}
	if afterHits := atomic.LoadInt64(&idp.jwksHit); afterHits != beforeHits+1 {
		t.Errorf("expected 1 refetch on unknown kid, got %d extra", afterHits-beforeHits)
	}
}

func TestResolve_UnknownKidAfterRefetch_Errors(t *testing.T) {
	idp := newFakeIdP(t)
	pub := mustGenKey(t)
	idp.setKeys(map[string]ed25519.PublicKey{"k1": pub})

	c := jwks.NewCache(jwks.Config{
		Issuer:          idp.server.URL,
		RefreshInterval: 10 * time.Minute,
		Clock:           &fakeClock{t: time.Now()},
	})

	_, err := c.Resolve(context.Background(), "never-existed")
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
	// The error should be wrappable as ErrUnknownKID so callers can
	// distinguish this from a network failure.
	if !errorsIs(err, jwks.ErrUnknownKID) {
		t.Errorf("expected ErrUnknownKID, got %v", err)
	}
}

// Stale-if-error: after RefreshInterval, a failed refresh should still
// serve the last-known-good JWKS until StaleWindow elapses.
func TestResolve_StaleIfError(t *testing.T) {
	idp := newFakeIdP(t)
	pub := mustGenKey(t)
	idp.setKeys(map[string]ed25519.PublicKey{"k1": pub})
	clk := &fakeClock{t: time.Now()}

	c := jwks.NewCache(jwks.Config{
		Issuer:          idp.server.URL,
		RefreshInterval: 10 * time.Minute,
		StaleWindow:     1 * time.Hour,
		Clock:           clk,
	})

	// Initial fetch succeeds.
	if _, err := c.Resolve(context.Background(), "k1"); err != nil {
		t.Fatalf("initial: %v", err)
	}

	// Flip the IdP to failing. Advance past RefreshInterval so the next
	// Resolve triggers a refresh.
	idp.mu.Lock()
	idp.failJWKS = true
	idp.mu.Unlock()
	clk.advance(15 * time.Minute) // past refresh interval, inside stale window

	// Should still serve k1 from stale cache.
	got, err := c.Resolve(context.Background(), "k1")
	if err != nil {
		t.Fatalf("stale resolve: %v", err)
	}
	if !pub.Equal(got) {
		t.Errorf("wrong key from stale cache")
	}

	// Advance past the stale window — cache should now hard-fail.
	clk.advance(2 * time.Hour)
	if _, err := c.Resolve(context.Background(), "k1"); err == nil {
		t.Error("expected error after stale window expired")
	}
}

// Integration with tokens.Verifier: a real JWT verifier wired with a
// jwks.Cache should accept a token signed by a key the cache just
// fetched.
func TestIntegration_VerifierAcceptsFetchedKey(t *testing.T) {
	idp := newFakeIdP(t)

	// Generate a real keypair; IdP publishes pub, we sign a token with priv.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	idp.setKeys(map[string]ed25519.PublicKey{"k1": pub})

	cache := jwks.NewCache(jwks.Config{
		Issuer:          idp.server.URL,
		RefreshInterval: 10 * time.Minute,
		Clock:           &fakeClock{t: time.Now()},
	})

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{idp.server.URL: cache},
		"docs-api",
		nil,
	)

	// Sign a token using the private key with kid=k1.
	raw := signTestJWT(t, priv, "k1", idp.server.URL, "docs-api", "u-123")

	claims, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "u-123" {
		t.Errorf("Subject = %q", claims.Subject)
	}
}

// --- low-dependency JWT signer for the integration test above ---
//
// We avoid pulling in the tokens.Signer here because that would require a
// KeyStore + KEK setup. Just hand-crank an EdDSA JWT.

func signTestJWT(t *testing.T, priv ed25519.PrivateKey, kid, iss, aud, sub string) string {
	t.Helper()
	header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}
	now := time.Now().Unix()
	payload := map[string]any{
		"iss": iss,
		"aud": aud,
		"sub": sub,
		"iat": now,
		"nbf": now,
		"exp": now + 300,
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	signing := h + "." + p
	sig := ed25519.Sign(priv, []byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// errors.Is without importing errors in test body (keeps imports tidy).
func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Sanity: catch accidental import removal.
var _ = fmt.Sprintf
