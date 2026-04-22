// Package jwks implements an HTTP-fetched JWKS cache that satisfies
// tokens.KeyResolver. It is the downstream-service counterpart to the
// IdP's tokens.KeyStoreResolver:
//
//   - IdP verifying its own tokens: KeyStoreResolver reads the DB
//   - Downstream service (docs-api): jwks.Cache fetches + caches over HTTP
//
// One Cache instance per trusted issuer. The Verifier holds a map of
// {issuer → KeyResolver}, so each Cache only answers for one issuer's
// keys.
//
// Behavior:
//
//   - On first Resolve, fetches /.well-known/openid-configuration to get
//     the jwks_uri, then fetches the JWKS, then serves keys by kid.
//   - On cache miss (unknown kid), triggers a refetch — this is the
//     "IdP rotated keys" path. If the new JWKS has the kid, we resolve
//     successfully. If not, ErrUnknownKID.
//   - After RefreshInterval, the cache is considered stale and the next
//     Resolve triggers a background-free lazy refresh.
//   - If refresh fails and we have a cached JWKS within StaleWindow, we
//     keep serving. This is "stale-if-error": network blips shouldn't
//     break token validation.
//   - All fetches respect the caller's context (so Verifier's per-request
//     context flows through to HTTP calls).
//
// What this is NOT:
//
//   - No background goroutines. Keeps the lifecycle simple — the Cache
//     is live as long as Resolve is being called, and garbage-collects
//     cleanly when the docs-api process exits.
//   - Not a general-purpose JWKS library. Only handles EdDSA/Ed25519
//     keys — matches what our IdP issues. A production cache would
//     delegate key parsing to a proper JOSE lib.
package jwks

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mhockenbury/identity-provider/internal/oidc"
	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// ErrUnknownKID is returned when a kid isn't present in the cached JWKS
// AND a refetch didn't turn it up. tokens.Verifier maps this to
// tokens.ErrUnknownKID via its keyfunc indirection — test coverage in
// internal/tokens/jwt_test.go exercises that mapping.
var ErrUnknownKID = errors.New("jwks: unknown kid")

// Clock is the time abstraction used for TTL + stale-window logic.
// Exported so tests can inject a fake clock.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

// Config configures a Cache.
type Config struct {
	// Issuer is the issuer URL. The cache appends
	// /.well-known/openid-configuration to fetch discovery. MUST match the
	// `iss` claim on tokens this cache validates.
	Issuer string

	// RefreshInterval is how long a successfully-fetched JWKS is served
	// before a proactive refresh. 10m is a reasonable default — short
	// enough to pick up rotations promptly, long enough to not hammer
	// the IdP.
	RefreshInterval time.Duration

	// StaleWindow is how long we'll keep serving a cached JWKS when
	// refresh fails. Protects against IdP blips. Set to 0 to disable
	// (strict freshness — any refresh failure is a hard error).
	StaleWindow time.Duration

	// HTTPClient fetches discovery + JWKS. nil → http.DefaultClient with
	// a 5s timeout wrapper. Tests inject a client pointing at an httptest
	// server.
	HTTPClient *http.Client

	// Clock lets tests inject deterministic time. nil → real clock.
	Clock Clock
}

// Cache holds the current JWKS for one issuer. Safe for concurrent use.
//
// The cache state moves between three conceptual states:
//
//	uninitialized           — no fetch yet; first Resolve triggers it
//	fresh (age < refresh)   — serve from cache; Resolve is map-lookup fast
//	stale (age > refresh)   — next Resolve triggers refetch
//	                          (if refetch fails: serve stale until StaleWindow)
//
// The lock discipline is simple: RLock for lookups, Lock for refresh. A
// refetch does a double-check under the write lock to coalesce concurrent
// misses to a single upstream request.
type Cache struct {
	cfg  Config
	http *http.Client

	mu          sync.RWMutex
	jwksURI     string                       // learned from discovery
	keys        map[string]ed25519.PublicKey // kid -> key
	lastFetched time.Time                    // zero = never
	lastErr     error                        // last refresh error (for stale-if-error decisions)
}

// NewCache builds a Cache. Always succeeds — the first HTTP fetch is
// lazy, on the first Resolve call. That way constructing a verifier at
// startup doesn't block on the IdP being reachable.
func NewCache(cfg Config) *Cache {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 10 * time.Minute
	}
	if cfg.StaleWindow < 0 {
		cfg.StaleWindow = 0
	}
	if cfg.Clock == nil {
		cfg.Clock = wallClock{}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	return &Cache{
		cfg:  cfg,
		http: hc,
		keys: map[string]ed25519.PublicKey{},
	}
}

// Resolve implements tokens.KeyResolver.
//
// Fast path: cached, fresh, kid hits → return without lock contention.
// Slow path: stale-or-missing kid → refetch under the write lock.
//
// Unknown kid after a refetch → ErrUnknownKID. Callers (specifically
// tokens.Verifier) map this to their own ErrUnknownKID sentinel so
// handlers can distinguish "refetch was attempted" from other failures.
func (c *Cache) Resolve(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	now := c.cfg.Clock.Now()

	c.mu.RLock()
	k, hit := c.keys[kid]
	age := now.Sub(c.lastFetched)
	initialized := !c.lastFetched.IsZero()
	c.mu.RUnlock()

	// Fast path: hit AND fresh.
	if hit && initialized && age < c.cfg.RefreshInterval {
		return k, nil
	}

	// Slow path: need a refetch. Either:
	//   - never fetched (initialized=false)
	//   - fetched but stale (age >= RefreshInterval)
	//   - fetched fresh but kid missing (likely rotation; refetch and retry)
	//
	// A kid miss while the cache is still fresh must force a refetch —
	// otherwise refresh()'s coalescing check would skip it.
	force := initialized && !hit
	if err := c.refresh(ctx, force); err != nil {
		// Refresh failed. Can we serve stale?
		c.mu.RLock()
		k, hit = c.keys[kid]
		ageAfter := now.Sub(c.lastFetched)
		c.mu.RUnlock()
		if hit && c.cfg.StaleWindow > 0 && ageAfter < c.cfg.RefreshInterval+c.cfg.StaleWindow {
			return k, nil
		}
		return nil, fmt.Errorf("jwks refresh: %w", err)
	}

	c.mu.RLock()
	k, hit = c.keys[kid]
	c.mu.RUnlock()
	if !hit {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
	}
	return k, nil
}

// refresh fetches discovery (if we don't have jwks_uri yet) and JWKS,
// and atomically swaps the cache.
//
// Coalesces concurrent refreshes: if another goroutine already did a
// refetch while this one was waiting for the write lock, we skip the
// HTTP call — UNLESS force is set, which is how Resolve asks us to
// bypass coalescing for the unknown-kid-while-fresh case.
func (c *Cache) refresh(ctx context.Context, force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check: maybe another goroutine refreshed while we blocked.
	now := c.cfg.Clock.Now()
	if !force && !c.lastFetched.IsZero() && now.Sub(c.lastFetched) < c.cfg.RefreshInterval {
		return nil
	}

	// Resolve jwks_uri the first time, or if the URL base changed (which
	// we don't currently detect; it's a rare config-time event).
	if c.jwksURI == "" {
		uri, err := c.fetchDiscovery(ctx)
		if err != nil {
			c.lastErr = err
			return fmt.Errorf("fetch discovery: %w", err)
		}
		c.jwksURI = uri
	}

	keys, err := c.fetchJWKS(ctx, c.jwksURI)
	if err != nil {
		c.lastErr = err
		return fmt.Errorf("fetch jwks: %w", err)
	}

	c.keys = keys
	c.lastFetched = now
	c.lastErr = nil
	return nil
}

// fetchDiscovery hits the standard well-known URL and returns jwks_uri.
func (c *Cache) fetchDiscovery(ctx context.Context) (string, error) {
	url := strings.TrimRight(c.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var d oidc.Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return "", fmt.Errorf("decode discovery: %w", err)
	}
	if d.JWKSURI == "" {
		return "", fmt.Errorf("discovery missing jwks_uri")
	}
	return d.JWKSURI, nil
}

// fetchJWKS hits the jwks_uri, parses the response into keys keyed by kid.
// Skips JWK entries that aren't Ed25519 (we only issue EdDSA) — a real
// production cache would support the full key-type matrix.
func (c *Cache) fetchJWKS(ctx context.Context, url string) (map[string]ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	j, err := tokens.ParseJWKS(body)
	if err != nil {
		return nil, err
	}

	out := make(map[string]ed25519.PublicKey, len(j.Keys))
	for _, k := range j.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue // not ours
		}
		pub, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("parse kid %q: %w", k.Kid, err)
		}
		out[k.Kid] = pub
	}
	return out, nil
}

// static assertion — we implement tokens.KeyResolver.
var _ tokens.KeyResolver = (*Cache)(nil)
