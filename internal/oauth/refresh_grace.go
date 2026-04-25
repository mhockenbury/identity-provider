package oauth

// refreshGraceCache stores the just-minted token response for a recently
// rotated refresh token. If the same refresh-token plaintext is presented
// twice within the grace window — the canonical race when a browser SPA
// fires multiple parallel renewals — we return the cached response
// instead of returning invalid_grant.
//
// Pattern documented by Okta and Auth0 as the way to make rotating
// refresh tokens robust against real-world client races. OAuth 2.1 BCP
// (draft) explicitly allows it provided the window is short and bounded.
//
// In-memory only; lost on restart. That's a deliberate cost/complexity
// trade-off — a 30s window through a restart is rare and the worst case
// (one client gets invalid_grant and re-auths) is bounded.
//
// The cached value is the full marshaled JSON of the /token response,
// including the rotated refresh_token. Returning the SAME response on
// duplicate presentation means both racing clients converge on the
// same access_token + new refresh_token; whichever lands first will
// have the new refresh token in hand and the next rotation cycle works.

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// graceWindow is how long after a successful rotation we'll serve the
// cached response on a duplicate presentation. Long enough to cover
// browser-network latency races (~hundreds of ms), short enough that
// a stolen-token replay attack window stays small.
const graceWindow = 30 * time.Second

type cachedResponse struct {
	body      []byte // marshaled tokenResponse JSON
	expiresAt time.Time
}

// refreshGraceCache is a tiny TTL map. Concurrency-safe. Caller hashes
// the plaintext token before lookup/store so plaintexts never sit in
// the in-process map.
type refreshGraceCache struct {
	mu      sync.Mutex
	entries map[string]cachedResponse // key = sha256 hex of plaintext
}

func newRefreshGraceCache() *refreshGraceCache {
	return &refreshGraceCache{entries: map[string]cachedResponse{}}
}

// graceCache is the package-level shared cache used by handleRefresh.
// One per IdP process. Hashed keys, TTL-bounded values; safe enough
// to keep at module scope.
var graceCache = newRefreshGraceCache()

// Get returns the cached response if the key was recently consumed, or
// nil if not. Lazily evicts expired entries on access.
func (c *refreshGraceCache) Get(plaintext string) []byte {
	key := keyOf(plaintext)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return nil
	}
	return e.body
}

// Put records a freshly minted response for the just-consumed plaintext.
// Also opportunistically evicts a few expired entries — keeps memory
// bounded without a background goroutine.
func (c *refreshGraceCache) Put(plaintext string, body []byte) {
	key := keyOf(plaintext)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cachedResponse{
		body:      append([]byte(nil), body...),
		expiresAt: now.Add(graceWindow),
	}
	// Best-effort eviction: scan a few entries.
	scanned := 0
	for k, v := range c.entries {
		if scanned > 8 {
			break
		}
		if now.After(v.expiresAt) {
			delete(c.entries, k)
		}
		scanned++
	}
}

func keyOf(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
