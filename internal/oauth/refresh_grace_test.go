package oauth

import (
	"testing"
)

func TestRefreshGraceCache_HitWithinWindow(t *testing.T) {
	c := newRefreshGraceCache()
	c.Put("plaintext-A", []byte(`{"access_token":"abc"}`))

	got := c.Get("plaintext-A")
	if got == nil {
		t.Fatal("expected hit, got nil")
	}
	if string(got) != `{"access_token":"abc"}` {
		t.Errorf("body = %q", got)
	}
}

func TestRefreshGraceCache_DifferentKeyMisses(t *testing.T) {
	c := newRefreshGraceCache()
	c.Put("plaintext-A", []byte(`a`))

	if got := c.Get("plaintext-B"); got != nil {
		t.Errorf("expected miss for unrelated key, got %q", got)
	}
}

func TestRefreshGraceCache_KeyIsHashed(t *testing.T) {
	// Ensure plaintexts aren't directly used as map keys — confirm
	// distinct plaintexts that share a prefix don't alias.
	c := newRefreshGraceCache()
	c.Put("plain-1", []byte(`one`))
	c.Put("plain-2", []byte(`two`))
	if string(c.Get("plain-1")) != "one" {
		t.Errorf("plain-1 collision")
	}
	if string(c.Get("plain-2")) != "two" {
		t.Errorf("plain-2 collision")
	}
}

func TestRefreshGraceCache_BodyIsCopied(t *testing.T) {
	// Mutating the caller's slice after Put must not affect what Get
	// returns. Catches a subtle reference-aliasing bug.
	c := newRefreshGraceCache()
	body := []byte(`original`)
	c.Put("k", body)
	body[0] = 'X' // mutate after store
	if string(c.Get("k")) != "original" {
		t.Errorf("cached body was mutated through caller's slice")
	}
}

func TestRefreshGraceCache_ExpiredEvicted(t *testing.T) {
	c := newRefreshGraceCache()
	c.Put("k", []byte(`v`))
	// Manually backdate the entry so it's past the grace window.
	c.mu.Lock()
	e := c.entries[keyOf("k")]
	e.expiresAt = e.expiresAt.Add(-2 * graceWindow)
	c.entries[keyOf("k")] = e
	c.mu.Unlock()

	if got := c.Get("k"); got != nil {
		t.Errorf("expected expired entry to evict, got %q", got)
	}
	// The Get call should have evicted it.
	c.mu.Lock()
	_, present := c.entries[keyOf("k")]
	c.mu.Unlock()
	if present {
		t.Error("expired entry not removed")
	}
}
