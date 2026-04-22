package http

import (
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/gorilla/csrf"
)

// CSRF protection wraps POST /login and POST /consent. Without this a
// third-party site could auto-submit <form action="https://idp/consent"
// method="POST"> and grant scopes on a logged-in user's behalf.
//
// Using gorilla/csrf for the primitives: it handles the cookie/token
// plumbing and the constant-time compare. We wrap it thinly so our
// handler code can call a single CSRFMiddleware(authKey, secure) and
// templates can read the per-request token via csrf.TemplateField.

// CSRFKeyLength is the required length for the authentication key in
// bytes. gorilla/csrf recommends 32.
const CSRFKeyLength = 32

// CSRFMiddleware returns a middleware that enforces CSRF on unsafe
// methods (POST/PUT/PATCH/DELETE). GET/HEAD/OPTIONS pass through.
//
// authKey must be 32 bytes. Pass hex-decoded env var contents.
// secure is true when the IdP is served over https.
//
// Per gorilla/csrf docs, the middleware sets a cookie on every response
// carrying an HMAC-signed token. Handlers render a hidden form field
// with csrf.Token(r) (or csrf.TemplateField(r) inside html/template);
// the library verifies that the form field equals the cookie.
//
// SameSite=Lax is set because our session cookie uses the same mode and
// we want the token cookie to mirror it.
//
// When secure=false we additionally tell gorilla/csrf that the request
// is plaintext HTTP via PlaintextHTTPRequest. Otherwise gorilla enforces
// a strict TLS-oriented Referer check that rejects every POST we make
// in dev (the check is meant to defend against HTTP-MITM injecting forms
// when the IdP is ostensibly TLS; when we KNOW the deployment is plaintext
// HTTP, the check is a false positive).
func CSRFMiddleware(authKey []byte, secure bool) func(http.Handler) http.Handler {
	protect := csrf.Protect(
		authKey,
		csrf.Secure(secure),
		csrf.SameSite(csrf.SameSiteLaxMode),
		csrf.HttpOnly(true),
		csrf.Path("/"),
	)

	if secure {
		return protect
	}
	// HTTP deployment: wrap each request to set the plaintext context flag
	// BEFORE gorilla's protect middleware inspects it.
	return func(next http.Handler) http.Handler {
		wrapped := protect(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapped.ServeHTTP(w, csrf.PlaintextHTTPRequest(r))
		})
	}
}

// ParseCSRFKey parses a hex-encoded 32-byte key, the shape we want env
// vars to carry. Separate from CSRFMiddleware so config loading can
// fail loudly at startup rather than silently at first request.
func ParseCSRFKey(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("csrf key hex decode: %w", err)
	}
	if len(b) != CSRFKeyLength {
		return nil, fmt.Errorf("csrf key length = %d, want %d bytes (%d hex chars)",
			len(b), CSRFKeyLength, CSRFKeyLength*2)
	}
	return b, nil
}
