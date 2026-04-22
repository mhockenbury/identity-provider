package http_test

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/csrf"

	myhttp "github.com/mhockenbury/identity-provider/internal/http"
)

func testCSRFKey(t *testing.T) []byte {
	t.Helper()
	// Deterministic 32 bytes for tests. Any fixed value works; we don't
	// need cryptographic freshness here, just a valid-length key.
	b, _ := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	return b
}

func TestParseCSRFKey_ValidHex(t *testing.T) {
	key, err := myhttp.ParseCSRFKey(hex.EncodeToString(testCSRFKey(t)))
	if err != nil {
		t.Fatalf("ParseCSRFKey: %v", err)
	}
	if len(key) != myhttp.CSRFKeyLength {
		t.Errorf("len = %d, want %d", len(key), myhttp.CSRFKeyLength)
	}
}

func TestParseCSRFKey_RejectsWrongShapes(t *testing.T) {
	cases := []string{
		"",                          // empty
		"not-hex",                   // not hex
		hex.EncodeToString([]byte("too-short")), // too few bytes
		strings.Repeat("aa", 33),    // too many bytes
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := myhttp.ParseCSRFKey(c)
			if err == nil {
				t.Errorf("expected error for %q", c)
			}
		})
	}
}

// POST with no CSRF token gets rejected by the middleware. Default 403
// per gorilla/csrf unless you override the error handler.
func TestCSRFMiddleware_POSTWithoutTokenRejected(t *testing.T) {
	var handlerRan bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRan = true
	})
	h := myhttp.CSRFMiddleware(testCSRFKey(t), false)(inner)

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if handlerRan {
		t.Error("inner handler should not run when CSRF check fails")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// GET request sets the CSRF cookie; a subsequent POST carrying that
// cookie AND the matching token in the form passes through.
//
// This mirrors what our real flow does: GET /login renders a form with
// csrf.TemplateField, the user's browser submits both the token and
// the cookie, and the middleware verifies they match.
func TestCSRFMiddleware_GETIssuesTokenPOSTAcceptsIt(t *testing.T) {
	// The "GET" path needs to echo the token out to the caller (a real
	// handler embeds it in HTML; we extract it by calling csrf.Token(r)
	// in the inner handler).
	var issuedToken string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuedToken = csrf.Token(r)
		_, _ = io.WriteString(w, issuedToken)
	})
	h := myhttp.CSRFMiddleware(testCSRFKey(t), false)(inner)

	// GET: obtain the csrf cookie + token.
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getRec.Code)
	}
	if issuedToken == "" {
		t.Fatal("expected csrf.Token to produce a token on GET")
	}

	// POST: carry both the cookie from the previous response AND the
	// token in the X-CSRF-Token header (gorilla accepts the header or
	// the form field). The Referer header is also REQUIRED by gorilla/csrf
	// for POST requests (defense against bare <form> cross-origin submits
	// that omit it); we set it to a same-origin URL.
	postReq := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(""))
	postReq.Header.Set("Referer", "http://example.test/login")
	for _, c := range getRec.Result().Cookies() {
		postReq.AddCookie(c)
	}
	postReq.Header.Set("X-CSRF-Token", issuedToken)

	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusOK {
		t.Errorf("POST status = %d, want 200 (body=%s)", postRec.Code, postRec.Body.String())
	}
}

// POST with a cookie from a DIFFERENT CSRF middleware instance (different
// keys → different tokens) must be rejected — this is the property that
// stops an attacker with a valid cookie from a different origin from
// forging a token.
func TestCSRFMiddleware_MismatchedTokenRejected(t *testing.T) {
	// Two separate middlewares with different keys. Token issued by A
	// must not validate against cookie + middleware B.
	keyA := testCSRFKey(t)
	keyB, _ := hex.DecodeString("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")

	var tokenA string
	innerA := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenA = csrf.Token(r)
	})
	hA := myhttp.CSRFMiddleware(keyA, false)(innerA)
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getRec := httptest.NewRecorder()
	hA.ServeHTTP(getRec, getReq)

	// Now submit tokenA against middleware B (different key).
	hB := myhttp.CSRFMiddleware(keyB, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not run; cross-key token must be rejected")
	}))
	postReq := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(""))
	postReq.Header.Set("Referer", "http://example.test/login")
	for _, c := range getRec.Result().Cookies() {
		postReq.AddCookie(c)
	}
	postReq.Header.Set("X-CSRF-Token", tokenA)
	postRec := httptest.NewRecorder()
	hB.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (cross-key token must fail)", postRec.Code)
	}
}
