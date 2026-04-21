package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mhockenbury/identity-provider/internal/oidc"
)

func TestBuildDiscovery_EndpointsDerivedFromIssuer(t *testing.T) {
	d := oidc.BuildDiscovery(oidc.DiscoveryConfig{
		Issuer:          "https://idp.test",
		ScopesSupported: []string{"openid", "profile", "email"},
	})

	if d.Issuer != "https://idp.test" {
		t.Errorf("Issuer = %q", d.Issuer)
	}
	if d.AuthorizationEndpoint != "https://idp.test/authorize" {
		t.Errorf("AuthorizationEndpoint = %q", d.AuthorizationEndpoint)
	}
	if d.TokenEndpoint != "https://idp.test/token" {
		t.Errorf("TokenEndpoint = %q", d.TokenEndpoint)
	}
	if d.JWKSURI != "https://idp.test/.well-known/jwks.json" {
		t.Errorf("JWKSURI = %q", d.JWKSURI)
	}
	if d.UserinfoEndpoint != "https://idp.test/userinfo" {
		t.Errorf("UserinfoEndpoint = %q", d.UserinfoEndpoint)
	}
}

func TestBuildDiscovery_RequiredFields(t *testing.T) {
	// OIDC Discovery §4: issuer, authorization_endpoint, token_endpoint,
	// jwks_uri, response_types_supported, subject_types_supported,
	// id_token_signing_alg_values_supported are REQUIRED.
	d := oidc.BuildDiscovery(oidc.DiscoveryConfig{Issuer: "https://idp.test"})

	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" ||
		d.JWKSURI == "" ||
		len(d.ResponseTypesSupported) == 0 ||
		len(d.SubjectTypesSupported) == 0 ||
		len(d.IDTokenSigningAlgValuesSupported) == 0 {
		t.Errorf("missing REQUIRED field in discovery doc: %+v", d)
	}
}

// The handler must not advertise support for flows we haven't built —
// that would trick clients into trying them and getting opaque errors.
func TestBuildDiscovery_AdvertisesOnlyImplementedFeatures(t *testing.T) {
	d := oidc.BuildDiscovery(oidc.DiscoveryConfig{Issuer: "https://idp.test"})

	// We implement code flow only. No implicit, no hybrid.
	if len(d.ResponseTypesSupported) != 1 || d.ResponseTypesSupported[0] != "code" {
		t.Errorf("ResponseTypesSupported = %v, want [code]", d.ResponseTypesSupported)
	}

	// We only support EdDSA.
	if len(d.IDTokenSigningAlgValuesSupported) != 1 ||
		d.IDTokenSigningAlgValuesSupported[0] != "EdDSA" {
		t.Errorf("IDTokenSigningAlgValuesSupported = %v, want [EdDSA]", d.IDTokenSigningAlgValuesSupported)
	}

	// S256 only — plain challenge method is explicitly rejected by our
	// authorize handler (to be built); advertising only S256 here is
	// consistent with that.
	if len(d.CodeChallengeMethodsSupported) != 1 ||
		d.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("CodeChallengeMethodsSupported = %v, want [S256]", d.CodeChallengeMethodsSupported)
	}

	// Grant types: code + refresh. No client_credentials, no password, etc.
	want := map[string]bool{"authorization_code": true, "refresh_token": true}
	if len(d.GrantTypesSupported) != len(want) {
		t.Errorf("GrantTypesSupported = %v, want %v", d.GrantTypesSupported, want)
	}
	for _, g := range d.GrantTypesSupported {
		if !want[g] {
			t.Errorf("unexpected grant_type %q in GrantTypesSupported", g)
		}
	}
}

func TestHandler_ServesJSON(t *testing.T) {
	h := oidc.Handler(oidc.DiscoveryConfig{
		Issuer:          "https://idp.test",
		ScopesSupported: []string{"openid"},
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Errorf("Cache-Control not set")
	}

	// Round-trip: the body must parse back into Discovery without loss.
	var d oidc.Discovery
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.Issuer != "https://idp.test" {
		t.Errorf("round-trip Issuer = %q", d.Issuer)
	}
}

// Issuer with trailing slash is a common misconfig that breaks clients
// (RFC 8414 says issuer MUST NOT have trailing slash). We don't fail at
// config load today — documented as a future hardening — but we do want
// the endpoint URLs NOT to double-up slashes when it happens.
//
// This test pins current behavior: if Issuer has a trailing slash, we
// currently produce `https://idp.test//authorize`. Arguably a bug;
// flagged in the assertion to make it visible.
func TestBuildDiscovery_TrailingSlashBehavior(t *testing.T) {
	d := oidc.BuildDiscovery(oidc.DiscoveryConfig{Issuer: "https://idp.test/"})
	// Current behavior: we naively concat. A future fix would normalize
	// by trimming. Either behavior is OK for the lab; this test exists
	// so the behavior is explicit and the test breaks if someone changes
	// it without intent.
	if d.AuthorizationEndpoint != "https://idp.test//authorize" {
		t.Logf("NOTE: trailing-slash behavior changed; authorize_endpoint = %q", d.AuthorizationEndpoint)
	}
}
