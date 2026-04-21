package tokens_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// --- test fixtures ---

// fixedClock lets tests assert time-dependent behavior (exp, nbf, iat)
// without sleeping. The Verifier and Signer both accept a Clock.
type fixedClock struct{ t time.Time }

func (f *fixedClock) Now() time.Time { return f.t }
func (f *fixedClock) Advance(d time.Duration) {
	f.t = f.t.Add(d)
}

// staticResolver answers kid → public key from a fixed map. This is what
// the demo-api's JWKS cache will look like, minus the cache layer.
type staticResolver struct {
	keys map[string]ed25519.PublicKey
}

func (r *staticResolver) Resolve(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	pub, ok := r.keys[kid]
	if !ok {
		return nil, fmt.Errorf("kid %q not in resolver", kid)
	}
	return pub, nil
}

// signerFixture brings up a KeyStore with a pre-activated key and returns
// a Signer ready to use. The Verifier built from the same store can
// round-trip tokens.
type signerFixture struct {
	store    *tokens.KeyStore
	kek      tokens.KEK
	signer   *tokens.Signer
	activeKey *tokens.SigningKey
	clock    *fixedClock
	issuer   string
}

func newSignerFixture(t *testing.T, issuer string) *signerFixture {
	t.Helper()
	pool := testPool(t)
	kek := testKEK(t)
	store := tokens.NewKeyStore(pool, kek)

	k, err := store.Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cleanKey(t, pool, k.KID)
	if err := store.Activate(context.Background(), k.KID); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	clock := &fixedClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	signer := tokens.NewSigner(store, kek, issuer, clock)

	return &signerFixture{
		store: store, kek: kek, signer: signer,
		activeKey: k, clock: clock, issuer: issuer,
	}
}

// resolverFromFixture builds a KeyResolver that answers kid → pub for
// every key that's been generated in the store. Simulates a demo-api
// whose JWKS cache is fresh.
func resolverFromFixture(t *testing.T, f *signerFixture) *staticResolver {
	t.Helper()
	keys, err := f.store.ForJWKS(context.Background())
	if err != nil {
		t.Fatalf("ForJWKS: %v", err)
	}
	m := make(map[string]ed25519.PublicKey, len(keys))
	for _, k := range keys {
		m[k.KID] = k.PublicKey
	}
	return &staticResolver{keys: m}
}

// --- signing tests ---

func TestSignAccessToken_ProducesVerifiableJWT(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	claims := tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "user-alice",
				Audience: jwt.ClaimStrings{"demo-api"},
			},
		},
		Scope:    "read:docs write:docs",
		ClientID: "localdev",
	}
	raw, err := f.signer.SignAccessToken(ctx, claims, 15*time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if raw == "" {
		t.Fatal("got empty token")
	}

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{f.issuer: resolverFromFixture(t, f)},
		"demo-api",
		f.clock,
	)
	got, err := v.Verify(ctx, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject != "user-alice" {
		t.Errorf("Subject = %q, want user-alice", got.Subject)
	}
	if got.Scope != "read:docs write:docs" {
		t.Errorf("Scope = %q", got.Scope)
	}
	if got.ClientID != "localdev" {
		t.Errorf("ClientID = %q", got.ClientID)
	}
	if got.Issuer != f.issuer {
		t.Errorf("Issuer = %q", got.Issuer)
	}
}

func TestSignIDToken_CarriesNonceAndEmail(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	raw, err := f.signer.SignIDToken(ctx, tokens.IDClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  "user-alice",
				Audience: jwt.ClaimStrings{"client-localdev"},
			},
		},
		Nonce:         "n-0S6_WzA2Mj",
		AuthTime:      f.clock.Now().Unix(),
		Email:         "alice@example.com",
		EmailVerified: true,
	}, 5*time.Minute)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	// Parse as IDClaims through a verifier targeted at the ID-token audience.
	// We don't expose an "IDVerifier" — callers parse the token string with
	// the library directly when they need the OIDC-specific fields. Here
	// we use the raw parser to confirm the claims serialize correctly.
	token, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithTimeFunc(f.clock.Now),
	).Parse(raw, func(tok *jwt.Token) (any, error) {
		// Raw parse, using the known-good public key directly.
		return f.activeKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse id token: %v", err)
	}
	if !token.Valid {
		t.Fatal("id token not valid")
	}

	m := token.Claims.(jwt.MapClaims)
	if m["nonce"] != "n-0S6_WzA2Mj" {
		t.Errorf("nonce = %v", m["nonce"])
	}
	if m["email"] != "alice@example.com" {
		t.Errorf("email = %v", m["email"])
	}
	if m["email_verified"] != true {
		t.Errorf("email_verified = %v", m["email_verified"])
	}
	if m["auth_time"] == nil {
		t.Errorf("auth_time missing")
	}
}

func TestSign_NoActiveKeyReturnsError(t *testing.T) {
	// Signer with a KeyStore that has no active key → Signer.sign
	// returns the ErrNoActiveKey from the store.
	pool := testPool(t)
	kek := testKEK(t)
	store := tokens.NewKeyStore(pool, kek)
	signer := tokens.NewSigner(store, kek, "https://idp.test", nil)

	_, err := signer.SignAccessToken(context.Background(), tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{Subject: "x", Audience: jwt.ClaimStrings{"y"}},
		},
	}, time.Minute)
	if !errors.Is(err, tokens.ErrNoActiveKey) {
		t.Errorf("err = %v, want ErrNoActiveKey", err)
	}
}

// --- verification: the interesting part ---

func TestVerify_RejectsExpiredToken(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	raw, err := f.signer.SignAccessToken(ctx, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "u", Audience: jwt.ClaimStrings{"demo-api"},
			},
		},
	}, 1*time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	// Advance past expiry, then verify.
	f.clock.Advance(2 * time.Minute)

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{f.issuer: resolverFromFixture(t, f)},
		"demo-api",
		f.clock,
	)
	_, err = v.Verify(ctx, raw)
	if !errors.Is(err, tokens.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// Issuer allowlist: token signed by issuer A cannot verify against a
// verifier that trusts only issuer B. This is the multi-issuer gate.
func TestVerify_RejectsTokenFromUnknownIssuer(t *testing.T) {
	f := newSignerFixture(t, "https://idp-a.test")
	ctx := context.Background()

	raw, _ := f.signer.SignAccessToken(ctx, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "u", Audience: jwt.ClaimStrings{"demo-api"},
			},
		},
	}, time.Minute)

	// Verifier trusts ONLY idp-b, but the token was issued by idp-a.
	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{"https://idp-b.test": resolverFromFixture(t, f)},
		"demo-api",
		f.clock,
	)
	_, err := v.Verify(ctx, raw)
	if !errors.Is(err, tokens.ErrIssuerMismatch) {
		t.Errorf("err = %v, want ErrIssuerMismatch", err)
	}
}

// Multi-issuer: verifier trusts A and B, token is from B, must succeed.
// Mirrors the real multi-issuer deployment — "demo-api accepts tokens
// from our IdP *and* an upstream or sibling".
//
// Uses direct jwt-go signing (skipping the DB-backed Signer) for the
// "second" issuer because the DB can only host one active key at a time.
// The verifier doesn't care — it only sees the resulting JWT.
func TestVerify_AcceptsTokenFromAnyTrustedIssuer(t *testing.T) {
	fA := newSignerFixture(t, "https://idp-a.test")
	ctx := context.Background()

	// Build a second issuer "B" in-memory only.
	pubB, privB, _ := ed25519.GenerateKey(nil)
	kidB := "k_issuer-b-test"

	// Sign a token "as B" directly with jwt-go.
	tokenB := jwt.NewWithClaims(jwt.SigningMethodEdDSA, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://idp-b.test",
				Subject:   "u-from-b",
				Audience:  jwt.ClaimStrings{"demo-api"},
				ExpiresAt: jwt.NewNumericDate(fA.clock.Now().Add(time.Minute)),
				NotBefore: jwt.NewNumericDate(fA.clock.Now()),
				IssuedAt:  jwt.NewNumericDate(fA.clock.Now()),
			},
		},
		Scope: "read:docs",
	})
	tokenB.Header["kid"] = kidB
	raw, err := tokenB.SignedString(privB)
	if err != nil {
		t.Fatalf("sign from B: %v", err)
	}

	// Verifier trusts both, with separate key resolvers per issuer.
	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{
			"https://idp-a.test": resolverFromFixture(t, fA),
			"https://idp-b.test": &staticResolver{keys: map[string]ed25519.PublicKey{kidB: pubB}},
		},
		"demo-api",
		fA.clock,
	)
	got, err := v.Verify(ctx, raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Issuer != "https://idp-b.test" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
	if got.Subject != "u-from-b" {
		t.Errorf("Subject = %q", got.Subject)
	}
}

// Same `kid` across issuers: verifier picks the resolver by issuer, not by kid.
// Both IdPs intentionally advertise the same `kid` value; verification must
// still pick up the right public key via the per-issuer resolver. This is
// the subtle bit of multi-issuer that tutorials skip.
func TestVerify_SameKIDAcrossIssuersResolvedByIssuer(t *testing.T) {
	fA := newSignerFixture(t, "https://idp-a.test")

	// Build a second issuer B with its own key pair, but use the SAME kid
	// string as A's active key. If the verifier looked up kid first and
	// issuer second, it'd grab A's public key and signature would fail.
	pubB, privB, _ := ed25519.GenerateKey(nil)
	sharedKID := fA.activeKey.KID // same string!

	tokenB := jwt.NewWithClaims(jwt.SigningMethodEdDSA, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://idp-b.test",
				Subject:   "u-from-b",
				Audience:  jwt.ClaimStrings{"demo-api"},
				ExpiresAt: jwt.NewNumericDate(fA.clock.Now().Add(time.Minute)),
				NotBefore: jwt.NewNumericDate(fA.clock.Now()),
				IssuedAt:  jwt.NewNumericDate(fA.clock.Now()),
			},
		},
	})
	tokenB.Header["kid"] = sharedKID
	raw, err := tokenB.SignedString(privB)
	if err != nil {
		t.Fatalf("sign from B: %v", err)
	}

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{
			// A's resolver has A's key under sharedKID (that's its active key).
			"https://idp-a.test": resolverFromFixture(t, fA),
			// B's resolver has B's key under the same kid string.
			"https://idp-b.test": &staticResolver{keys: map[string]ed25519.PublicKey{sharedKID: pubB}},
		},
		"demo-api",
		fA.clock,
	)
	// Token claims iss=B → verifier must pick B's resolver → succeeds with B's key.
	got, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("expected success (verifier should pick B's resolver), got %v", err)
	}
	if got.Issuer != "https://idp-b.test" {
		t.Errorf("Issuer = %q", got.Issuer)
	}
}

// Audience must match. Token issued to aud=A, verifier expects aud=B.
func TestVerify_RejectsWrongAudience(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	raw, _ := f.signer.SignAccessToken(ctx, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "u", Audience: jwt.ClaimStrings{"service-A"},
			},
		},
	}, time.Minute)

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{f.issuer: resolverFromFixture(t, f)},
		"service-B", // different aud
		f.clock,
	)
	_, err := v.Verify(ctx, raw)
	if !errors.Is(err, tokens.ErrAudienceMissing) {
		t.Errorf("err = %v, want ErrAudienceMissing", err)
	}
}

// Forged token: attacker signs a token with their own key and tries to pass
// it off as from our IdP. Verification fails because the verifier looks up
// the "real" public key for that kid and signatures don't match.
func TestVerify_RejectsForgedToken(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	// Construct a token signed with a completely foreign key, but claim
	// the issuer + kid of our real IdP.
	forgedPub, forgedPriv, _ := ed25519.GenerateKey(nil)
	_ = forgedPub

	forged := jwt.NewWithClaims(jwt.SigningMethodEdDSA, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    f.issuer,
				Subject:   "u-forged",
				Audience:  jwt.ClaimStrings{"demo-api"},
				ExpiresAt: jwt.NewNumericDate(f.clock.Now().Add(time.Minute)),
				IssuedAt:  jwt.NewNumericDate(f.clock.Now()),
			},
		},
	})
	forged.Header["kid"] = f.activeKey.KID // claim the real kid

	raw, err := forged.SignedString(forgedPriv)
	if err != nil {
		t.Fatalf("sign forged: %v", err)
	}

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{f.issuer: resolverFromFixture(t, f)},
		"demo-api",
		f.clock,
	)
	_, err = v.Verify(ctx, raw)
	if !errors.Is(err, tokens.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

// Unknown kid: token header has a kid the resolver doesn't know. Surfaces
// as ErrUnknownKID so the demo-api middleware can distinguish "refetch
// JWKS" (unknown kid) from "reject outright" (invalid signature).
func TestVerify_UnknownKIDSurfacesAsSentinel(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	// Build a token with a kid the resolver hasn't seen. Easiest way:
	// sign with our real key, then stomp the kid header before sending.
	// But jwt-go doesn't let us easily mutate after signing, so we
	// directly construct an empty resolver.
	raw, err := f.signer.SignAccessToken(ctx, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "u", Audience: jwt.ClaimStrings{"demo-api"},
			},
		},
	}, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Resolver with no keys registered → every kid is unknown.
	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{
			f.issuer: &staticResolver{keys: map[string]ed25519.PublicKey{}},
		},
		"demo-api",
		f.clock,
	)
	_, err = v.Verify(ctx, raw)
	if !errors.Is(err, tokens.ErrUnknownKID) {
		t.Errorf("err = %v, want ErrUnknownKID", err)
	}
}

// A token with alg=none or alg=HS256 must be rejected even if everything
// else matches. Ed25519 is the only accepted alg.
func TestVerify_RejectsWrongAlg(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	// Sign with HS256 using a symmetric key — different alg family entirely.
	hmacSigned := jwt.NewWithClaims(jwt.SigningMethodHS256, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    f.issuer,
				Subject:   "u",
				Audience:  jwt.ClaimStrings{"demo-api"},
				ExpiresAt: jwt.NewNumericDate(f.clock.Now().Add(time.Minute)),
			},
		},
	})
	hmacSigned.Header["kid"] = f.activeKey.KID
	raw, err := hmacSigned.SignedString([]byte("some-symmetric-key"))
	if err != nil {
		t.Fatalf("sign hmac: %v", err)
	}

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{f.issuer: resolverFromFixture(t, f)},
		"demo-api",
		f.clock,
	)
	_, err = v.Verify(ctx, raw)
	if err == nil {
		t.Fatal("expected error for HS256 token")
	}
	// jwt-go's WithValidMethods error wraps; we surface under ErrInvalidToken.
	if !errors.Is(err, tokens.ErrInvalidToken) && !errors.Is(err, tokens.ErrUnexpectedAlg) {
		t.Errorf("err = %v, want ErrInvalidToken or ErrUnexpectedAlg", err)
	}
}

// Tampered token: flip a single character in the payload. Signature
// won't match → reject.
func TestVerify_RejectsTamperedPayload(t *testing.T) {
	f := newSignerFixture(t, "https://idp.test")
	ctx := context.Background()

	raw, err := f.signer.SignAccessToken(ctx, tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject: "u-legit", Audience: jwt.ClaimStrings{"demo-api"},
			},
		},
		Scope: "read:docs",
	}, time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Naive tamper: replace the first char of the payload (middle section).
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %q", raw)
	}
	// Change one char of the payload (index 10) — replaces base64url alphabet
	// with something else still in base64url to keep it decodable as a whole.
	b := []byte(parts[1])
	if b[10] == 'A' {
		b[10] = 'B'
	} else {
		b[10] = 'A'
	}
	tampered := parts[0] + "." + string(b) + "." + parts[2]

	v := tokens.NewVerifier(
		map[string]tokens.KeyResolver{f.issuer: resolverFromFixture(t, f)},
		"demo-api",
		f.clock,
	)
	_, err = v.Verify(ctx, tampered)
	if !errors.Is(err, tokens.ErrInvalidToken) {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}
