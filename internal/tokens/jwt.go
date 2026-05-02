package tokens

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Sentinel errors surfaced to handlers.
var (
	ErrInvalidToken    = errors.New("invalid token")
	ErrUnknownKID      = errors.New("unknown signing key (kid)")
	ErrUnexpectedAlg   = errors.New("unexpected signing algorithm")
	ErrIssuerMismatch  = errors.New("issuer does not match expected")
	ErrAudienceMissing = errors.New("audience missing from claims")
)

// Clock is a tiny abstraction over time.Now so tests can assert expiry
// behavior without sleeping. DefaultClock is wall-clock.
type Clock interface {
	Now() time.Time
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

var DefaultClock Clock = wallClock{}

// Signer produces signed JWTs using the ACTIVE key from a KeyStore.
// One Signer wraps one KeyStore; the caller constructs it once at startup
// and reuses. Each Sign call picks up whatever key is currently active,
// so a rotation mid-flight just changes which key signs subsequent tokens.
type Signer struct {
	keys   *KeyStore
	kek    KEK
	issuer string
	clock  Clock
}

// NewSigner wraps a KeyStore. issuer is baked into every token as `iss`;
// it must match the value at /.well-known/openid-configuration or
// downstream services will reject tokens.
func NewSigner(keys *KeyStore, kek KEK, issuer string, clock Clock) *Signer {
	if clock == nil {
		clock = DefaultClock
	}
	return &Signer{keys: keys, kek: kek, issuer: issuer, clock: clock}
}

// SignAccessToken produces an access-token JWT. The caller supplies the
// claim values that vary per-request (sub, aud, scope, etc.); the signer
// fills in iss, iat, exp, jti from its config + clock.
//
// ttl is typically 15 minutes (matches README §6 decisions).
func (s *Signer) SignAccessToken(ctx context.Context, c AccessClaims, ttl time.Duration) (string, error) {
	s.fillRegistered(&c.BaseClaims, ttl)
	return s.sign(ctx, c)
}

// SignIDToken produces an ID token. Same contract as SignAccessToken, with
// a typically-shorter ttl (5 min per README §6). OIDC clients validate
// the nonce claim; callers should set it from the /authorize request.
func (s *Signer) SignIDToken(ctx context.Context, c IDClaims, ttl time.Duration) (string, error) {
	s.fillRegistered(&c.BaseClaims, ttl)
	return s.sign(ctx, c)
}

// fillRegistered populates the RFC 7519 fields the signer controls.
// Caller-controlled fields (sub, aud) are left alone.
func (s *Signer) fillRegistered(b *BaseClaims, ttl time.Duration) {
	now := s.clock.Now()
	b.Issuer = s.issuer
	b.IssuedAt = jwt.NewNumericDate(now)
	b.NotBefore = jwt.NewNumericDate(now)
	b.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))
	// jti is a unique per-token identifier. Useful for downstream de-dup
	// and for any future revocation list. UUID is fine.
	b.ID = uuid.NewString()
}

// sign fetches the current ACTIVE key, unwraps the private half, and
// emits a signed JWT. Caller should keep the string opaque and hand it
// to an HTTP response.
func (s *Signer) sign(ctx context.Context, claims jwt.Claims) (string, error) {
	key, err := s.keys.GetActive(ctx)
	if err != nil {
		return "", fmt.Errorf("get active signing key: %w", err)
	}
	if err := key.Unwrap(s.kek); err != nil {
		return "", fmt.Errorf("unwrap active key: %w", err)
	}

	// EdDSA signing for Ed25519. jwt-go v5 accepts the raw ed25519.PrivateKey.
	// The kid header is what downstream services look up to find the public
	// key in JWKS — it must match SigningKey.KID.
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = key.KID

	signed, err := token.SignedString(key.PrivateKey())
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// Verifier validates JWTs emitted by any configured issuer. Used by the
// docs-api for downstream verification — but exposed here in the tokens
// package so internal verification (e.g., ID tokens issued for internal
// clients) can use the same code path.
//
// Issuer → KeyResolver maps an iss value to a function that returns the
// public key for a given kid. Multiple issuers supported on purpose:
// that's the "multi-issuer verification" learning objective.
type Verifier struct {
	issuers   map[string]KeyResolver
	audiences []string // empty means audience check is skipped
	clock     Clock
}

// KeyResolver answers "what's the public key for this kid?" for a given
// issuer. Implementations are typically backed by a JWKS cache.
type KeyResolver interface {
	Resolve(ctx context.Context, kid string) (ed25519.PublicKey, error)
}

// NewVerifier constructs a verifier. issuers is the allowlist — tokens
// with an `iss` not in this map are rejected. audience, if non-empty,
// must match the token's `aud` claim. For multi-audience verification
// (e.g. one resource server accepting tokens issued for several
// clients), use NewVerifierMultiAud instead.
func NewVerifier(issuers map[string]KeyResolver, audience string, clock Clock) *Verifier {
	var auds []string
	if audience != "" {
		auds = []string{audience}
	}
	return NewVerifierMultiAud(issuers, auds, clock)
}

// NewVerifierMultiAud is the multi-audience form. The token must have
// at least one `aud` value present in `audiences`; an empty audiences
// slice skips the check entirely (don't ship that in production).
func NewVerifierMultiAud(issuers map[string]KeyResolver, audiences []string, clock Clock) *Verifier {
	if clock == nil {
		clock = DefaultClock
	}
	// Defensive copy: callers shouldn't mutate our maps/slices after the fact.
	cp := make(map[string]KeyResolver, len(issuers))
	for k, v := range issuers {
		cp[k] = v
	}
	auds := make([]string, len(audiences))
	copy(auds, audiences)
	return &Verifier{issuers: cp, audiences: auds, clock: clock}
}

// Verify parses, verifies signature, and validates exp/nbf/iss/aud on a
// JWT string. On success returns the verified claims as a pointer so
// callers can read fields without another parse pass.
//
// Does NOT validate scope or any client-specific field — that's the
// handler's job. The verifier answers "is this token legitimate and
// current"; the handler answers "does this token authorize this request."
func (v *Verifier) Verify(ctx context.Context, raw string) (*AccessClaims, error) {
	// Custom keyfunc: peek at the header to find (iss, kid), resolve the
	// public key via the per-issuer KeyResolver. Two-phase: first parse
	// the unverified token to read iss; then resolve; then jwt-go
	// re-verifies with the resolved key.
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		// We supply our own clock via options so tests are deterministic.
		jwt.WithTimeFunc(v.clock.Now),
	)

	claims := &AccessClaims{}
	_, err := parser.ParseWithClaims(raw, claims, func(tok *jwt.Token) (any, error) {
		return v.resolveKey(ctx, tok, claims)
	})
	if err != nil {
		// jwt-go wraps many validation failures (exp/nbf/iat/signature).
		// We map our own sentinels for the ones we raise in resolveKey;
		// everything else surfaces under ErrInvalidToken.
		if errors.Is(err, ErrUnknownKID) || errors.Is(err, ErrUnexpectedAlg) ||
			errors.Is(err, ErrIssuerMismatch) || errors.Is(err, ErrAudienceMissing) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	return claims, nil
}

// resolveKey is the keyfunc passed to jwt-go's parser. It runs after the
// unsigned parse, so `claims.Issuer` is already populated. Returns the
// public key that should have signed the token; jwt-go then verifies.
func (v *Verifier) resolveKey(ctx context.Context, tok *jwt.Token, claims *AccessClaims) (any, error) {
	// Alg check. jwt.WithValidMethods also enforces this but adding an
	// explicit sentinel makes the error path testable from callers.
	if tok.Method.Alg() != "EdDSA" {
		return nil, fmt.Errorf("%w: got %q", ErrUnexpectedAlg, tok.Method.Alg())
	}

	// Issuer must be on our allowlist. This is the multi-issuer gate —
	// a token signed by a legitimate-but-untrusted IdP is rejected here,
	// before we even look up its public key.
	iss := claims.Issuer
	resolver, ok := v.issuers[iss]
	if !ok {
		return nil, fmt.Errorf("%w: iss=%q", ErrIssuerMismatch, iss)
	}

	// Audience enforcement. RFC 7519 §4.1.3: if aud is present, it MUST
	// be validated. We require a match if the verifier is configured
	// with one or more acceptable audiences. NewVerifier wraps the
	// single-aud case (the common one); NewVerifierMultiAud is reserved
	// for resource servers that legitimately host multiple logical
	// audiences (rare).
	if len(v.audiences) > 0 {
		matched := false
		for _, want := range v.audiences {
			ok, err := claims.HasAudience(want)
			if err != nil {
				return nil, fmt.Errorf("%w: aud check: %v", ErrInvalidToken, err)
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("%w: expected one of %v, got %v", ErrAudienceMissing, v.audiences, claims.Audience)
		}
	}

	// Resolve the kid to a public key via the per-issuer resolver.
	kid, _ := tok.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("%w: no kid in header", ErrInvalidToken)
	}
	pub, err := resolver.Resolve(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: kid=%q: %v", ErrUnknownKID, kid, err)
	}
	return pub, nil
}

// HasAudience matches the audience string against claims.Audience. Must
// return (found, error); jwt-go's jwt.ClaimStrings type makes this
// awkward to do inline, so we wrap it here.
func (c *AccessClaims) HasAudience(want string) (bool, error) {
	if len(c.Audience) == 0 {
		return false, nil
	}
	for _, aud := range c.Audience {
		if aud == want {
			return true, nil
		}
	}
	return false, nil
}
