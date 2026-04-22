package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/mhockenbury/identity-provider/internal/clients"
	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// TokenConfig wires the /token handler. Handlers depend on narrow
// interfaces so tests can bypass the DB.
type TokenConfig struct {
	Clients         TokenClientStore
	AuthCodes       AuthCodeStore
	RefreshTokens   tokens.RefreshTokenStore
	Signer          TokenSigner
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
	RefreshTokenTTL time.Duration
	Issuer          string
	UserInfo        UserInfoLookup
}

// TokenClientStore is the subset /token needs from the clients package.
// Authenticate handles both confidential (secret match) and public
// (no-secret PKCE-only) clients.
type TokenClientStore interface {
	Authenticate(ctx context.Context, clientID, presentedSecret string) (clients.Client, error)
}

// TokenSigner is the subset /token needs from tokens.Signer — sign an
// access token and an ID token.
type TokenSigner interface {
	SignAccessToken(ctx context.Context, c tokens.AccessClaims, ttl time.Duration) (string, error)
	SignIDToken(ctx context.Context, c tokens.IDClaims, ttl time.Duration) (string, error)
}

// UserInfoLookup returns identity claims for an ID token. Currently just
// email; extended with profile/etc. as more scopes are supported.
type UserInfoLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (UserInfo, error)
}

// UserInfo is the minimal user shape for building an ID token.
type UserInfo struct {
	ID    uuid.UUID
	Email string
}

// tokenResponse is the JSON shape /token returns on success per
// RFC 6749 §5.1 + OIDC Core §3.1.3.3. id_token is present when the
// openid scope was requested.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// oauthError is the JSON shape of an OAuth error response per RFC 6749 §5.2.
type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Token handles POST /token. The endpoint multiplexes on grant_type:
// "authorization_code" and "refresh_token". Other grants (password,
// client_credentials, token_exchange) are out of scope.
//
// Client authentication accepts both client_secret_basic (Authorization
// header) and client_secret_post (form field). Public clients send
// neither — PKCE provides proof of possession.
//
// Error responses follow RFC 6749 §5.2: JSON body with a standard
// "error" code + optional "error_description", status 400 or 401, no
// caching. We never redirect from /token; unlike /authorize this is a
// back-channel endpoint that never involves the user's browser.
func Token(cfg TokenConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Content-Type must be application/x-www-form-urlencoded per
		// RFC 6749 §3.2; ParseForm handles both form + query params but
		// for POST we only want the body.
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "could not parse form")
			return
		}

		// No caching. Token responses contain credentials.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")

		// --- Client authentication (RFC 6749 §2.3). ---
		// Try Authorization: Basic first; fall back to form fields.
		clientID, clientSecret, ok := parseBasicAuth(r)
		if !ok {
			clientID = r.PostFormValue("client_id")
			clientSecret = r.PostFormValue("client_secret")
		}
		if clientID == "" {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "missing client credentials")
			return
		}
		client, err := cfg.Clients.Authenticate(r.Context(), clientID, clientSecret)
		if err != nil {
			// Per spec, both "not found" and "wrong secret" map to invalid_client.
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}

		grantType := r.PostFormValue("grant_type")
		switch grantType {
		case "authorization_code":
			handleAuthCode(w, r, cfg, client)
		case "refresh_token":
			handleRefresh(w, r, cfg, client)
		case "":
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing grant_type")
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type="+grantType)
		}
	}
}

// handleAuthCode processes grant_type=authorization_code per RFC 6749 §4.1.3
// and PKCE verification per RFC 7636 §4.6.
func handleAuthCode(w http.ResponseWriter, r *http.Request, cfg TokenConfig, client clients.Client) {
	// Client must be allowed this grant type.
	if err := client.CheckGrant("authorization_code"); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", err.Error())
		return
	}

	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	codeVerifier := r.PostFormValue("code_verifier")
	if code == "" || redirectURI == "" || codeVerifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing code, redirect_uri, or code_verifier")
		return
	}

	// Consume the auth code (atomic single-use). This also verifies
	// client_id + redirect_uri match.
	row, err := cfg.AuthCodes.Consume(r.Context(), code, client.ID, redirectURI)
	if err != nil {
		switch {
		case errors.Is(err, ErrCodeNotFound), errors.Is(err, ErrCodeAlreadyUsed), errors.Is(err, ErrCodeExpired):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code invalid or already used")
		case errors.Is(err, ErrCodeClientMismatch):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code does not match this client/redirect_uri")
		default:
			slog.ErrorContext(r.Context(), "token: consume code", "err", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		}
		return
	}

	// PKCE: SHA-256(code_verifier) must equal the stored code_challenge.
	// Constant-time compare on the base64url strings.
	if !verifyPKCE(codeVerifier, row.CodeChallenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Issue tokens.
	scope := strings.Join(row.Scopes, " ")
	accessClaims := tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  row.UserID.String(),
				Audience: jwt.ClaimStrings{client.ID},
			},
		},
		Scope:    scope,
		ClientID: client.ID,
	}
	accessToken, err := cfg.Signer.SignAccessToken(r.Context(), accessClaims, cfg.AccessTokenTTL)
	if err != nil {
		slog.ErrorContext(r.Context(), "token: sign access", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	// Refresh token if client is allowed it.
	var refreshPlaintext string
	if slices.Contains(client.AllowedGrants, "refresh_token") {
		plaintext, _, err := cfg.RefreshTokens.Issue(r.Context(), row.UserID, client.ID, row.Scopes, cfg.RefreshTokenTTL)
		if err != nil {
			slog.ErrorContext(r.Context(), "token: issue refresh", "err", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		refreshPlaintext = plaintext
	}

	// ID token only when openid scope was requested (OIDC Core §3.1.3.3).
	var idToken string
	if slices.Contains(row.Scopes, "openid") {
		idClaims := tokens.IDClaims{
			BaseClaims: tokens.BaseClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:  row.UserID.String(),
					Audience: jwt.ClaimStrings{client.ID},
				},
			},
			Nonce:    row.Nonce,
			AuthTime: time.Now().Unix(),
		}
		// If scope includes "email", populate email claims.
		if slices.Contains(row.Scopes, "email") {
			u, err := cfg.UserInfo.GetByID(r.Context(), row.UserID)
			if err == nil {
				idClaims.Email = u.Email
				idClaims.EmailVerified = true
			}
		}
		tok, err := cfg.Signer.SignIDToken(r.Context(), idClaims, cfg.IDTokenTTL)
		if err != nil {
			slog.ErrorContext(r.Context(), "token: sign id", "err", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		idToken = tok
	}

	writeTokenResponse(w, tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(cfg.AccessTokenTTL.Seconds()),
		Scope:        scope,
		RefreshToken: refreshPlaintext,
		IDToken:      idToken,
	})
}

// handleRefresh processes grant_type=refresh_token per RFC 6749 §6.
// Rotates the refresh token and issues a fresh access+ID token.
func handleRefresh(w http.ResponseWriter, r *http.Request, cfg TokenConfig, client clients.Client) {
	if err := client.CheckGrant("refresh_token"); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", err.Error())
		return
	}

	refreshToken := r.PostFormValue("refresh_token")
	if refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}

	// Optional scope downgrade request.
	var requestedScopes []string
	if raw := r.PostFormValue("scope"); raw != "" {
		requestedScopes = strings.Fields(raw)
	}

	newPlaintext, row, err := cfg.RefreshTokens.Rotate(r.Context(), refreshToken, client.ID, requestedScopes, cfg.RefreshTokenTTL)
	if err != nil {
		switch {
		case errors.Is(err, tokens.ErrRefreshNotFound),
			errors.Is(err, tokens.ErrRefreshExpired),
			errors.Is(err, tokens.ErrRefreshRevoked):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token invalid")
		default:
			slog.ErrorContext(r.Context(), "token: rotate refresh", "err", err)
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token could not be rotated")
		}
		return
	}

	// Issue fresh access + ID tokens.
	scope := strings.Join(row.Scopes, " ")
	accessClaims := tokens.AccessClaims{
		BaseClaims: tokens.BaseClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:  row.UserID.String(),
				Audience: jwt.ClaimStrings{client.ID},
			},
		},
		Scope:    scope,
		ClientID: client.ID,
	}
	accessToken, err := cfg.Signer.SignAccessToken(r.Context(), accessClaims, cfg.AccessTokenTTL)
	if err != nil {
		slog.ErrorContext(r.Context(), "token: sign access (refresh)", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	var idToken string
	if slices.Contains(row.Scopes, "openid") {
		idClaims := tokens.IDClaims{
			BaseClaims: tokens.BaseClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:  row.UserID.String(),
					Audience: jwt.ClaimStrings{client.ID},
				},
			},
			AuthTime: time.Now().Unix(),
		}
		if slices.Contains(row.Scopes, "email") {
			u, err := cfg.UserInfo.GetByID(r.Context(), row.UserID)
			if err == nil {
				idClaims.Email = u.Email
				idClaims.EmailVerified = true
			}
		}
		tok, err := cfg.Signer.SignIDToken(r.Context(), idClaims, cfg.IDTokenTTL)
		if err != nil {
			slog.ErrorContext(r.Context(), "token: sign id (refresh)", "err", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "")
			return
		}
		idToken = tok
	}

	writeTokenResponse(w, tokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(cfg.AccessTokenTTL.Seconds()),
		Scope:        scope,
		RefreshToken: newPlaintext,
		IDToken:      idToken,
	})
}

// verifyPKCE: base64url(SHA-256(verifier)) == stored challenge.
// Constant-time compare the resulting strings.
func verifyPKCE(verifier, storedChallenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedChallenge)) == 1
}

// parseBasicAuth extracts client_id + client_secret from
// Authorization: Basic <base64(id:secret)>. Returns ok=false if absent
// or malformed; caller falls back to form fields.
func parseBasicAuth(r *http.Request) (id, secret string, ok bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", "", false
	}
	id, secret, ok = r.BasicAuth()
	return
}

func writeTokenResponse(w http.ResponseWriter, resp tokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oauthError{Error: code, ErrorDescription: desc})
}
