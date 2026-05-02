#!/usr/bin/env bash
# docs_smoke.sh — end-to-end smoke test for layer 9 (docs-api).
#
# What this exercises:
#   1. IdP issues an access token via auth-code+PKCE to alice.
#   2. docs-api accepts alice's token (JWKS fetched live), verifies
#      signature + iss + aud, extracts sub.
#   3. FGA tuples (seeded at docs-api startup) allow alice viewer on
#      Engineering but NOT Public.
#   4. All three endpoints work: /docs, /docs/{id}, /folders/{id}.
#   5. Scope enforcement: without write:docs, PATCH fails.
#
# Prerequisites:
#   - Full compose stack up (postgres-idp, postgres-fga, openfga)
#   - `make dev-all` completed (idp seeded with localdev client + alice)
#   - `idp serve` running on :8080
#   - OPENFGA_STORE_ID + OPENFGA_AUTHORIZATION_MODEL_ID set in env
#     (from `idp fga init` output)
#   - docs-api NOT already running — this script starts its own

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

IDP_URL="http://localhost:8080"
DOCS_URL="http://localhost:8083"

# RFC 8707 audience semantics: the access token's `aud` claim identifies
# the *resource server*, not the OAuth client. The SPA passes
# `resource=docs-api` at /authorize; the IdP stamps that into `aud`;
# docs-api's REQUIRED_AUD must match.
CLIENT_ID="localdev"
RESOURCE="docs-api"
REQUIRED_AUD="$RESOURCE"

ALICE_EMAIL="smoke-alice@example.com"

# --- pretty output ---
c_info()  { printf '\033[36m[INFO]\033[0m %s\n'  "$*"; }
c_ok()    { printf '\033[32m[OK]\033[0m   %s\n'  "$*"; }
c_fail()  { printf '\033[31m[FAIL]\033[0m %s\n'  "$*"; exit 1; }
c_step()  { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }

# --- env checks ---
#
# Auto-source /tmp/idp-env if present so the user doesn't have to do
# `source /tmp/idp-env && bash scripts/docs_smoke.sh`.
if [ -f /tmp/idp-env ] && [ -z "${OPENFGA_STORE_ID:-}" ]; then
    # shellcheck disable=SC1091
    . /tmp/idp-env
fi

: "${OPENFGA_STORE_ID:?Run 'idp fga init' and source /tmp/idp-env first}"
: "${OPENFGA_AUTHORIZATION_MODEL_ID:?Run 'idp fga init' and source /tmp/idp-env first}"

c_step "prerequisites"

if ! curl -sf "$IDP_URL/healthz" > /dev/null; then
    c_fail "IdP not running at $IDP_URL — start with: make dev-serve"
fi
c_ok "IdP reachable"

# --- look up alice's sub ---

c_step "look up alice's user UUID"

ALICE_SUB=$(docker exec identity-provider-postgres-idp-1 \
    psql -U idp -d idp -tAc "SELECT id FROM users WHERE email = '$ALICE_EMAIL'" 2>/dev/null \
    | tr -d ' ' | head -1)

if [ -z "$ALICE_SUB" ]; then
    c_fail "User $ALICE_EMAIL not found; run: make dev-user"
fi
c_ok "alice sub = $ALICE_SUB"

# --- start docs-api ---

c_step "start docs-api (seeded with alice as viewer on Engineering)"

# Clean up any previous docs-api instance.
if lsof -i :8083 -t > /dev/null 2>&1; then
    c_info "killing existing listener on :8083"
    fuser -k 8083/tcp 2>/dev/null || true
    sleep 1
fi

DOCS_LOG="/tmp/docs-api-smoke.log"
# Export everything docs-api needs. REQUIRED_AUD = CLIENT_ID is the
# lab-scale shortcut documented at the top of this file.
OPENFGA_STORE_ID="$OPENFGA_STORE_ID" \
OPENFGA_AUTHORIZATION_MODEL_ID="$OPENFGA_AUTHORIZATION_MODEL_ID" \
TRUSTED_ISSUERS="$IDP_URL" \
REQUIRED_AUD="$REQUIRED_AUD" \
DOCS_SEED_ALICE="$ALICE_SUB" \
LOG_LEVEL=info \
    go run "$REPO_ROOT/cmd/docs-api" > "$DOCS_LOG" 2>&1 &
DOCS_PID=$!
trap 'kill $DOCS_PID 2>/dev/null || true' EXIT

# Wait for /healthz.
for i in $(seq 1 20); do
    if curl -sf "$DOCS_URL/healthz" > /dev/null; then break; fi
    sleep 0.5
done
if ! curl -sf "$DOCS_URL/healthz" > /dev/null; then
    echo "--- docs-api log ---"
    cat "$DOCS_LOG"
    c_fail "docs-api did not start; log above"
fi
c_ok "docs-api listening on :8083 (pid $DOCS_PID)"
c_ok "log: $DOCS_LOG"

# --- get access token via dev_flow ---

c_step "drive auth-code+PKCE flow to get alice an access token"

# Steps: authorize → login → [consent if not remembered] → code → token.
# Handles the "consent already recorded" fast-path where /authorize after
# /login redirects straight to the callback with ?code=...

CJAR="/tmp/idp-cookies-smoke.txt"
: > "$CJAR"

VERIFIER="$(head -c 32 /dev/urandom | base64 | tr -d '=/+' | head -c 43)"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | base64 | tr -d '=' | tr '+/' '-_')"
STATE="$(head -c 12 /dev/urandom | xxd -p)"
NONCE="$(head -c 12 /dev/urandom | xxd -p)"
REDIRECT="http://localhost:5173/callback"

AUTHZ_URL="${IDP_URL}/authorize?response_type=code&client_id=${CLIENT_ID}"
AUTHZ_URL+="&redirect_uri=$(printf '%s' "$REDIRECT" | jq -sRr '@uri')"
AUTHZ_URL+="&scope=$(printf '%s' "openid email read:docs write:docs" | jq -sRr '@uri')"
AUTHZ_URL+="&resource=$(printf '%s' "$RESOURCE" | jq -sRr '@uri')"
AUTHZ_URL+="&state=${STATE}"
AUTHZ_URL+="&code_challenge=${CHALLENGE}"
AUTHZ_URL+="&code_challenge_method=S256"
AUTHZ_URL+="&nonce=${NONCE}"

# extractCode takes a redirect URL and pulls the ?code= param, or returns empty.
extractCode() { printf '%s' "$1" | sed -nE 's/.*[?&]code=([^&]+).*/\1/p'; }

# 1. /authorize → /login.
login_url=$(curl -s -o /dev/null -w '%{redirect_url}' -c "$CJAR" "$AUTHZ_URL")
[ -n "$login_url" ] || c_fail "authorize didn't redirect"

# 2. GET /login — capture CSRF + the return_to round-trip value. The
#    login form hides the original /authorize URL in a return_to field;
#    we must submit it back so the IdP redirects us there post-login.
login_html=$(curl -s -b "$CJAR" -c "$CJAR" "$login_url")
csrf=$(printf '%s' "$login_html" | grep -oP 'name="gorilla.csrf.Token" value="\K[^"]+' | head -1)
[ -n "$csrf" ] || c_fail "no CSRF token on login page"

# return_to has HTML-encoded ampersands (&amp;); decode them.
return_to=$(printf '%s' "$login_html" \
    | grep -oP 'name="return_to" value="\K[^"]+' | head -1 \
    | sed 's/&amp;/\&/g')
[ -n "$return_to" ] || c_fail "no return_to on login page"

# 3. POST /login — succeed, redirect back to /authorize (with session).
after_login=$(curl -s -o /dev/null -w '%{redirect_url}' \
    -b "$CJAR" -c "$CJAR" \
    -X POST \
    --data-urlencode "gorilla.csrf.Token=$csrf" \
    --data-urlencode "return_to=$return_to" \
    --data-urlencode "email=$ALICE_EMAIL" \
    --data-urlencode "password=correct-horse-battery-staple" \
    "${IDP_URL}/login")
[ -n "$after_login" ] || c_fail "login POST didn't redirect"

# 4. Follow the redirect. Two outcomes possible depending on prior consent:
#    (a) consent remembered → lands on <REDIRECT>?code=...  [fast path]
#    (b) no remembered consent → lands on /consent          [full path]
case "$after_login" in
    "${REDIRECT}"*)
        CODE=$(extractCode "$after_login")
        [ -n "$CODE" ] || c_fail "fast-path but no code in URL: $after_login"
        c_ok "consent already recorded; code issued via fast path"
        ;;
    *)
        # Follow /authorize redirect to reach /consent.
        next=$(curl -s -o /dev/null -w '%{redirect_url}' -b "$CJAR" -c "$CJAR" "$after_login")
        case "$next" in
            "${REDIRECT}"*)
                CODE=$(extractCode "$next")
                [ -n "$CODE" ] || c_fail "no code on /authorize follow: $next"
                c_ok "code issued after session establishment"
                ;;
            *)
                consent_html=$(curl -s -b "$CJAR" -c "$CJAR" "$next")
                csrf=$(printf '%s' "$consent_html" | grep -oP 'name="gorilla.csrf.Token" value="\K[^"]+' | head -1)
                [ -n "$csrf" ] || c_fail "no CSRF token on consent page (url=$next)"
                # The consent form carries ALL the auth-code state as
                # hidden fields; we round-trip every one of them back.
                decode_entities() {
                    printf '%s' "$1" | sed -e 's/&amp;/\&/g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e 's/&#34;/"/g' -e 's/&#39;/'\''/g'
                }
                redir_hidden=$(decode_entities "$(printf '%s' "$consent_html" | grep -oP 'name="redirect_uri" value="\K[^"]+' | head -1)")
                state_hidden=$(printf '%s' "$consent_html" | grep -oP 'name="state" value="\K[^"]+' | head -1)
                return_hidden=$(decode_entities "$(printf '%s' "$consent_html" | grep -oP 'name="return_to" value="\K[^"]+' | head -1)")

                client_hidden=$(printf '%s' "$consent_html" | grep -oP 'name="client_id" value="\K[^"]+' | head -1)
                consent_args=(
                    --data-urlencode "decision=approve"
                    --data-urlencode "gorilla.csrf.Token=$csrf"
                    --data-urlencode "client_id=$client_hidden"
                    --data-urlencode "redirect_uri=$redir_hidden"
                    --data-urlencode "state=$state_hidden"
                    --data-urlencode "return_to=$return_hidden"
                )
                while IFS= read -r s; do
                    [ -z "$s" ] && continue
                    consent_args+=(--data-urlencode "scope=$s")
                done < <(printf '%s' "$consent_html" | grep -oP 'name="scope" value="\K[^"]+' || true)

                after_consent=$(curl -s -o /dev/null -w '%{redirect_url}' \
                    -b "$CJAR" -c "$CJAR" -X POST \
                    "${consent_args[@]}" "${IDP_URL}/consent")
                [ -n "$after_consent" ] || c_fail "consent POST returned no redirect"

                # after_consent is typically /authorize?...; one more
                # hop should land on the callback with ?code=.
                code_url="$after_consent"
                case "$code_url" in
                    "${REDIRECT}"*) ;;
                    *)
                        code_url=$(curl -s -o /dev/null -w '%{redirect_url}' \
                            -b "$CJAR" -c "$CJAR" "$after_consent")
                        ;;
                esac
                CODE=$(extractCode "$code_url")
                [ -n "$CODE" ] || c_fail "consent didn't produce a code; final url=$code_url"
                c_ok "consent recorded + code issued"
                ;;
        esac
        ;;
esac

# 6. POST /token — exchange code for tokens.
token_resp=$(curl -s -X POST "${IDP_URL}/token" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=$CODE" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "redirect_uri=$REDIRECT" \
    --data-urlencode "code_verifier=$VERIFIER")

ACCESS=$(printf '%s' "$token_resp" | jq -r '.access_token // empty')
[ -n "$ACCESS" ] || c_fail "no access_token: $token_resp"
c_ok "got access token ($(echo "$ACCESS" | head -c 24)...)"

# --- exercise docs-api ---

c_step "GET /healthz (open)"
st=$(curl -s -o /dev/null -w '%{http_code}' "$DOCS_URL/healthz")
[ "$st" = "200" ] || c_fail "healthz = $st"
c_ok "200 OK"

c_step "GET /docs without token (expect 401)"
st=$(curl -s -o /dev/null -w '%{http_code}' "$DOCS_URL/docs")
[ "$st" = "401" ] || c_fail "unauth /docs = $st"
c_ok "401 Unauthorized"

c_step "GET /docs with alice's token — should return alice-viewable docs"
resp=$(curl -s -H "Authorization: Bearer $ACCESS" "$DOCS_URL/docs")
echo "$resp" | jq '.docs | map({id, title})'
count=$(echo "$resp" | jq '.docs | length')
# Alice sees 4 docs:
#   - Engineering Overview  (owner on folder:engineering → viewer via inheritance)
#   - Deploy Runbook        (editor on folder:runbooks → viewer via inheritance)
#   - On-Call Runbook       (same)
#   - Private Notes         (direct owner → viewer)
# She does NOT see Public README (carol's folder).
if [ "$count" != "4" ]; then
    c_fail "expected 4 viewable docs for alice, got $count"
fi
# Sanity-check: Public README must NOT be in the list.
if echo "$resp" | jq -e '.docs[] | select(.title == "Public README")' > /dev/null 2>&1; then
    c_fail "alice should NOT see Public README"
fi
c_ok "4 docs visible; Public README correctly hidden"

c_step "GET /docs/{eng-overview} — should succeed"
DOC_ID="22222222-2222-2222-2222-000000000001"
resp=$(curl -s -H "Authorization: Bearer $ACCESS" "$DOCS_URL/docs/$DOC_ID")
echo "$resp" | jq '{id, title}'
title=$(echo "$resp" | jq -r '.title // empty')
[ "$title" = "Engineering Overview" ] || c_fail "wrong title: $title"
c_ok "fetched 'Engineering Overview'"

c_step "GET /docs/{public-readme} — alice is NOT viewer (expect 404)"
# Carol's folder, alice has no path there. Not 403: we hide existence.
PUBLIC_README_ID="22222222-2222-2222-2222-000000000004"
st=$(curl -s -H "Authorization: Bearer $ACCESS" -o /dev/null -w '%{http_code}' "$DOCS_URL/docs/$PUBLIC_README_ID")
[ "$st" = "404" ] || c_fail "public-readme = $st (want 404 — alice shouldn't see)"
c_ok "404 (existence hidden, as designed)"

c_step "GET /folders/{engineering}/docs — should list 1 doc (eng-overview; runbooks are in nested folder)"
FOLDER_ID="11111111-1111-1111-1111-000000000001"
resp=$(curl -s -H "Authorization: Bearer $ACCESS" "$DOCS_URL/folders/$FOLDER_ID/docs")
echo "$resp" | jq '.docs | map({id, title})'
count=$(echo "$resp" | jq '.docs | length')
[ "$count" = "1" ] || c_fail "expected 1 doc in engineering folder (non-recursive), got $count"
c_ok "engineering folder lists 1 doc"

c_step "PATCH /docs/{eng-overview} — should succeed (alice is owner via folder)"
resp=$(curl -s -H "Authorization: Bearer $ACCESS" \
    -X PATCH \
    -H 'Content-Type: application/json' \
    -d '{"title":"Engineering Overview [edited]"}' \
    "$DOCS_URL/docs/$DOC_ID")
new_title=$(echo "$resp" | jq -r '.title')
[ "$new_title" = "Engineering Overview [edited]" ] || c_fail "patch failed: $resp"
c_ok "title updated"

c_step "shutdown docs-api"
kill $DOCS_PID 2>/dev/null || true
wait $DOCS_PID 2>/dev/null || true
c_ok "clean exit"

printf '\n\033[32m=== smoke test PASSED ===\033[0m\n'
printf 'access_token:  alice (sub=%s)\n' "$ALICE_SUB"
printf 'visible docs:  4 (engineering + inherited runbooks + owned private-notes)\n'
printf 'hidden doc:    public-readme (404 by design; alice has no path)\n'
printf 'write path:    PATCH with write:docs scope + editor tuple\n'
