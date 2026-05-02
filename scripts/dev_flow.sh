#!/usr/bin/env bash
# dev_flow.sh — drive the OAuth authorization-code + PKCE flow via curl.
#
# Requires: `idp serve` running on :8080, `make dev-all` having seeded
# the localdev client and smoke-alice user.
#
# Captures cookies in /tmp/idp-cookies.txt so session + CSRF persist
# across requests. Each step prints a short summary; the final result
# is the authorization code, which you can then exchange at /token
# (that step is commented out until the token endpoint is implemented).
#
# This script is meant for protocol regression testing; it's NOT a
# substitute for driving the flow through a real browser (for which
# `make oauth-url` gives you a pastable link).

set -euo pipefail

BASE_URL="http://localhost:8080"
CLIENT_ID="localdev"
REDIRECT_URI="http://localhost:5173/callback"
SCOPE="openid email read:docs"
RESOURCE="docs-api" # RFC 8707 — token's `aud`
STATE="$(head -c 12 /dev/urandom | xxd -p)"
NONCE="$(head -c 12 /dev/urandom | xxd -p)"
EMAIL="smoke-alice@example.com"
PASSWORD="correct-horse-battery-staple"

COOKIE_JAR="/tmp/idp-cookies.txt"
: > "$COOKIE_JAR"

# --- PKCE ---
VERIFIER="$(head -c 32 /dev/urandom | base64 | tr -d '=/+' | head -c 43)"
CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | base64 | tr -d '=' | tr '+/' '-_')"

AUTHZ_URL="${BASE_URL}/authorize?response_type=code&client_id=${CLIENT_ID}"
AUTHZ_URL+="&redirect_uri=$(printf '%s' "$REDIRECT_URI" | jq -sRr '@uri')"
AUTHZ_URL+="&scope=$(printf '%s' "$SCOPE" | jq -sRr '@uri')"
AUTHZ_URL+="&resource=$(printf '%s' "$RESOURCE" | jq -sRr '@uri')"
AUTHZ_URL+="&state=${STATE}"
AUTHZ_URL+="&code_challenge=${CHALLENGE}"
AUTHZ_URL+="&code_challenge_method=S256"
AUTHZ_URL+="&nonce=${NONCE}"

printf "\n[1/6] GET /authorize (anonymous → redirect to /login)\n"
login_url=$(curl -s -o /dev/null -w '%{redirect_url}' -c "$COOKIE_JAR" "$AUTHZ_URL")
printf '     %s\n' "$login_url"
case "$login_url" in
    *"/login?return_to="*) ;;
    *) echo "ERROR: expected redirect to /login, got: $login_url"; exit 1 ;;
esac

printf "\n[2/6] GET /login (fetch form + CSRF cookie/token)\n"
login_html=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$login_url")
# Extract hidden CSRF token field value (gorilla/csrf).
csrf_token=$(printf '%s' "$login_html" | grep -oP 'name="gorilla.csrf.Token" value="\K[^"]+' || true)
if [ -z "$csrf_token" ]; then
    echo "ERROR: could not extract CSRF token from /login response"
    echo "---BODY---"
    echo "$login_html" | head -40
    exit 1
fi
printf '     got csrf token: %s...\n' "${csrf_token:0:16}"

printf "\n[3/6] POST /login (authenticate)\n"
return_to=$(printf '%s' "$login_url" | sed -n 's|.*return_to=\([^&]*\).*|\1|p')
# urldecode — return_to comes URL-encoded inside the login URL.
return_to_decoded=$(printf '%s' "$return_to" | python3 -c 'import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))')

post_response_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -H "Referer: ${BASE_URL}/login" \
    -X POST "${BASE_URL}/login" \
    --data-urlencode "email=${EMAIL}" \
    --data-urlencode "password=${PASSWORD}" \
    --data-urlencode "return_to=${return_to_decoded}" \
    --data-urlencode "gorilla.csrf.Token=${csrf_token}")
case "$post_response_code" in
    302) printf '     login OK → 302\n' ;;
    *)   echo "ERROR: login POST returned $post_response_code (want 302)"; exit 1 ;;
esac

printf "\n[4/6] GET /authorize again (session now present → redirect to /consent)\n"
consent_url=$(curl -s -o /dev/null -w '%{redirect_url}' \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    "$AUTHZ_URL")
printf '     %s\n' "$consent_url"
case "$consent_url" in
    *"/consent?"*) ;;
    *) echo "ERROR: expected redirect to /consent, got: $consent_url"; exit 1 ;;
esac

printf "\n[5/6] GET + POST /consent (approve)\n"
consent_html=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$consent_url")
consent_csrf=$(printf '%s' "$consent_html" | grep -oP 'name="gorilla.csrf.Token" value="\K[^"]+' || true)
if [ -z "$consent_csrf" ]; then
    echo "ERROR: could not extract CSRF token from /consent response"
    exit 1
fi
# The consent page has all the state we need as hidden fields.
redirect_uri_hidden=$(printf '%s' "$consent_html" | grep -oP 'name="redirect_uri" value="\K[^"]+' | head -1)
state_hidden=$(printf '%s' "$consent_html" | grep -oP 'name="state" value="\K[^"]+' | head -1)
return_to_hidden=$(printf '%s' "$consent_html" | grep -oP 'name="return_to" value="\K[^"]+' | head -1)

# Extract scopes (there's one hidden input per scope).
scopes_list=$(printf '%s' "$consent_html" | grep -oP 'name="scope" value="\K[^"]+' || true)

# Decode HTML entities in the hidden field values (html/template escapes them).
decode_entities() {
    printf '%s' "$1" | sed -e 's/&amp;/\&/g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&quot;/"/g' -e 's/&#34;/"/g' -e 's/&#39;/'\''/g'
}
redirect_uri_hidden=$(decode_entities "$redirect_uri_hidden")
return_to_hidden=$(decode_entities "$return_to_hidden")

post_args=(
    --data-urlencode "decision=approve"
    --data-urlencode "client_id=${CLIENT_ID}"
    --data-urlencode "redirect_uri=${redirect_uri_hidden}"
    --data-urlencode "state=${state_hidden}"
    --data-urlencode "return_to=${return_to_hidden}"
    --data-urlencode "gorilla.csrf.Token=${consent_csrf}"
)
# One scope field per scope.
while IFS= read -r s; do
    [ -z "$s" ] && continue
    post_args+=(--data-urlencode "scope=${s}")
done <<< "$scopes_list"

consent_post_code=$(curl -s -o /dev/null -w '%{http_code}' \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    -H "Referer: ${BASE_URL}/consent" \
    -X POST "${BASE_URL}/consent" \
    "${post_args[@]}")
case "$consent_post_code" in
    302) printf '     consent approve OK → 302\n' ;;
    *)   echo "ERROR: consent POST returned $consent_post_code"; exit 1 ;;
esac

printf "\n[6/6] GET /authorize one more time (session + consent → redirect to client with code)\n"
final_url=$(curl -s -o /dev/null -w '%{redirect_url}' \
    -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
    "$AUTHZ_URL")
printf '     %s\n' "$final_url"

# Extract the code from the final redirect.
code=$(printf '%s' "$final_url" | grep -oP 'code=\K[^&]+' || true)
state_back=$(printf '%s' "$final_url" | grep -oP 'state=\K[^&]+' || true)

if [ -z "$code" ]; then
    echo "ERROR: no code in final redirect"
    exit 1
fi

printf "\n[7/7] POST /token (exchange code for tokens)\n"
token_response=$(curl -s -X POST "${BASE_URL}/token" \
    --data-urlencode "grant_type=authorization_code" \
    --data-urlencode "code=${code}" \
    --data-urlencode "redirect_uri=${REDIRECT_URI}" \
    --data-urlencode "client_id=${CLIENT_ID}" \
    --data-urlencode "code_verifier=${VERIFIER}")
# Pretty-print if jq is available.
if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$token_response" | jq '{
        token_type,
        expires_in,
        scope,
        access_token:  (if .access_token  then (.access_token  | .[0:32] + "...") else null end),
        id_token:      (if .id_token      then (.id_token      | .[0:32] + "...") else null end),
        refresh_token: (if .refresh_token then (.refresh_token | .[0:32] + "...") else null end)
    }'
else
    echo "$token_response"
fi

access_token=$(printf '%s' "$token_response" | grep -oP '"access_token":"\K[^"]+' || true)
refresh_token=$(printf '%s' "$token_response" | grep -oP '"refresh_token":"\K[^"]+' || true)
id_token=$(printf '%s' "$token_response" | grep -oP '"id_token":"\K[^"]+' || true)
if [ -z "$access_token" ]; then
    echo "ERROR: /token did not return access_token. Response:"
    printf '%s\n' "$token_response"
    exit 1
fi

# Decode the JWT payload (no verify) — useful "what's actually in there" check.
if command -v jq >/dev/null 2>&1; then
    printf '\nAccess token claims (decoded, NOT verified):\n'
    payload=$(printf '%s' "$access_token" | awk -F. '{print $2}')
    # base64url → base64 + padding.
    pad=$(( 4 - ${#payload} % 4 ))
    [ $pad -ne 4 ] && payload="${payload}$(printf '%0.s=' $(seq 1 $pad))"
    printf '%s' "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null | jq . || echo "(decode failed)"

    if [ -n "$id_token" ]; then
        printf '\nID token claims (decoded, NOT verified):\n'
        payload=$(printf '%s' "$id_token" | awk -F. '{print $2}')
        pad=$(( 4 - ${#payload} % 4 ))
        [ $pad -ne 4 ] && payload="${payload}$(printf '%0.s=' $(seq 1 $pad))"
        printf '%s' "$payload" | tr '_-' '/+' | base64 -d 2>/dev/null | jq . || echo "(decode failed)"
    fi
fi

printf "\n[8/8] GET /userinfo (with the access token)\n"
userinfo_response=$(curl -s -H "Authorization: Bearer ${access_token}" "${BASE_URL}/userinfo")
if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$userinfo_response" | jq .
else
    echo "$userinfo_response"
fi

if [ -n "$refresh_token" ]; then
    printf "\n=== bonus: refresh the token ===\n"
    refresh_response=$(curl -s -X POST "${BASE_URL}/token" \
        --data-urlencode "grant_type=refresh_token" \
        --data-urlencode "refresh_token=${refresh_token}" \
        --data-urlencode "client_id=${CLIENT_ID}")
    if command -v jq >/dev/null 2>&1; then
        printf '%s\n' "$refresh_response" | jq '{
            token_type, expires_in, scope,
            access_token:  (if .access_token  then (.access_token  | .[0:32] + "...") else null end),
            refresh_token_rotated: (if .refresh_token then true else false end)
        }'
    else
        echo "$refresh_response"
    fi
fi

cat <<EOF

=== flow complete ===
initial code:  $code
state match:   $([ "$state_back" = "$STATE" ] && echo 'yes' || echo "NO (got $state_back, want $STATE)")
access_token:  issued
id_token:      $([ -n "$id_token" ] && echo 'issued' || echo 'not issued')
refresh_token: $([ -n "$refresh_token" ] && echo 'issued + rotated' || echo 'not issued')
EOF
