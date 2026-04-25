// useHasScope inspects the current access token's `scope` claim and
// reports whether a given scope is present. Tokens are JWTs whose
// payload (middle base64url segment) carries `scope` as a
// space-separated string per RFC 6749 §3.3.

import { useMemo } from "react";
import { useAuth } from "react-oidc-context";

export function useHasScope(want: string): boolean {
  const auth = useAuth();
  const token = auth.user?.access_token;

  return useMemo(() => {
    if (!token) return false;
    const scope = decodeScope(token);
    if (!scope) return false;
    return scope.split(/\s+/).includes(want);
  }, [token, want]);
}

function decodeScope(token: string): string | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(b64urlToB64(parts[1])));
    return typeof payload.scope === "string" ? payload.scope : null;
  } catch {
    return null;
  }
}

// atob expects standard base64; JWTs use base64url. Pad as needed.
function b64urlToB64(s: string): string {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  return pad ? s + "=".repeat(4 - pad) : s;
}
