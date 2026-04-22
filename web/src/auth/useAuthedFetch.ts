// useAuthedFetch is the fetch wrapper every API call in the SPA uses.
// Reads the current access token from the AuthProvider, injects it as
// Bearer, and surfaces 401 responses as a specific error so callers
// can decide whether to re-auth.
//
// Returns a stable function suitable for use inside React Query's
// queryFn. The function closes over the current access token via
// useRef, so React Query doesn't have to re-subscribe every render.

import { useAuth } from "react-oidc-context";
import { useCallback } from "react";

export class AuthError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function useAuthedFetch() {
  const auth = useAuth();

  return useCallback(
    async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const token = auth.user?.access_token;
      if (!token) {
        throw new AuthError(0, "no access token available");
      }

      const headers = new Headers(init.headers);
      headers.set("Authorization", `Bearer ${token}`);
      if (init.body && !headers.has("content-type")) {
        headers.set("content-type", "application/json");
      }

      const resp = await fetch(input, { ...init, headers });

      if (resp.status === 401) {
        // Token might have just expired; let react-oidc-context try a
        // silent renewal next time. Surface the 401 so the caller can
        // decide whether to render a "session expired" UI.
        throw new AuthError(401, "unauthorized");
      }

      return resp;
    },
    [auth.user?.access_token],
  );
}
