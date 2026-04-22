// OIDC client configuration for the docs SPA.
//
// Pulled from env at build time:
//   VITE_IDP_URL      e.g. http://localhost:8080
//   VITE_CLIENT_ID    e.g. localdev
//
// A single config serves both the docs and admin route trees; scopes
// requested by each tree differ, handled by the AuthProvider prop.

import type { UserManagerSettings } from "oidc-client-ts";

const IDP_URL = import.meta.env.VITE_IDP_URL ?? "http://localhost:8080";
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID ?? "localdev";

// Base scopes for the docs SPA. The admin UI requests `admin` in
// addition — done when the admin route tree mounts (see App.tsx).
export const DOCS_SCOPES = "openid email read:docs write:docs";
export const ADMIN_SCOPES = DOCS_SCOPES + " admin";

export const oidcConfig: UserManagerSettings = {
  authority: IDP_URL,
  client_id: CLIENT_ID,
  redirect_uri: window.location.origin + "/callback",
  post_logout_redirect_uri: window.location.origin + "/",
  response_type: "code",
  scope: DOCS_SCOPES,

  // Token storage: in-memory only. `userStore` stays null so
  // oidc-client-ts never touches localStorage/sessionStorage for the
  // tokens themselves. The library still uses sessionStorage for
  // transient state during the /authorize → /callback round-trip
  // (PKCE verifier, nonce, state); that's brief and unavoidable.
  userStore: undefined,

  // Automatic silent renewal via the refresh_token grant. The IdP
  // issues refresh tokens with rotation already wired up (layer 6).
  automaticSilentRenew: true,

  // Don't monitor the session via iframe polling — our IdP doesn't
  // implement the session-management spec. Relying on access token
  // lifetime is fine for a lab.
  monitorSession: false,

  // Trim logs; verbose only while debugging.
  loadUserInfo: false,
};
