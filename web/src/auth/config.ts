// OIDC client configuration for the docs SPA.
//
// Two providers, one per route tree:
//   • docs tree  (/, /docs/*) → client_id=localdev-docs, resource=docs-api
//   • admin tree (/admin/*)   → client_id=localdev-admin, resource=idp-admin
//
// Why two providers? Tokens carry RFC 8707 audience semantics — a token
// minted for `aud=docs-api` cannot call /admin/api/*, and vice versa.
// Each provider asks the IdP for a token bound to its resource.
//
// Storage: sessionStorage with per-provider prefixes so PKCE verifier +
// nonce + state from one provider don't clobber the other during a
// concurrent login flow. Tokens themselves stay in-memory (no
// localStorage/sessionStorage for tokens; XSS exposure floor).
//
// Build-time env knobs (rare to override):
//   VITE_IDP_URL          default http://localhost:8080
//   VITE_DOCS_CLIENT_ID   default localdev-docs
//   VITE_ADMIN_CLIENT_ID  default localdev-admin

import type { UserManagerSettings } from "oidc-client-ts";
import { WebStorageStateStore } from "oidc-client-ts";

const IDP_URL = import.meta.env.VITE_IDP_URL ?? "http://localhost:8080";
const DOCS_CLIENT_ID = import.meta.env.VITE_DOCS_CLIENT_ID ?? "localdev-docs";
const ADMIN_CLIENT_ID = import.meta.env.VITE_ADMIN_CLIENT_ID ?? "localdev-admin";

const DOCS_RESOURCE = "docs-api";
const ADMIN_RESOURCE = "idp-admin";

const DOCS_SCOPES = "openid email read:docs write:docs";
const ADMIN_SCOPES = "openid email admin";

function makeConfig(opts: {
  clientId: string;
  scopes: string;
  resource: string;
  storageKey: string;
  callbackPath: string; // distinct per provider so /callback routes pick the right AuthProvider
  postLogoutPath: string;
}): UserManagerSettings {
  return {
    authority: IDP_URL,
    client_id: opts.clientId,
    redirect_uri: window.location.origin + opts.callbackPath,
    post_logout_redirect_uri: window.location.origin + opts.postLogoutPath,
    response_type: "code",
    scope: opts.scopes,
    // RFC 8707 — passed through as ?resource=... at /authorize and /token.
    // The IdP stamps this into the access token's `aud`.
    extraQueryParams: { resource: opts.resource },
    extraTokenParams: { resource: opts.resource },

    // Per-provider sessionStorage prefix prevents the two providers from
    // racing on PKCE verifier / state / nonce during interleaved login
    // flows. Tokens are still in-memory only.
    stateStore: new WebStorageStateStore({
      store: window.sessionStorage,
      prefix: opts.storageKey + ":",
    }),

    automaticSilentRenew: true,
    monitorSession: false,
    loadUserInfo: false,
  };
}

export const docsOidcConfig = makeConfig({
  clientId: DOCS_CLIENT_ID,
  scopes: DOCS_SCOPES,
  resource: DOCS_RESOURCE,
  storageKey: "oidc.docs",
  callbackPath: "/callback",
  postLogoutPath: "/",
});

export const adminOidcConfig = makeConfig({
  clientId: ADMIN_CLIENT_ID,
  scopes: ADMIN_SCOPES,
  resource: ADMIN_RESOURCE,
  storageKey: "oidc.admin",
  callbackPath: "/admin/callback",
  postLogoutPath: "/",
});
