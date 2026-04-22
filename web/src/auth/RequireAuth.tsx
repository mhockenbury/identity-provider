// RequireAuth is a route guard. If the user isn't authenticated yet,
// it triggers a redirect to the IdP and renders a placeholder. Once
// authenticated, it renders its children.
//
// Kept dumb on purpose — all the state lives inside react-oidc-context's
// AuthProvider. This is just a ~15-line UX wrapper.

import { useAuth } from "react-oidc-context";
import type { ReactNode } from "react";

export function RequireAuth({ children }: { children: ReactNode }) {
  const auth = useAuth();

  if (auth.activeNavigator === "signinSilent" || auth.isLoading) {
    return <CenteredMessage>Loading…</CenteredMessage>;
  }

  if (auth.error) {
    return (
      <CenteredMessage>
        <p className="text-red-600">Auth error: {auth.error.message}</p>
        <button
          onClick={() => auth.signinRedirect()}
          className="mt-4 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
        >
          Try again
        </button>
      </CenteredMessage>
    );
  }

  if (!auth.isAuthenticated) {
    // Kick off the auth-code+PKCE flow. The library handles the
    // verifier/challenge generation + /authorize redirect.
    auth.signinRedirect();
    return <CenteredMessage>Redirecting to sign in…</CenteredMessage>;
  }

  return <>{children}</>;
}

function CenteredMessage({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="text-center text-gray-600">{children}</div>
    </div>
  );
}
