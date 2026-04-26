// Callback page — the redirect_uri registered with the IdP.
// react-oidc-context's AuthProvider picks up ?code + &state from the
// URL automatically; all we do is render a placeholder and redirect
// once the library finishes the exchange.

import { useAuth } from "react-oidc-context";
import { Navigate } from "react-router-dom";

export function Callback() {
  const auth = useAuth();

  if (auth.activeNavigator === "signinSilent" || auth.isLoading) {
    return <Message>Completing sign-in…</Message>;
  }

  if (auth.error) {
    return (
      <Message>
        <p className="text-red-600">Sign-in failed: {auth.error.message}</p>
        <Navigate to="/" replace />
      </Message>
    );
  }

  if (auth.isAuthenticated) {
    return <Navigate to="/docs" replace />;
  }

  return <Message>Waiting for auth…</Message>;
}

function Message({ children }: Readonly<{children: React.ReactNode}>) {
  return (
    <div className="flex min-h-full items-center justify-center text-gray-600">
      <div className="text-center">{children}</div>
    </div>
  );
}
