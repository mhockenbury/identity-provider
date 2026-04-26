// Public landing page. Shows a sign-in button if not authed,
// redirects to /docs if already authed.

import { useAuth } from "react-oidc-context";
import { Navigate } from "react-router-dom";

export function Landing() {
  const auth = useAuth();

  if (auth.isLoading) {
    return <FullScreenMessage>Loading…</FullScreenMessage>;
  }

  if (auth.isAuthenticated) {
    return <Navigate to="/docs" replace />;
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-gray-50">
      <div className="max-w-md rounded-lg border border-gray-200 bg-white p-8 text-center shadow-sm">
        <h1 className="text-2xl font-semibold text-gray-900">docs</h1>
        <p className="mt-2 text-sm text-gray-600">
          A small documents product built on top of identity-provider.
        </p>
        <button
          onClick={() => auth.signinRedirect()}
          className="mt-6 w-full rounded bg-blue-600 px-4 py-2 font-medium text-white hover:bg-blue-700"
        >
          Sign in
        </button>
        {auth.error && (
          <p className="mt-4 text-sm text-red-600">
            {auth.error.message}
          </p>
        )}
      </div>
    </div>
  );
}

function FullScreenMessage({ children }: Readonly<{children: React.ReactNode}>) {
  return (
    <div className="flex min-h-full items-center justify-center text-gray-600">
      {children}
    </div>
  );
}
